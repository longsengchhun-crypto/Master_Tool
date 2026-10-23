//! The relay: how the SENTRIX app on a person's computer reports through the shared bot without ever holding its token.
//!
//! Server side (runs next to the bot):
//!   POST   /v1/link    {code, name}  -> {token, userName}   exchanges the one-time code from the bot for a device token
//!   POST   /v1/report  {text}        -> 202                 queues a report to the linked person's private chat
//!   GET    /v1/status                -> {linked, reachable}
//!   DELETE /v1/link                  -> 204                 unlinks this computer
//!   GET    /v1/jobs                  -> {jobs:[...]}        files posted in the owner's protected groups, to be checked HERE
//!   GET    /v1/jobs/<id>/file        -> the file's bytes    passed through memory from Telegram, never stored on the server
//!   POST   /v1/jobs/<id>/result      {ok, result|error}     the verdict the computer reached (see edge.rs)
//! The device token is a random 256-bit secret shown once; only its hash is stored. A token only ever reaches the person
//! it was issued for: there is no way to name another chat. Report text is reduced to a few safe formatting tags.
//!
//! Client side: `RelayClient` (a `Courier`) so the app's existing report queue, retry and de-duplication work unchanged.
//! Run it behind HTTPS: the client refuses plain http except to the local machine.

use crate::hosted::normalize_device_code;
use crate::edge::{EdgeJobInfo, EdgeSubmit, FileSource, EDGE_BATCH};
use crate::hosted_store::{token_hash, CodeKind};
use crate::queue::{now_ms, JobStore};
use crate::telegram::{Courier, TgError, MAX_BOT_DOWNLOAD};
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_BODY: u64 = 16 * 1024;
pub const MAX_TEXT: usize = 3500;
pub const REPORTS_PER_MIN: usize = 6;
pub const REPORTS_PER_HOUR: usize = 60;
pub const LINK_TRIES_PER_10_MIN_PER_IP: usize = 10;
pub const LINK_TRIES_PER_10_MIN_ALL: usize = 100;
/// An app asks for work every few seconds while it runs.
pub const JOB_POLLS_PER_MIN: usize = 120;
pub const FILE_FETCHES_PER_MIN: usize = 60;

// ---- text safety -------------------------------------------------------------------------------------------------

/// Reduce text from a device to what Telegram's HTML mode may safely show: `<b> <i> <code>` pairs and the four basic
/// entities. Anything else is shown as plain characters. If the tags are not balanced, no tag is kept at all.
pub fn sanitize_html(text: &str) -> String {
    let text: String = text.chars().filter(|c| !c.is_control() || *c == '\n').take(MAX_TEXT).collect();
    let mut out = String::new();
    let mut stack: Vec<&str> = vec![];
    let mut balanced = true;
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let rest = &text[i..];
        let mut handled = false;
        for tag in ["b", "i", "code"] {
            let open = format!("<{tag}>");
            let close = format!("</{tag}>");
            if rest.starts_with(&open) {
                stack.push(if tag == "b" { "b" } else if tag == "i" { "i" } else { "code" });
                out.push_str(&open);
                i += open.len();
                handled = true;
                break;
            }
            if rest.starts_with(&close) {
                if stack.pop() != Some(tag) {
                    balanced = false;
                }
                out.push_str(&close);
                i += close.len();
                handled = true;
                break;
            }
        }
        if handled {
            continue;
        }
        let ch = rest.chars().next().unwrap();
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => {
                let ent = ["&amp;", "&lt;", "&gt;", "&quot;"].iter().find(|e| rest.starts_with(**e));
                match ent {
                    Some(e) => {
                        out.push_str(e);
                        i += e.len();
                        continue;
                    }
                    None => out.push_str("&amp;"),
                }
            }
            c => out.push(c),
        }
        i += ch.len_utf8();
    }
    if !balanced || !stack.is_empty() {
        // Strip every tag we let through and show the text plainly.
        for t in ["<b>", "</b>", "<i>", "</i>", "<code>", "</code>"] {
            out = out.replace(t, "");
        }
    }
    out
}

// ---- rate limits -------------------------------------------------------------------------------------------------

#[derive(Default)]
struct Limits {
    per_device: Mutex<HashMap<String, VecDeque<Instant>>>,
    link_ip: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
    link_all: Mutex<VecDeque<Instant>>,
}

fn hit<K: std::hash::Hash + Eq + Clone>(m: &Mutex<HashMap<K, VecDeque<Instant>>>, k: &K, limit: usize, window: Duration) -> bool {
    let mut g = m.lock().unwrap();
    let q = g.entry(k.clone()).or_default();
    let now = Instant::now();
    while q.front().is_some_and(|t| now.duration_since(*t) > window) {
        q.pop_front();
    }
    if q.len() >= limit {
        return false;
    }
    q.push_back(now);
    if g.len() > 5000 {
        g.retain(|_, v| v.back().is_some_and(|t| now.duration_since(*t) <= window));
    }
    true
}

// ---- server ------------------------------------------------------------------------------------------------------

pub struct RelayServer {
    stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
    pub addr: String,
}

impl RelayServer {
    /// Listen on `addr` (for example `127.0.0.1:8787`). `trust_proxy`: take the client address from `X-Forwarded-For`
    /// (only when a reverse proxy you control sits in front, otherwise anyone could spoof it).
    pub fn start(addr: &str, store: Arc<JobStore>, trust_proxy: bool) -> Result<RelayServer, String> {
        Self::start_with_files(addr, store, trust_proxy, None)
    }

    /// Like `start`, and also able to hand an app the bytes of the files it was asked to check (needs the bot's access to Telegram).
    pub fn start_with_files(addr: &str, store: Arc<JobStore>, trust_proxy: bool, files: Option<Arc<dyn FileSource>>) -> Result<RelayServer, String> {
        let server = Arc::new(tiny_http::Server::http(addr).map_err(|e| e.to_string())?);
        let bound = server.server_addr().to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let limits = Arc::new(Limits::default());
        let mut threads = vec![];
        for i in 0..8 {
            let (srv, st, stop2, lim, fs) = (server.clone(), store.clone(), stop.clone(), limits.clone(), files.clone());
            threads.push(std::thread::Builder::new().name(format!("sentrix-relay-{i}")).spawn(move || {
                while !stop2.load(Ordering::Relaxed) {
                    match srv.recv_timeout(Duration::from_millis(300)) {
                        Ok(Some(req)) => handle(req, &st, &lim, trust_proxy, fs.as_deref()),
                        Ok(None) => {}
                        Err(_) => std::thread::sleep(Duration::from_millis(50)),
                    }
                }
            }).map_err(|e| e.to_string())?);
        }
        Ok(RelayServer { stop, threads, addr: bound })
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

fn reply(req: tiny_http::Request, status: u16, body: Value) {
    let s = body.to_string();
    let mut r = tiny_http::Response::from_string(s).with_status_code(status);
    if let Ok(h) = tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]) {
        r = r.with_header(h);
    }
    let _ = req.respond(r);
}

fn bearer(req: &tiny_http::Request) -> Option<String> {
    req.headers().iter().find(|h| h.field.equiv("Authorization")).and_then(|h| h.value.as_str().strip_prefix("Bearer ").map(|t| t.trim().to_string())).filter(|t| t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()))
}

fn client_ip(req: &tiny_http::Request, trust_proxy: bool) -> IpAddr {
    if trust_proxy {
        if let Some(ip) = req.headers().iter().find(|h| h.field.equiv("X-Forwarded-For")).and_then(|h| h.value.as_str().split(',').next_back()).and_then(|s| s.trim().parse().ok()) {
            return ip;
        }
    }
    req.remote_addr().map(|a| a.ip()).unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

fn read_json(req: &mut tiny_http::Request) -> Option<Value> {
    let mut buf = Vec::new();
    req.as_reader().take(MAX_BODY + 1).read_to_end(&mut buf).ok()?;
    if buf.len() as u64 > MAX_BODY {
        return None;
    }
    serde_json::from_slice(&buf).ok()
}

fn handle(mut req: tiny_http::Request, store: &JobStore, lim: &Limits, trust_proxy: bool, files: Option<&dyn FileSource>) {
    let now = now_ms();
    let url = req.url().split('?').next().unwrap_or("").to_string();
    let method = req.method().clone();
    match (method.as_str(), url.as_str()) {
        ("POST", "/v1/link") => {
            let ip = client_ip(&req, trust_proxy);
            let window = Duration::from_secs(600);
            let ok_ip = hit(&lim.link_ip, &ip, LINK_TRIES_PER_10_MIN_PER_IP, window);
            let ok_all = {
                let mut q = lim.link_all.lock().unwrap();
                let n = Instant::now();
                while q.front().is_some_and(|t| n.duration_since(*t) > window) {
                    q.pop_front();
                }
                if q.len() >= LINK_TRIES_PER_10_MIN_ALL {
                    false
                } else {
                    q.push_back(n);
                    true
                }
            };
            if !(ok_ip && ok_all) {
                return reply(req, 429, json!({"error": "Too many attempts. Wait a few minutes."}));
            }
            let Some(b) = read_json(&mut req) else { return reply(req, 400, json!({"error": "Bad request."})) };
            let code = normalize_device_code(b["code"].as_str().unwrap_or(""));
            let name = b["name"].as_str().unwrap_or("My computer").to_string();
            if code.len() != 8 {
                return reply(req, 400, json!({"error": "That code does not look right."}));
            }
            let Some(user) = store.code_take(CodeKind::Device, &code, now) else {
                return reply(req, 400, json!({"error": "That code is wrong, expired or already used. Ask the bot for a new one."}));
            };
            let mut raw = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut raw);
            let token = hex::encode(raw);
            if store.device_create(user, &name, &token_hash(&token), now).is_err() {
                return reply(req, 500, json!({"error": "Could not link. Try again."}));
            }
            let who = store.user_get(user).ok().flatten().map(|u| u.first_name).unwrap_or_default();
            let safe: String = name.chars().filter(|c| !c.is_control()).take(60).collect();
            let text = format!("<b>SENTRIX app linked</b>\n{} is now connected. Results from files it checks will arrive here.", sanitize_html(&safe));
            let _ = store.enqueue_notification_to(&format!("relay-linked:{user}:{now}"), "hosted_notice", &text, now, Some(user), None);
            store.add_event("relay_linked", "info", "A SENTRIX app was linked to a person's chat.", now);
            reply(req, 200, json!({"token": token, "userName": who}));
        }
        ("POST", "/v1/report") => {
            let Some(token) = bearer(&req) else { return reply(req, 401, json!({"error": "Not linked."})) };
            let Some(dev) = store.device_by_token(&token) else { return reply(req, 401, json!({"error": "Not linked."})) };
            if !hit(&lim.per_device, &format!("{}:m", dev.id), REPORTS_PER_MIN, Duration::from_secs(60)) || !hit(&lim.per_device, &format!("{}:h", dev.id), REPORTS_PER_HOUR, Duration::from_secs(3600)) {
                return reply(req, 429, json!({"error": "Too many reports. They will be retried."}));
            }
            let Some(b) = read_json(&mut req) else { return reply(req, 400, json!({"error": "Bad request."})) };
            let text = sanitize_html(b["text"].as_str().unwrap_or(""));
            if text.trim().is_empty() {
                return reply(req, 400, json!({"error": "Nothing to send."}));
            }
            store.device_touch(&dev.id, now);
            if !store.user_reachable(dev.user_id) {
                return reply(req, 409, json!({"error": "The bot cannot write to this person. Open the bot in Telegram and press Start."}));
            }
            // Same text from the same computer within ten minutes is one message (a retry after a lost reply).
            let key = format!("relay:{}:{}:{}", dev.id, hex::encode(&Sha256::digest(text.as_bytes())[..8]), now / 600_000);
            // The target is always the person this token was issued to. The request cannot name a chat.
            let queued = store.enqueue_notification_to(&key, "relay", &text, now, Some(dev.user_id), None).unwrap_or(false);
            reply(req, 202, json!({"queued": queued}));
        }
        ("GET", "/v1/status") => {
            let Some(token) = bearer(&req) else { return reply(req, 401, json!({"error": "Not linked."})) };
            let Some(dev) = store.device_by_token(&token) else { return reply(req, 401, json!({"error": "Not linked."})) };
            store.device_touch(&dev.id, now);
            reply(req, 200, json!({"linked": true, "reachable": store.user_reachable(dev.user_id)}));
        }
        ("DELETE", "/v1/link") => {
            let Some(token) = bearer(&req) else { return reply(req, 401, json!({"error": "Not linked."})) };
            let Some(dev) = store.device_by_token(&token) else { return reply(req, 401, json!({"error": "Not linked."})) };
            store.device_revoke(dev.user_id, &dev.id, now);
            reply(req, 204, json!(null));
        }
        ("GET", "/v1/jobs") => {
            let Some(token) = bearer(&req) else { return reply(req, 401, json!({"error": "Not linked."})) };
            let Some(dev) = store.device_by_token(&token) else { return reply(req, 401, json!({"error": "Not linked."})) };
            if !hit(&lim.per_device, &format!("{}:j", dev.id), JOB_POLLS_PER_MIN, Duration::from_secs(60)) {
                return reply(req, 429, json!({"error": "Asking too often."}));
            }
            // Asking for work is also how the app shows it is installed and running.
            store.device_touch(&dev.id, now);
            let jobs: Vec<EdgeJobInfo> = store
                .edge_claim(dev.user_id, EDGE_BATCH, now)
                .into_iter()
                .map(|j| {
                    let group = store.group_get(j.group_chat).ok().flatten().map(|g| g.title).unwrap_or_default();
                    EdgeJobInfo { id: j.id, name: j.name, size: j.size, group: group.chars().filter(|c| !c.is_control()).take(60).collect() }
                })
                .collect();
            reply(req, 200, json!({ "jobs": jobs }));
        }
        ("GET", p) if job_path(p, "/file").is_some() => {
            let id = job_path(p, "/file").unwrap().to_string();
            let Some(token) = bearer(&req) else { return reply(req, 401, json!({"error": "Not linked."})) };
            let Some(dev) = store.device_by_token(&token) else { return reply(req, 401, json!({"error": "Not linked."})) };
            if !hit(&lim.per_device, &format!("{}:f", dev.id), FILE_FETCHES_PER_MIN, Duration::from_secs(60)) {
                return reply(req, 429, json!({"error": "Too many files at once."}));
            }
            // Only the person the file belongs to, and only a job that was handed out to their apps.
            let job = match store.edge_get(&id) {
                Some(j) if j.owner == dev.user_id && j.state == "leased" => j,
                _ => return reply(req, 404, json!({"error": "No such file for you."})),
            };
            let Some(src) = files else { return reply(req, 503, json!({"error": "This server cannot hand out files."})) };
            store.device_touch(&dev.id, now);
            // The bytes live in memory only for as long as this answer takes. Nothing is written to the server's disk.
            match src.fetch(&job.file_id, MAX_BOT_DOWNLOAD) {
                Ok(bytes) => {
                    let mut r = tiny_http::Response::from_data(bytes);
                    if let Ok(h) = tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/octet-stream"[..]) {
                        r = r.with_header(h);
                    }
                    let _ = req.respond(r);
                }
                Err(e) => reply(req, 502, json!({"error": e.chars().filter(|c| !c.is_control()).take(200).collect::<String>()})),
            }
        }
        ("POST", p) if job_path(p, "/result").is_some() => {
            let id = job_path(p, "/result").unwrap().to_string();
            let Some(token) = bearer(&req) else { return reply(req, 401, json!({"error": "Not linked."})) };
            let Some(dev) = store.device_by_token(&token) else { return reply(req, 401, json!({"error": "Not linked."})) };
            let Some(b) = read_json(&mut req) else { return reply(req, 400, json!({"error": "Bad request."})) };
            let Ok(sub) = serde_json::from_value::<EdgeSubmit>(b) else { return reply(req, 400, json!({"error": "Bad request."})) };
            store.device_touch(&dev.id, now);
            let (ok, payload) = match (sub.ok, &sub.result) {
                (true, Some(r)) => (true, serde_json::to_string(r).unwrap_or_default()),
                _ => (false, sub.error.unwrap_or_default().chars().filter(|c| !c.is_control()).take(200).collect::<String>()),
            };
            if store.edge_finish(&id, dev.user_id, ok, &payload, now) {
                reply(req, 200, json!({"ok": true}));
            } else {
                reply(req, 404, json!({"error": "No such job for you, or it was already answered."}));
            }
        }
        _ => reply(req, 404, json!({"error": "Not found."})),
    }
}

/// `/v1/jobs/<id><suffix>` with a well-formed id (a UUID), or `None`.
fn job_path<'a>(path: &'a str, suffix: &str) -> Option<&'a str> {
    let id = path.strip_prefix("/v1/jobs/")?.strip_suffix(suffix)?;
    (id.len() == 36 && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-')).then_some(id)
}

// ---- client ------------------------------------------------------------------------------------------------------

/// https only, except this machine (development and tests).
pub fn validate_relay_url(raw: &str) -> Result<String, String> {
    let s = raw.trim().trim_end_matches('/').to_string();
    let local = ["http://127.0.0.1", "http://localhost"].iter().any(|p| s == *p || s.starts_with(&format!("{p}:")));
    if (s.starts_with("https://") && s.len() > 8 && !s.contains(['@', ' ', '?', '#'])) || local {
        Ok(s)
    } else {
        Err("The SENTRIX relay address must start with https://".into())
    }
}

pub struct RelayClient {
    base: String,
    token: String,
    agent: ureq::Agent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Linked {
    pub token: String,
    pub user_name: String,
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(20))).http_status_as_error(false).build().into()
}

fn err_text(v: &Value, fallback: &str) -> String {
    v["error"].as_str().unwrap_or(fallback).to_string()
}

/// Exchange the code shown by the bot for a device token. The token is returned once; the caller must store it protected.
pub fn link(base: &str, code: &str, name: &str) -> Result<Linked, String> {
    let base = validate_relay_url(base)?;
    let mut resp = agent().post(&format!("{base}/v1/link")).send_json(json!({"code": code, "name": name})).map_err(|_| "Could not reach the SENTRIX relay. Check your internet connection.".to_string())?;
    let status = resp.status().as_u16();
    let v: Value = resp.body_mut().read_json().unwrap_or(json!({}));
    if status != 200 {
        return Err(err_text(&v, "Linking failed."));
    }
    Ok(Linked { token: v["token"].as_str().ok_or("Linking failed.")?.to_string(), user_name: v["userName"].as_str().unwrap_or("").to_string() })
}

impl RelayClient {
    pub fn new(base: &str, token: &str) -> Result<Self, String> {
        Ok(RelayClient { base: validate_relay_url(base)?, token: token.to_string(), agent: agent() })
    }

    /// `Ok((linked, reachable))`. `linked == false` means the bot's owner unlinked this computer.
    pub fn status(&self) -> Result<(bool, bool), String> {
        let mut r = self.agent.get(&format!("{}/v1/status", self.base)).header("Authorization", &format!("Bearer {}", self.token)).call().map_err(|_| "Could not reach the SENTRIX relay.".to_string())?;
        match r.status().as_u16() {
            200 => {
                let v: Value = r.body_mut().read_json().unwrap_or(json!({}));
                Ok((true, v["reachable"].as_bool().unwrap_or(false)))
            }
            401 => Ok((false, false)),
            c => Err(format!("The relay answered {c}.")),
        }
    }

    /// Files waiting to be checked on this computer. Also tells the relay the app is running.
    pub fn jobs(&self) -> Result<Vec<EdgeJobInfo>, String> {
        let mut r = self.agent.get(&format!("{}/v1/jobs", self.base)).header("Authorization", &format!("Bearer {}", self.token)).call().map_err(|_| "Could not reach the SENTRIX relay.".to_string())?;
        match r.status().as_u16() {
            200 => {
                let v: Value = r.body_mut().read_json().unwrap_or(json!({}));
                Ok(serde_json::from_value(v["jobs"].clone()).unwrap_or_default())
            }
            401 => Err("This computer is not linked any more.".into()),
            c => Err(format!("The relay answered {c}.")),
        }
    }

    /// The bytes of one file, as the bot received them from Telegram.
    pub fn fetch_job_file(&self, id: &str) -> Result<Vec<u8>, String> {
        let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(180))).http_status_as_error(false).build().into();
        let mut r = agent.get(&format!("{}/v1/jobs/{id}/file", self.base)).header("Authorization", &format!("Bearer {}", self.token)).call().map_err(|_| "Could not reach the SENTRIX relay.".to_string())?;
        match r.status().as_u16() {
            200 => r.body_mut().with_config().limit(MAX_BOT_DOWNLOAD + 1).read_to_vec().map_err(|e| e.to_string()),
            c => {
                let v: Value = r.body_mut().read_json().unwrap_or(json!({}));
                Err(err_text(&v, &format!("The relay answered {c}.")))
            }
        }
    }

    /// Send the verdict for one file.
    pub fn submit_job_result(&self, id: &str, s: &EdgeSubmit) -> Result<(), String> {
        let mut r = self.agent.post(&format!("{}/v1/jobs/{id}/result", self.base)).header("Authorization", &format!("Bearer {}", self.token)).send_json(s).map_err(|_| "Could not reach the SENTRIX relay.".to_string())?;
        match r.status().as_u16() {
            200 => Ok(()),
            // Already answered (a retry after a lost reply) is fine.
            404 => Ok(()),
            c => {
                let v: Value = r.body_mut().read_json().unwrap_or(json!({}));
                Err(err_text(&v, &format!("The relay answered {c}.")))
            }
        }
    }

    /// Tell the relay to forget this computer. Best effort: the local token is erased regardless.
    pub fn unlink(&self) -> bool {
        self.agent.delete(&format!("{}/v1/link", self.base)).header("Authorization", &format!("Bearer {}", self.token)).call().map(|r| r.status().as_u16() == 204).unwrap_or(false)
    }
}

impl Courier for RelayClient {
    fn send_reply(&self, _chat_id: i64, text: &str, _reply_to: Option<i64>) -> Result<i64, TgError> {
        let mut r = self.agent.post(&format!("{}/v1/report", self.base)).header("Authorization", &format!("Bearer {}", self.token)).send_json(json!({"text": text})).map_err(|e| TgError::Network(e.to_string()))?;
        let code = r.status().as_u16();
        if code == 202 {
            return Ok(0);
        }
        let v: Value = r.body_mut().read_json().unwrap_or(json!({}));
        let retry_after = r.headers().get("Retry-After").and_then(|h| h.to_str().ok()).and_then(|s| s.parse().ok());
        Err(TgError::Api { code, description: err_text(&v, "report refused"), retry_after })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_basic_formatting_survives() {
        assert_eq!(sanitize_html("<b>Bad</b> file <code>x.exe</code>"), "<b>Bad</b> file <code>x.exe</code>");
        assert_eq!(sanitize_html("<a href=\"https://evil\">click</a>"), "&lt;a href=\"https://evil\"&gt;click&lt;/a&gt;");
        assert_eq!(sanitize_html("<script>alert(1)</script>"), "&lt;script&gt;alert(1)&lt;/script&gt;");
        assert_eq!(sanitize_html("a & b"), "a &amp; b");
        assert_eq!(sanitize_html("1 &lt; 2"), "1 &lt; 2", "an entity that is already correct is kept");
    }

    #[test]
    fn unbalanced_tags_are_dropped_instead_of_breaking_the_message() {
        assert_eq!(sanitize_html("<b>open only"), "open only");
        assert_eq!(sanitize_html("close only</b>"), "close only");
        assert_eq!(sanitize_html("<b><i>x</b></i>"), "x");
    }

    #[test]
    fn control_characters_and_length_are_limited() {
        assert_eq!(sanitize_html("a\u{0}b\u{7}c"), "abc");
        assert!(sanitize_html(&"x".repeat(10_000)).len() <= MAX_TEXT);
    }

    #[test]
    fn the_relay_address_must_be_https_or_this_machine() {
        assert!(validate_relay_url("https://relay.example.com").is_ok());
        assert!(validate_relay_url("http://127.0.0.1:8787").is_ok());
        assert!(validate_relay_url("http://relay.example.com").is_err());
        assert!(validate_relay_url("https://user:pw@relay.example.com").is_err());
        assert!(validate_relay_url("ftp://x").is_err());
    }
}

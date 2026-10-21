//! A local TEST DOUBLE of the Telegram Bot API (getMe, sendMessage, getUpdates, getFile, file download).
//! Tests built on it prove that SENTRIX's client and pipeline behave correctly against the documented protocol.
//! They are NOT a test of live Telegram: nothing here talks to api.telegram.org.
#![allow(dead_code)]

use sentrix_core::service::Hooks;
use sentrix_core::ScanReport;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const TOKEN: &str = "123456789:AAHkq3Zr0pXxJ2mN8sVbT5wYcLdEfGh1Ijk";
pub const CHAT: i64 = 4242;

#[derive(Debug, Clone)]
pub enum Fail {
    Status(u16),
    RateLimit(u64),
    /// Close the connection without answering.
    Drop,
}

#[derive(Default)]
pub struct State {
    pub sent: Vec<(i64, String)>,
    pub calls: Vec<String>,
    pub send_failures: VecDeque<Fail>,
    pub updates: Vec<Value>,
    pub files: HashMap<String, Vec<u8>>,
    /// getFile reports this size instead of the real one (to test a lying server).
    pub lie_about_size: HashMap<String, u64>,
    /// Simulated groups the bot is in, by chat id.
    pub groups: HashMap<i64, GroupSim>,
    /// (chat, message) pairs the bot successfully deleted.
    pub deleted: Vec<(i64, i64)>,
    /// reply_to of each entry in `sent`.
    pub reply_to: Vec<Option<i64>>,
    /// BotFather privacy mode: when true, getMe reports can_read_all_group_messages = false.
    pub privacy_on: bool,
}

#[derive(Debug, Clone, Default)]
pub struct GroupSim {
    pub admins: Vec<i64>,
    pub bot_admin: bool,
    pub bot_can_delete: bool,
}

pub const BOT_ID: i64 = 123456789;

pub struct Mock {
    pub base: String,
    pub state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
}

impl Mock {
    pub fn start() -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        listener.set_nonblocking(true).unwrap();
        let state = Arc::new(Mutex::new(State::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let (s2, st2) = (state.clone(), stop.clone());
        std::thread::spawn(move || {
            while !st2.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((conn, _)) => {
                        // On Windows an accepted socket inherits the listener's non-blocking mode; a read that races the
                        // client's send would then fail with WouldBlock and the connection would be dropped.
                        let _ = conn.set_nonblocking(false);
                        let s3 = s2.clone();
                        std::thread::spawn(move || handle(conn, s3));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Mock { base, state, stop }
    }

    pub fn sent_texts(&self) -> Vec<String> {
        self.state.lock().unwrap().sent.iter().map(|(_, t)| t.clone()).collect()
    }

    pub fn add_document_update(&self, update_id: i64, chat: i64, from: i64, name: &str, bytes: Vec<u8>) {
        let mut s = self.state.lock().unwrap();
        let id = format!("FILE{update_id}");
        let size = bytes.len();
        s.files.insert(id.clone(), bytes);
        s.updates.push(json!({"update_id": update_id, "message": {"chat": {"id": chat, "type": "private"}, "from": {"id": from}, "document": {"file_id": id, "file_name": name, "file_size": size}}}));
    }

    pub fn add_text_update(&self, update_id: i64, chat: i64, from: i64, text: &str) {
        self.state.lock().unwrap().updates.push(json!({"update_id": update_id, "message": {"chat": {"id": chat, "type": "private"}, "from": {"id": from}, "text": text}}));
    }

    pub fn add_group(&self, chat: i64, admins: &[i64], bot_admin: bool, bot_can_delete: bool) {
        self.state.lock().unwrap().groups.insert(chat, GroupSim { admins: admins.to_vec(), bot_admin, bot_can_delete });
    }

    pub fn set_bot_can_delete(&self, chat: i64, v: bool) {
        if let Some(g) = self.state.lock().unwrap().groups.get_mut(&chat) {
            g.bot_can_delete = v;
        }
    }

    pub fn add_bot_joined(&self, update_id: i64, chat: i64, title: &str, by: i64) {
        self.state.lock().unwrap().updates.push(json!({"update_id": update_id, "my_chat_member": {"chat": {"id": chat, "type": "supergroup", "title": title}, "from": {"id": by}, "old_chat_member": {"status": "left"}, "new_chat_member": {"status": "member"}}}));
    }

    pub fn add_bot_removed(&self, update_id: i64, chat: i64, title: &str) {
        self.state.lock().unwrap().updates.push(json!({"update_id": update_id, "my_chat_member": {"chat": {"id": chat, "type": "supergroup", "title": title}, "from": {"id": 1}, "old_chat_member": {"status": "member"}, "new_chat_member": {"status": "kicked"}}}));
    }

    pub fn add_group_text(&self, update_id: i64, chat: i64, message_id: i64, from: i64, text: &str) {
        self.state.lock().unwrap().updates.push(json!({"update_id": update_id, "message": {"message_id": message_id, "chat": {"id": chat, "type": "supergroup", "title": "Test group"}, "from": {"id": from}, "text": text}}));
    }

    /// An administrator posting anonymously: the "sender" is the group itself.
    pub fn add_anonymous_group_text(&self, update_id: i64, chat: i64, message_id: i64, text: &str) {
        self.state.lock().unwrap().updates.push(json!({"update_id": update_id, "message": {"message_id": message_id, "chat": {"id": chat, "type": "supergroup", "title": "Test group"}, "from": {"id": 1087}, "sender_chat": {"id": chat, "type": "supergroup"}, "text": text}}));
    }

    /// `advertised_size` lets a test claim a size different from the real bytes.
    pub fn add_group_document(&self, update_id: i64, chat: i64, message_id: i64, from: i64, name: &str, bytes: Vec<u8>, advertised_size: Option<u64>) {
        let mut s = self.state.lock().unwrap();
        let id = format!("GFILE{update_id}");
        let size = advertised_size.unwrap_or(bytes.len() as u64);
        s.files.insert(id.clone(), bytes);
        s.updates.push(json!({"update_id": update_id, "message": {"message_id": message_id, "chat": {"id": chat, "type": "supergroup", "title": "Test group"}, "from": {"id": from}, "document": {"file_id": id, "file_unique_id": format!("U{update_id}"), "file_name": name, "file_size": size}}}));
    }

    /// A document whose file Telegram will refuse to serve (expired, deleted, or otherwise inaccessible).
    pub fn add_group_document_gone(&self, update_id: i64, chat: i64, message_id: i64, from: i64, name: &str) {
        self.state.lock().unwrap().updates.push(json!({"update_id": update_id, "message": {"message_id": message_id, "chat": {"id": chat, "type": "supergroup", "title": "Test group"}, "from": {"id": from}, "document": {"file_id": "GONE", "file_unique_id": "UGONE", "file_name": name, "file_size": 100}}}));
    }

    pub fn texts_in(&self, chat: i64) -> Vec<String> {
        self.state.lock().unwrap().sent.iter().filter(|(c, _)| *c == chat).map(|(_, t)| t.clone()).collect()
    }

    pub fn deleted(&self) -> Vec<(i64, i64)> {
        self.state.lock().unwrap().deleted.clone()
    }

    pub fn called(&self, method: &str) -> usize {
        self.state.lock().unwrap().calls.iter().filter(|m| m.as_str() == method).count()
    }

    pub fn wait_for_messages_in(&self, chat: i64, n: usize, secs: u64) -> bool {
        let end = std::time::Instant::now() + Duration::from_secs(secs);
        while std::time::Instant::now() < end {
            if self.texts_in(chat).len() >= n {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    pub fn wait_for_messages(&self, n: usize, secs: u64) -> bool {
        let end = std::time::Instant::now() + Duration::from_secs(secs);
        while std::time::Instant::now() < end {
            if self.state.lock().unwrap().sent.len() >= n {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn respond(conn: &mut TcpStream, status: u16, body: &[u8], ctype: &str) {
    let head = format!("HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    let _ = conn.write_all(head.as_bytes());
    let _ = conn.write_all(body);
    let _ = conn.flush();
}

fn json_resp(conn: &mut TcpStream, status: u16, v: Value) {
    respond(conn, status, v.to_string().as_bytes(), "application/json");
}

fn handle(mut conn: TcpStream, state: Arc<Mutex<State>>) {
    let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        match conn.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let first = head.lines().next().unwrap_or("").to_string();
    let path = first.split_whitespace().nth(1).unwrap_or("").to_string();
    let clen: usize = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0))).unwrap_or(0);
    while buf.len() < header_end + clen {
        match conn.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    let body: Value = serde_json::from_slice(&buf[header_end..]).unwrap_or(json!({}));

    // File download: /file/bot<token>/<path>
    if let Some(rest) = path.strip_prefix(&format!("/file/bot{TOKEN}/")) {
        let id = rest.trim_start_matches("docs/");
        let s = state.lock().unwrap();
        match s.files.get(id) {
            Some(b) => respond(&mut conn, 200, b, "application/octet-stream"),
            None => respond(&mut conn, 404, b"", "text/plain"),
        }
        return;
    }
    let Some(rest) = path.strip_prefix("/bot") else { return respond(&mut conn, 404, b"", "text/plain") };
    let (tok, method) = rest.split_once('/').unwrap_or((rest, ""));
    state.lock().unwrap().calls.push(method.to_string());
    if tok != TOKEN {
        return json_resp(&mut conn, 401, json!({"ok": false, "error_code": 401, "description": "Unauthorized"}));
    }
    match method {
        "getMe" => {
            let privacy = state.lock().unwrap().privacy_on;
            json_resp(&mut conn, 200, json!({"ok": true, "result": {"id": BOT_ID, "is_bot": true, "first_name": "SENTRIX Test", "username": "sentrix_test_bot", "can_join_groups": true, "can_read_all_group_messages": !privacy}}))
        }
        "getChatMember" => {
            let chat = body["chat_id"].as_i64().unwrap_or(0);
            let user = body["user_id"].as_i64().unwrap_or(0);
            let s = state.lock().unwrap();
            let Some(g) = s.groups.get(&chat) else { return json_resp(&mut conn, 400, json!({"ok": false, "error_code": 400, "description": "Bad Request: chat not found"})) };
            let r = if user == BOT_ID {
                if g.bot_admin { json!({"status": "administrator", "can_delete_messages": g.bot_can_delete}) } else { json!({"status": "member"}) }
            } else if g.admins.contains(&user) {
                json!({"status": "administrator", "can_delete_messages": true})
            } else {
                json!({"status": "member"})
            };
            json_resp(&mut conn, 200, json!({"ok": true, "result": r}));
        }
        "deleteMessage" => {
            let chat = body["chat_id"].as_i64().unwrap_or(0);
            let mid = body["message_id"].as_i64().unwrap_or(0);
            let mut s = state.lock().unwrap();
            let allowed = s.groups.get(&chat).is_some_and(|g| g.bot_admin && g.bot_can_delete);
            if !allowed {
                return json_resp(&mut conn, 400, json!({"ok": false, "error_code": 400, "description": "Bad Request: not enough rights to delete the message"}));
            }
            s.deleted.push((chat, mid));
            json_resp(&mut conn, 200, json!({"ok": true, "result": true}));
        }
        "sendMessage" => {
            let fail = state.lock().unwrap().send_failures.pop_front();
            match fail {
                Some(Fail::Drop) => return,
                Some(Fail::Status(c)) => return json_resp(&mut conn, c, json!({"ok": false, "error_code": c, "description": "Internal Server Error"})),
                Some(Fail::RateLimit(s)) => return json_resp(&mut conn, 429, json!({"ok": false, "error_code": 429, "description": "Too Many Requests: retry later", "parameters": {"retry_after": s}})),
                None => {}
            }
            let chat = body["chat_id"].as_i64().unwrap_or(0);
            if chat != CHAT && !state.lock().unwrap().groups.contains_key(&chat) {
                return json_resp(&mut conn, 400, json!({"ok": false, "error_code": 400, "description": "Bad Request: chat not found"}));
            }
            let text = body["text"].as_str().unwrap_or("").to_string();
            let reply = body["reply_parameters"]["message_id"].as_i64();
            let mut s = state.lock().unwrap();
            s.reply_to.push(reply);
            s.sent.push((chat, text));
            let id = s.sent.len();
            json_resp(&mut conn, 200, json!({"ok": true, "result": {"message_id": id}}));
        }
        "getUpdates" => {
            let offset = body["offset"].as_i64().unwrap_or(0);
            let s = state.lock().unwrap();
            let r: Vec<Value> = s.updates.iter().filter(|u| u["update_id"].as_i64().unwrap_or(0) >= offset).cloned().collect();
            drop(s);
            if r.is_empty() {
                std::thread::sleep(Duration::from_millis(150));
            }
            json_resp(&mut conn, 200, json!({"ok": true, "result": r}));
        }
        "getFile" => {
            let id = body["file_id"].as_str().unwrap_or("");
            let s = state.lock().unwrap();
            match s.files.get(id) {
                Some(b) => {
                    let size = s.lie_about_size.get(id).copied().unwrap_or(b.len() as u64);
                    json_resp(&mut conn, 200, json!({"ok": true, "result": {"file_id": id, "file_size": size, "file_path": format!("docs/{id}")}}))
                }
                None => json_resp(&mut conn, 400, json!({"ok": false, "error_code": 400, "description": "Bad Request: file not found"})),
            }
        }
        _ => json_resp(&mut conn, 404, json!({"ok": false, "error_code": 404, "description": "Not Found"})),
    }
}

/// Collects every final report the service hands to the UI layer.
#[derive(Default)]
pub struct Collect {
    pub reports: Mutex<Vec<ScanReport>>,
}

impl Hooks for Collect {
    fn on_report(&self, r: &ScanReport) {
        self.reports.lock().unwrap().push(r.clone());
    }
}

impl Collect {
    pub fn wait_for(&self, n: usize, secs: u64) -> bool {
        let end = std::time::Instant::now() + Duration::from_secs(secs);
        while std::time::Instant::now() < end {
            if self.reports.lock().unwrap().len() >= n {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }
    pub fn count(&self) -> usize {
        self.reports.lock().unwrap().len()
    }
}

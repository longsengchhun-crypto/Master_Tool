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
}

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
        "getMe" => json_resp(&mut conn, 200, json!({"ok": true, "result": {"id": 123456789, "is_bot": true, "first_name": "SENTRIX Test", "username": "sentrix_test_bot"}})),
        "sendMessage" => {
            let fail = state.lock().unwrap().send_failures.pop_front();
            match fail {
                Some(Fail::Drop) => return,
                Some(Fail::Status(c)) => return json_resp(&mut conn, c, json!({"ok": false, "error_code": c, "description": "Internal Server Error"})),
                Some(Fail::RateLimit(s)) => return json_resp(&mut conn, 429, json!({"ok": false, "error_code": 429, "description": "Too Many Requests: retry later", "parameters": {"retry_after": s}})),
                None => {}
            }
            let chat = body["chat_id"].as_i64().unwrap_or(0);
            if chat != CHAT {
                return json_resp(&mut conn, 400, json!({"ok": false, "error_code": 400, "description": "Bad Request: chat not found"}));
            }
            let text = body["text"].as_str().unwrap_or("").to_string();
            let mut s = state.lock().unwrap();
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

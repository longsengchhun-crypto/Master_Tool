//! Telegram **Bot API** client (https://core.telegram.org/bots/api). This is the *only* Telegram surface in this crate.
//! It is not an account client: a bot can see only messages sent to it, which is exactly what we need for (a) sending
//! reports to the user and (b) receiving files the user chooses to send to their own bot.
//!
//! Security properties:
//!  * the token is validated for shape and never appears in any error string (`redact`);
//!  * endpoints must be https (loopback http is allowed so tests can use a local test server);
//!  * every call has timeouts; downloads are size-capped before and while reading;
//!  * attacker-controlled text (file names) is HTML-escaped and stripped of control/bidi characters before sending.

use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::time::Duration;

pub const DEFAULT_BASE: &str = "https://api.telegram.org";
/// Telegram Bot API `getFile` limit (https://core.telegram.org/bots/faq).
pub const MAX_BOT_DOWNLOAD: u64 = 20 * 1024 * 1024;
/// Telegram's hard limit for one message's text.
pub const MAX_MESSAGE_CHARS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TgError {
    /// DNS/TLS/connect/timeout. Retryable.
    Network(String),
    Api { code: u16, description: String, retry_after: Option<u64> },
    Parse(String),
    TooLarge(u64),
    InvalidToken,
    InvalidEndpoint(String),
}

impl TgError {
    pub fn is_retryable(&self) -> bool {
        match self {
            TgError::Network(_) => true,
            TgError::Api { code, .. } => *code == 429 || *code >= 500,
            _ => false,
        }
    }

    /// Server-requested wait (HTTP 429), in milliseconds.
    pub fn retry_after_ms(&self) -> Option<i64> {
        match self {
            TgError::Api { retry_after: Some(s), .. } => Some((*s as i64 + 1) * 1000),
            _ => None,
        }
    }

    /// Plain-language explanation for the UI. Never contains the token.
    pub fn user_message(&self) -> String {
        match self {
            TgError::Network(_) => "Could not reach Telegram. Check your internet connection; SENTRIX will keep retrying.".into(),
            TgError::Api { code: 401, .. } => "Telegram rejected the bot token. It may have been revoked or mistyped. Reconnect the bot with a fresh token.".into(),
            TgError::Api { code: 400, description, .. } if description.to_lowercase().contains("chat not found") => "Telegram cannot find that chat. Open your bot in Telegram and press Start, then check the Chat ID.".into(),
            TgError::Api { code: 403, .. } => "Telegram says the bot cannot message you. Open your bot in Telegram and press Start (or unblock it).".into(),
            TgError::Api { code: 409, .. } => "Another program is already receiving this bot's updates (or a webhook is set), so file submissions cannot be read.".into(),
            TgError::Api { code: 429, .. } => "Telegram is rate-limiting this bot. SENTRIX will retry automatically.".into(),
            TgError::Api { description, .. } => format!("Telegram refused the request: {description}"),
            TgError::Parse(_) => "Telegram sent a response SENTRIX could not understand.".into(),
            TgError::TooLarge(_) => "That file is larger than Telegram lets a bot download (20 MB).".into(),
            TgError::InvalidToken => "That does not look like a bot token. It should look like 123456789:AA… and comes from @BotFather.".into(),
            TgError::InvalidEndpoint(m) => m.clone(),
        }
    }
}

impl std::fmt::Display for TgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TgError::Network(m) | TgError::Parse(m) | TgError::InvalidEndpoint(m) => write!(f, "{m}"),
            TgError::Api { code, description, .. } => write!(f, "Telegram API error {code}: {description}"),
            TgError::TooLarge(n) => write!(f, "file too large ({n} bytes)"),
            TgError::InvalidToken => write!(f, "invalid bot token format"),
        }
    }
}
impl std::error::Error for TgError {}

/// `123456789:AAH…` : numeric bot id, a colon, then a URL-safe secret.
pub fn valid_token_shape(t: &str) -> bool {
    let Some((id, secret)) = t.split_once(':') else { return false };
    (5..=20).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_digit()) && (30..=80).contains(&secret.len()) && secret.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Remove the token (and anything shaped like `bot<id>:<secret>`) from text. Applied to every error string.
pub fn redact(text: &str, token: &str) -> String {
    let s = if token.len() >= 8 { text.replace(token, "<bot-token>") } else { text.to_string() };
    // Also catch URL fragments like /bot123:SECRET/ in case the token variable differs (e.g. a previous token).
    // Works on byte offsets of ASCII markers only and copies everything else as whole UTF-8 slices.
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut copied = 0; // start of the not-yet-copied region
    let mut i = 0;
    while i < b.len() {
        if b[i..].starts_with(b"bot") && i + 3 < b.len() && b[i + 3].is_ascii_digit() {
            let mut j = i + 3;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if j < b.len() && b[j] == b':' {
                let mut k = j + 1;
                while k < b.len() && (b[k].is_ascii_alphanumeric() || b[k] == b'_' || b[k] == b'-') {
                    k += 1;
                }
                if k - (j + 1) >= 20 {
                    out.push_str(&s[copied..i]);
                    out.push_str("bot<redacted>");
                    copied = k;
                    i = k;
                    continue;
                }
            }
        }
        i += 1;
    }
    out.push_str(&s[copied..]);
    out
}

/// https only, except loopback (tests / local development).
pub fn validate_base(raw: &str) -> Result<String, TgError> {
    let s = raw.trim().trim_end_matches('/').to_string();
    let ok = s.starts_with("https://") && s.len() > 8 && !s.contains(['@', ' ', '?', '#'])
        || ["http://127.0.0.1", "http://localhost"].iter().any(|p| s == *p || s.starts_with(&format!("{p}:")));
    if ok {
        Ok(s)
    } else {
        Err(TgError::InvalidEndpoint("The Telegram endpoint must use https.".into()))
    }
}

// ---- model ---------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct BotInfo {
    pub id: i64,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub first_name: Option<String>,
    /// False while BotFather "privacy mode" is on: in groups the bot then only receives commands, mentions and replies,
    /// NOT ordinary messages or files (unless it is a group administrator).
    #[serde(default)]
    pub can_read_all_group_messages: Option<bool>,
    #[serde(default)]
    pub can_join_groups: Option<bool>,
}

/// A user's standing in a chat, as reported by Telegram (never inferred from message text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// creator, administrator, member, restricted, left, kicked
    pub status: String,
    pub can_delete_messages: bool,
}

impl Member {
    pub fn is_admin(&self) -> bool {
        self.status == "creator" || self.status == "administrator"
    }
    /// The chat creator can always delete; an administrator needs the explicit right.
    pub fn may_delete(&self) -> bool {
        self.status == "creator" || (self.status == "administrator" && self.can_delete_messages)
    }
}

/// The bot's own membership changed in a chat (added to or removed from a group, promoted, demoted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberChange {
    pub new_status: String,
    pub old_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub file_id: String,
    /// Stable across chats and forwards; used to recognise the same file twice.
    pub file_unique_id: Option<String>,
    pub file_name: Option<String>,
    pub file_size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incoming {
    pub update_id: i64,
    pub chat_id: i64,
    pub chat_type: String,
    pub chat_title: Option<String>,
    pub message_id: Option<i64>,
    pub from_id: Option<i64>,
    /// Set when an administrator posts anonymously (the "sender" is the group itself). The person cannot be identified.
    pub anonymous_admin: bool,
    pub member_change: Option<MemberChange>,
    /// First name of the sender, for greetings only (never stored).
    pub from_name: Option<String>,
    /// A tap on an inline button.
    pub callback: Option<Callback>,
    pub text: Option<String>,
    pub document: Option<Document>,
    /// A photo/video/audio/etc. was sent instead of a document (Telegram recompresses photos, so they are not scanned).
    pub other_media: bool,
}

/// A tap on an inline button: `id` must be answered, `data` is what the button carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Callback {
    pub id: String,
    pub data: String,
}

/// An inline button under a message.
#[derive(Debug, Clone)]
pub enum Button {
    Callback { text: String, data: String },
    Url { text: String, url: String },
}

impl Button {
    pub fn callback(text: &str, data: &str) -> Button {
        Button::Callback { text: text.into(), data: data.into() }
    }
    pub fn url(text: &str, url: &str) -> Button {
        Button::Url { text: text.into(), url: url.into() }
    }
    fn json(&self) -> Value {
        match self {
            Button::Callback { text, data } => json!({ "text": text, "callback_data": data }),
            Button::Url { text, url } => json!({ "text": text, "url": url }),
        }
    }
}

/// Anything that can deliver a queued report: the bot directly, or the relay in front of a shared bot.
pub trait Courier: Send + Sync {
    fn send_reply(&self, chat_id: i64, text: &str, reply_to: Option<i64>) -> Result<i64, TgError>;
}

impl Courier for BotClient {
    fn send_reply(&self, chat_id: i64, text: &str, reply_to: Option<i64>) -> Result<i64, TgError> {
        BotClient::send_reply(self, chat_id, text, reply_to)
    }
}

pub struct BotClient {
    token: String,
    base: String,
    agent: ureq::Agent,
}

impl BotClient {
    pub fn new(token: &str) -> Result<Self, TgError> {
        Self::with_base(token, DEFAULT_BASE)
    }

    pub fn with_base(token: &str, base: &str) -> Result<Self, TgError> {
        if !valid_token_shape(token) {
            return Err(TgError::InvalidToken);
        }
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(30))).build().into();
        Ok(BotClient { token: token.to_string(), base: validate_base(base)?, agent })
    }

    fn red(&self, s: impl AsRef<str>) -> String {
        redact(s.as_ref(), &self.token)
    }

    fn url(&self, method: &str) -> String {
        format!("{}/bot{}/{}", self.base, self.token, method)
    }

    fn call(&self, method: &str, body: &Value, timeout: Option<Duration>) -> Result<Value, TgError> {
        let agent = match timeout {
            Some(t) => ureq::Agent::config_builder().http_status_as_error(false).timeout_global(Some(t)).build().into(),
            None => self.agent.clone(),
        };
        let mut resp = agent.post(&self.url(method)).send_json(body).map_err(|e| TgError::Network(self.red(e.to_string())))?;
        let v: Value = resp.body_mut().read_json().map_err(|e| TgError::Parse(self.red(e.to_string())))?;
        if v["ok"].as_bool() == Some(true) {
            return Ok(v["result"].clone());
        }
        Err(TgError::Api {
            code: v["error_code"].as_u64().unwrap_or(resp.status().as_u16() as u64) as u16,
            description: self.red(v["description"].as_str().unwrap_or("unknown error")),
            retry_after: v["parameters"]["retry_after"].as_u64(),
        })
    }

    pub fn get_me(&self) -> Result<BotInfo, TgError> {
        serde_json::from_value(self.call("getMe", &json!({}), None)?).map_err(|e| TgError::Parse(self.red(e.to_string())))
    }

    /// Send HTML text. `text` must already be escaped (see `esc`). Returns the message id.
    pub fn send_message(&self, chat_id: i64, text: &str) -> Result<i64, TgError> {
        self.send_reply(chat_id, text, None)
    }

    /// Like `send_message`, optionally as a reply (so a group result sits under the file it describes).
    pub fn send_reply(&self, chat_id: i64, text: &str, reply_to: Option<i64>) -> Result<i64, TgError> {
        let text: String = text.chars().take(MAX_MESSAGE_CHARS).collect();
        let mut body = json!({ "chat_id": chat_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true });
        if let Some(m) = reply_to {
            body["reply_parameters"] = json!({ "message_id": m, "allow_sending_without_reply": true });
        }
        let r = self.call("sendMessage", &body, None)?;
        Ok(r["message_id"].as_i64().unwrap_or(0))
    }

    /// A message with inline buttons (rows of buttons).
    pub fn send_buttons(&self, chat_id: i64, text: &str, rows: &[Vec<Button>]) -> Result<i64, TgError> {
        let text: String = text.chars().take(MAX_MESSAGE_CHARS).collect();
        let kb: Vec<Vec<Value>> = rows.iter().map(|r| r.iter().map(Button::json).collect()).collect();
        let body = json!({ "chat_id": chat_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true, "reply_markup": { "inline_keyboard": kb } });
        let r = self.call("sendMessage", &body, None)?;
        Ok(r["message_id"].as_i64().unwrap_or(0))
    }

    /// Acknowledge a button tap (stops the spinner on the user's screen).
    pub fn answer_callback(&self, callback_id: &str, text: Option<&str>) -> Result<(), TgError> {
        let mut body = json!({ "callback_query_id": callback_id });
        if let Some(t) = text {
            body["text"] = json!(t.chars().take(180).collect::<String>());
        }
        self.call("answerCallbackQuery", &body, None).map(|_| ())
    }

    /// Ask Telegram for a user's standing in a chat. This is the only source of truth for "is this person an admin".
    pub fn get_chat_member(&self, chat_id: i64, user_id: i64) -> Result<Member, TgError> {
        let r = self.call("getChatMember", &json!({ "chat_id": chat_id, "user_id": user_id }), None)?;
        Ok(Member { status: r["status"].as_str().unwrap_or("").to_string(), can_delete_messages: r["can_delete_messages"].as_bool().unwrap_or(false) })
    }

    /// Delete a message. Telegram only allows it when the bot is an administrator with the delete right.
    pub fn delete_message(&self, chat_id: i64, message_id: i64) -> Result<(), TgError> {
        self.call("deleteMessage", &json!({ "chat_id": chat_id, "message_id": message_id }), None).map(|_| ())
    }

    pub fn leave_chat(&self, chat_id: i64) -> Result<(), TgError> {
        self.call("leaveChat", &json!({ "chat_id": chat_id }), None).map(|_| ())
    }

    /// Long-poll for updates. Pass `offset = last_update_id + 1` to acknowledge earlier ones.
    pub fn get_updates(&self, offset: Option<i64>, timeout_s: u64, limit: u32) -> Result<Vec<Incoming>, TgError> {
        let mut body = json!({ "timeout": timeout_s, "limit": limit, "allowed_updates": ["message", "my_chat_member", "callback_query"] });
        if let Some(o) = offset {
            body["offset"] = json!(o);
        }
        let r = self.call("getUpdates", &body, Some(Duration::from_secs(timeout_s + 15)))?;
        let arr = r.as_array().ok_or_else(|| TgError::Parse("getUpdates did not return a list".into()))?;
        Ok(arr.iter().filter_map(parse_update).collect())
    }

    pub fn get_file(&self, file_id: &str) -> Result<(String, Option<u64>), TgError> {
        let r = self.call("getFile", &json!({ "file_id": file_id }), None)?;
        let path = r["file_path"].as_str().ok_or_else(|| TgError::Parse("getFile returned no file_path".into()))?.to_string();
        Ok((path, r["file_size"].as_u64()))
    }

    /// Stream a file into `out`, refusing anything larger than `max_bytes` (checked against the advertised size first
    /// and again while reading, so a lying server cannot exhaust disk).
    pub fn download(&self, file_path: &str, out: &mut dyn Write, max_bytes: u64) -> Result<u64, TgError> {
        let url = format!("{}/file/bot{}/{}", self.base, self.token, file_path);
        let mut resp = self.agent.get(&url).call().map_err(|e| TgError::Network(self.red(e.to_string())))?;
        if resp.status().as_u16() != 200 {
            return Err(TgError::Api { code: resp.status().as_u16(), description: "download failed".into(), retry_after: None });
        }
        let mut reader = resp.body_mut().as_reader();
        let mut buf = [0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let n = reader.read(&mut buf).map_err(|e| TgError::Network(self.red(e.to_string())))?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > max_bytes {
                return Err(TgError::TooLarge(total));
            }
            out.write_all(&buf[..n]).map_err(|e| TgError::Network(e.to_string()))?;
        }
        Ok(total)
    }
}

fn parse_update(u: &Value) -> Option<Incoming> {
    let update_id = u["update_id"].as_i64()?;
    if let Some(c) = u.get("my_chat_member") {
        return Some(Incoming {
            update_id,
            chat_id: c["chat"]["id"].as_i64()?,
            chat_type: c["chat"]["type"].as_str().unwrap_or("").to_string(),
            chat_title: c["chat"]["title"].as_str().map(String::from),
            message_id: None,
            from_id: c["from"]["id"].as_i64(),
            anonymous_admin: false,
            member_change: Some(MemberChange { new_status: c["new_chat_member"]["status"].as_str().unwrap_or("").to_string(), old_status: c["old_chat_member"]["status"].as_str().unwrap_or("").to_string() }),
            from_name: None,
            callback: None,
            text: None,
            document: None,
            other_media: false,
        });
    }
    if let Some(c) = u.get("callback_query") {
        let m = &c["message"];
        return Some(Incoming {
            update_id,
            chat_id: m["chat"]["id"].as_i64()?,
            chat_type: m["chat"]["type"].as_str().unwrap_or("").to_string(),
            chat_title: m["chat"]["title"].as_str().map(String::from),
            message_id: m["message_id"].as_i64(),
            from_id: c["from"]["id"].as_i64(),
            anonymous_admin: false,
            member_change: None,
            from_name: c["from"]["first_name"].as_str().map(String::from),
            callback: Some(Callback { id: c["id"].as_str()?.to_string(), data: c["data"].as_str().unwrap_or("").chars().take(64).collect() }),
            text: None,
            document: None,
            other_media: false,
        });
    }
    let m = u.get("message")?;
    let doc = m
        .get("document")
        .map(|d| Document { file_id: d["file_id"].as_str().unwrap_or_default().to_string(), file_unique_id: d["file_unique_id"].as_str().map(String::from), file_name: d["file_name"].as_str().map(String::from), file_size: d["file_size"].as_u64() })
        .filter(|d| !d.file_id.is_empty());
    let chat_id = m["chat"]["id"].as_i64()?;
    Some(Incoming {
        update_id,
        chat_id,
        chat_type: m["chat"]["type"].as_str().unwrap_or("").to_string(),
        chat_title: m["chat"]["title"].as_str().map(String::from),
        message_id: m["message_id"].as_i64(),
        from_id: m["from"]["id"].as_i64(),
        anonymous_admin: m["sender_chat"]["id"].as_i64() == Some(chat_id),
        member_change: None,
        from_name: m["from"]["first_name"].as_str().map(String::from),
        callback: None,
        // A file's caption is its text; commands only ever come from `text`.
        text: m["text"].as_str().map(String::from),
        other_media: doc.is_none() && ["photo", "video", "audio", "voice", "video_note", "animation", "sticker"].iter().any(|k| m.get(*k).is_some()),
        document: doc,
    })
}

// ---- token storage -------------------------------------------------------------------------------------------

/// The bot token is a credential: it is stored only protected by the OS (DPAPI on Windows, bound to the Windows user),
/// never in settings, logs, the console or any plaintext file, and it is wiped on disconnect.
pub struct TokenVault {
    file: std::path::PathBuf,
}

impl TokenVault {
    pub fn new(dir: &std::path::Path) -> Self {
        TokenVault { file: dir.join("telegram-bot.token") }
    }

    pub fn exists(&self) -> bool {
        self.file.is_file()
    }

    pub fn save(&self, token: &str) -> Result<(), String> {
        if !valid_token_shape(token) {
            return Err(TgError::InvalidToken.user_message());
        }
        let sealed = crate::secret::protect(token.as_bytes()).map_err(|e| e.to_string())?;
        let tmp = self.file.with_extension("tmp");
        std::fs::write(&tmp, sealed).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &self.file).map_err(|e| e.to_string())
    }

    pub fn load(&self) -> Option<String> {
        let t = String::from_utf8(crate::secret::unprotect(&std::fs::read(&self.file).ok()?).ok()?).ok()?;
        valid_token_shape(&t).then_some(t)
    }

    /// Overwrite then delete. Returns true when nothing remains on disk.
    pub fn wipe(&self) -> bool {
        if let Ok(m) = std::fs::metadata(&self.file) {
            let _ = std::fs::write(&self.file, vec![0u8; m.len() as usize]);
        }
        let _ = std::fs::remove_file(&self.file);
        !self.file.exists()
    }
}

// ---- text safety ---------------------------------------------------------------------------------------------

/// Characters that let a name lie about itself: ASCII control codes and Unicode bidirectional overrides/isolates
/// (e.g. U+202E "right-to-left override" makes `exe.txt` display as `txt.exe`), plus zero-width characters.
pub(crate) fn is_deceptive(c: char) -> bool {
    c.is_control() || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200B}'..='\u{200F}' | '\u{FEFF}' | '\u{061C}')
}

/// Make an untrusted file name safe to show: strip deceptive characters, cap the length, HTML-escape for Telegram.
pub fn safe_display_name(name: &str) -> String {
    let cleaned: String = name.chars().filter(|c| !is_deceptive(*c)).take(120).collect();
    esc(if cleaned.trim().is_empty() { "(unnamed file)" } else { cleaned.trim() })
}

/// HTML-escape for `parse_mode=HTML`.
pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "123456789:AAHkq3Zr0pXxJ2mN8sVbT5wYcLdEfGh1Ijk";

    #[test]
    fn token_shape() {
        assert!(valid_token_shape(TOKEN));
        for bad in ["", "abc", "123:short", "notnumeric:AAHkq3Zr0pXxJ2mN8sVbT5wYcLdEfGh1Ijk", "123456789:AAHkq3Zr0pXxJ2mN8sVb T5wYcLdEfGh1Ijk", "123456789AAHkq3Zr0pXxJ2mN8sVbT5wYcLdEfGh1Ijk", &format!("{TOKEN}\n")] {
            assert!(!valid_token_shape(bad), "{bad:?}");
        }
    }

    #[test]
    fn redaction_removes_the_token_everywhere() {
        let msg = format!("error sending request for url (https://api.telegram.org/bot{TOKEN}/sendMessage): timed out; token={TOKEN}");
        let r = redact(&msg, TOKEN);
        assert!(!r.contains("AAHkq3Zr"), "{r}");
        assert!(!r.contains(TOKEN));
        // A different (e.g. previous) token shaped like a bot URL is also scrubbed.
        let other = redact("GET /bot987654321:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ/getMe failed", TOKEN);
        assert!(!other.contains("ZZZZZZZZ") && other.contains("bot<redacted>"), "{other}");
        assert_eq!(redact("nothing sensitive here", TOKEN), "nothing sensitive here");
    }

    #[test]
    fn redaction_preserves_non_ascii_text() {
        let msg = "отчёт 報告 ✓ /bot987654321:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ/x ünïcode";
        assert_eq!(redact(msg, TOKEN), "отчёт 報告 ✓ /bot<redacted>/x ünïcode");
    }

    #[test]
    fn endpoints_must_be_https_or_loopback() {
        assert!(validate_base("https://api.telegram.org").is_ok());
        assert!(validate_base("http://127.0.0.1:8080").is_ok());
        for bad in ["http://api.telegram.org", "ftp://x", "https://", "https://user@evil.example", "http://127.0.0.1.evil.example", "http://localhost.evil.example"] {
            assert!(validate_base(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn client_refuses_bad_tokens_and_endpoints() {
        assert_eq!(BotClient::new("nope").err(), Some(TgError::InvalidToken));
        assert!(BotClient::with_base(TOKEN, "http://evil.example").is_err());
    }

    #[test]
    fn retry_classification() {
        assert!(TgError::Network("x".into()).is_retryable());
        assert!(TgError::Api { code: 429, description: "x".into(), retry_after: Some(7) }.is_retryable());
        assert!(TgError::Api { code: 502, description: "x".into(), retry_after: None }.is_retryable());
        for code in [400, 401, 403, 404] {
            assert!(!TgError::Api { code, description: "x".into(), retry_after: None }.is_retryable(), "{code}");
        }
        assert_eq!(TgError::Api { code: 429, description: "x".into(), retry_after: Some(7) }.retry_after_ms(), Some(8000));
    }

    #[test]
    fn display_names_cannot_spoof_or_inject() {
        let rtl = "invoice\u{202E}fdp.exe";
        let s = safe_display_name(rtl);
        assert!(!s.contains('\u{202E}'), "bidi override must be stripped");
        assert_eq!(safe_display_name("<b>x</b> & y"), "&lt;b&gt;x&lt;/b&gt; &amp; y");
        assert_eq!(safe_display_name("a\u{0007}b\nc"), "abc");
        assert_eq!(safe_display_name("\u{200B}\u{202E}"), "(unnamed file)");
        assert!(safe_display_name(&"x".repeat(1000)).len() <= 120);
    }

    #[test]
    fn the_token_is_never_stored_in_clear_and_is_wiped_on_disconnect() {
        let d = tempfile::tempdir().unwrap();
        let v = TokenVault::new(d.path());
        assert!(!v.exists() && v.load().is_none());
        assert!(v.save("not a token").is_err(), "garbage is refused before it is stored");
        v.save(TOKEN).unwrap();
        let raw = std::fs::read(d.path().join("telegram-bot.token")).unwrap();
        if cfg!(windows) {
            assert!(!raw.windows(20).any(|w| TOKEN.as_bytes().windows(20).any(|t| t == w)), "no 20-byte slice of the token may appear in the file");
        }
        assert_eq!(v.load().as_deref(), Some(TOKEN));
        assert!(v.wipe());
        assert!(!v.exists() && v.load().is_none());
    }

    #[test]
    fn parses_updates() {
        let doc = json!({"update_id": 7, "message": {"chat": {"id": 42, "type": "private"}, "from": {"id": 42}, "document": {"file_id": "F1", "file_name": "a.exe", "file_size": 10}}});
        let i = parse_update(&doc).unwrap();
        assert_eq!((i.update_id, i.chat_id, i.from_id), (7, 42, Some(42)));
        assert_eq!(i.document.unwrap().file_name.as_deref(), Some("a.exe"));
        let photo = json!({"update_id": 8, "message": {"chat": {"id": 42, "type": "private"}, "from": {"id": 42}, "photo": [{}]}});
        assert!(parse_update(&photo).unwrap().other_media);
        assert!(parse_update(&json!({"update_id": 9, "edited_message": {}})).is_none());
    }
}

//! Personal Telegram account protection on top of TDLib.
//!
//! One worker thread owns the TDLib client and reacts to its updates; one scan thread does the slow work. Login is only
//! ever QR-based: the user approves the session on their phone inside Telegram. SENTRIX has no field for a phone number,
//! login code or password and never sends one. A cloud-password (two-step) account is reported as unsupported and signed
//! out again; it is never asked for its password.
//!
//! What reaches us is limited to what the signed-in client is actually given by Telegram. Secret chats are not enabled.
//! Content a chat marks as protected is not downloaded. Files are visible to the client only as metadata (name, size)
//! before they are downloaded, so there is NO pre-download scanning: the first possible content check is after the
//! download finishes. That download is a separate copy kept in an isolated folder that is emptied after each scan.
//!
//! The TDLib database is encrypted with a random key that exists only DPAPI-protected on this PC (`SessionVault`).

use crate::account::{unverified_report, AccountPrefs, AttachmentGate, ChatKind, IncomingAttachment, IngestError, SessionVault};
use crate::queue::{now_ms, JobStore};
use crate::service::ProtectionService;
use crate::tdjson::TdIo;
use crate::types::{ScanReport, Verdict};
use base64::Engine as _;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

pub const MAX_IN_FLIGHT_DOWNLOADS: usize = 16;
const SCAN_QUEUE: usize = 32;
/// A download that has not completed after this long is abandoned and reported, never scanned half-finished.
const DOWNLOAD_STALL: Duration = Duration::from_secs(10 * 60);
const SEEN_KEY: &str = "tg_acct_seen";
const COUNTS_KEY: &str = "tg_acct_counts";
const SEEN_MAX: usize = 4000;

// ---- what the UI sees ------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "state", content = "detail")]
pub enum LinkState {
    /// Cannot start in this build/environment; `detail` says exactly why.
    Unconfigured(String),
    Disconnected,
    Starting,
    /// A QR code is on screen waiting for the user to approve it in Telegram on their phone.
    WaitingForScan,
    /// The account has a cloud password. SENTRIX refuses to handle it and has signed the attempt out again.
    TwoStepUnsupported,
    Connected,
    /// Telegram ended the session (revoked from another device, or invalidated). Reconnecting needs a new QR scan.
    Expired,
    Failed(String),
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub scanned: u64,
    pub threats: u64,
    pub suspicious: u64,
    /// Could not be fully checked: too large, protected, download failed, scanner problem.
    pub inaccessible: u64,
    /// Deliberately not looked at (category switched off, already checked, outgoing).
    pub skipped: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Recent {
    pub at: i64,
    pub name: String,
    pub kind: &'static str,
    pub verdict: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountView {
    #[serde(flatten)]
    pub link: LinkState,
    /// SVG of the login QR code while `WaitingForScan`; never persisted or logged.
    pub qr_svg: Option<String>,
    /// The login link itself (a short-lived secret): kept in memory for terminal rendering in tests, never serialized.
    #[serde(skip)]
    pub login_link: Option<String>,
    /// First name of the connected account only: no phone number, username or id is kept.
    pub display: Option<String>,
    /// "ready" | "connecting" | "waiting_for_network" | "updating" | "unknown"
    pub connection: String,
    pub last_sync_at: Option<i64>,
    pub last_scan_at: Option<i64>,
    pub pending: usize,
    pub counts: Counts,
    pub recent: Vec<Recent>,
}

impl AccountView {
    pub fn new(link: LinkState) -> Self {
        AccountView { link, qr_svg: None, login_link: None, display: None, connection: "unknown".into(), last_sync_at: None, last_scan_at: None, pending: 0, counts: Counts::default(), recent: vec![] }
    }
}

// ---- scanning seam ---------------------------------------------------------------------------------------------

pub trait AttachmentScanner: Send + Sync {
    fn scan(&self, kind: ChatKind, name: &str, size: u64, content: &mut dyn Read) -> Result<ScanReport, IngestError>;
    fn publish(&self, r: &ScanReport);
    /// Raise an account notice (e.g. "authorization expired") through the user's own bot, if they want those.
    fn notice(&self, kind: &'static str, detail: &str);
}

/// The real implementation: the same engine, history and notification pipeline as every other source.
pub struct ServiceScanner {
    pub svc: Arc<ProtectionService>,
    pub gate: Arc<AttachmentGate>,
}

impl AttachmentScanner for ServiceScanner {
    fn scan(&self, kind: ChatKind, name: &str, size: u64, content: &mut dyn Read) -> Result<ScanReport, IngestError> {
        self.gate.ingest(&self.svc, &IncomingAttachment { chat_kind: kind, display_name: name.to_string(), size }, content)
    }
    fn publish(&self, r: &ScanReport) {
        self.svc.publish_report(r);
    }
    fn notice(&self, kind: &'static str, detail: &str) {
        self.svc.notify_system(kind, detail);
    }
}

// ---- configuration ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Credentials {
    pub api_id: i32,
    pub api_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountOptions {
    /// The user's own switch: monitoring can be paused without disconnecting or touching the bot.
    pub enabled: bool,
    pub prefs: AccountPrefs,
    /// Also look at photos, videos, audio and voice messages. Off by default: documents (where executables, scripts and
    /// archives arrive) are the risky category and media would multiply the download volume.
    pub media: bool,
}

impl Default for AccountOptions {
    fn default() -> Self {
        AccountOptions { enabled: true, prefs: AccountPrefs::default(), media: false }
    }
}

/// How the engine ended; decides what is wiped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exit {
    /// The app is closing: keep the session so protection resumes next start.
    Stop,
    /// The user asked to disconnect: sign out at Telegram, then erase everything local.
    Disconnect,
    /// Telegram ended the session.
    Revoked,
    /// Unsupported account type (cloud password). Signed out; local data erased.
    Unsupported,
    /// Telegram refused the sign-in attempt itself (bad API credentials, blocked network). Nothing was signed in.
    Failed,
}

const CTL_NONE: u8 = 0;
const CTL_STOP: u8 = 1;
const CTL_DISCONNECT: u8 = 2;

// ---- the engine ------------------------------------------------------------------------------------------------

struct Parked {
    msg: Value,
}

struct Pending {
    name: String,
    kind: ChatKind,
    size: u64,
    unique_id: String,
    message_key: String,
    started: Instant,
}

struct Job {
    file_id: i64,
    path: PathBuf,
    name: String,
    kind: ChatKind,
    size: u64,
    unique_id: String,
    message_key: String,
}

pub struct Shared {
    pub view: Mutex<AccountView>,
    pub store: Arc<JobStore>,
    pub scanner: Arc<dyn AttachmentScanner>,
    pub on_change: Box<dyn Fn() + Send + Sync>,
    pub options: RwLock<AccountOptions>,
    /// Downloads in progress and files waiting for / inside the scanner. Together they are the "pending" count.
    downloading: AtomicUsize,
    queued: AtomicUsize,
    seen: Mutex<(HashSet<String>, VecDeque<String>)>,
}

impl Shared {
    pub fn new(store: Arc<JobStore>, scanner: Arc<dyn AttachmentScanner>, on_change: Box<dyn Fn() + Send + Sync>, options: AccountOptions, initial: LinkState) -> Arc<Self> {
        let mut v = AccountView::new(initial);
        if let Some(c) = store.kv_get(COUNTS_KEY).and_then(|s| serde_json::from_str::<[u64; 5]>(&s).ok()) {
            v.counts = Counts { scanned: c[0], threats: c[1], suspicious: c[2], inaccessible: c[3], skipped: c[4] };
        }
        let mut order: VecDeque<String> = store.kv_get(SEEN_KEY).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        while order.len() > SEEN_MAX {
            order.pop_front();
        }
        let set = order.iter().cloned().collect();
        Arc::new(Shared { view: Mutex::new(v), store, scanner, on_change, options: RwLock::new(options), downloading: AtomicUsize::new(0), queued: AtomicUsize::new(0), seen: Mutex::new((set, order)) })
    }

    pub fn snapshot(&self) -> AccountView {
        self.view.lock().unwrap().clone()
    }

    fn update(&self, f: impl FnOnce(&mut AccountView)) {
        f(&mut self.view.lock().unwrap());
        (self.on_change)();
    }

    fn set_downloading(&self, n: usize) {
        self.downloading.store(n, Ordering::SeqCst);
        self.update(|v| v.pending = self.downloading.load(Ordering::SeqCst) + self.queued.load(Ordering::SeqCst));
    }

    fn queued_delta(&self, up: bool) {
        if up {
            self.queued.fetch_add(1, Ordering::SeqCst);
        } else {
            let mut cur = self.queued.load(Ordering::SeqCst);
            while cur > 0 {
                match self.queued.compare_exchange(cur, cur - 1, Ordering::SeqCst, Ordering::SeqCst) {
                    Ok(_) => break,
                    Err(now) => cur = now,
                }
            }
        }
        self.update(|v| v.pending = self.downloading.load(Ordering::SeqCst) + self.queued.load(Ordering::SeqCst));
    }

    fn save_counts(&self) {
        let c = self.view.lock().unwrap().counts.clone();
        self.store.kv_set(COUNTS_KEY, &serde_json::to_string(&[c.scanned, c.threats, c.suspicious, c.inaccessible, c.skipped]).unwrap_or_default());
    }

    fn was_seen(&self, key: &str) -> bool {
        self.seen.lock().unwrap().0.contains(key)
    }

    fn mark_seen(&self, key: &str) {
        let mut g = self.seen.lock().unwrap();
        if g.0.insert(key.to_string()) {
            g.1.push_back(key.to_string());
            while g.1.len() > SEEN_MAX {
                if let Some(old) = g.1.pop_front() {
                    g.0.remove(&old);
                }
            }
            self.store.kv_set(SEEN_KEY, &serde_json::to_string(&g.1).unwrap_or_default());
        }
    }

    fn forget_seen(&self) {
        let mut g = self.seen.lock().unwrap();
        g.0.clear();
        g.1.clear();
        self.store.kv_delete(SEEN_KEY);
    }

    fn push_recent(&self, r: Recent) {
        self.update(|v| {
            v.recent.insert(0, r);
            v.recent.truncate(20);
        });
    }

    /// A file we will not or cannot check: counted, recorded and (through the normal report path) shown as UNABLE TO VERIFY.
    fn unverified(&self, kind: ChatKind, name: &str, size: u64, reason: &str) {
        let origin = crate::account::origin_for(kind);
        let r = unverified_report(origin, name, size, reason);
        self.scanner.publish(&r);
        self.update(|v| v.counts.inaccessible += 1);
        self.save_counts();
        self.push_recent(Recent { at: now_ms(), name: r.file.name.clone(), kind: kind_label(kind), verdict: Verdict::UnableToVerify.label().into(), note: reason.into() });
        self.store.add_event("telegram_account_unverified", "warning", &format!("A Telegram attachment could not be checked: {reason}"), now_ms());
    }

    /// Deliberately ignored; counted so the numbers add up, not reported as a result.
    fn skipped(&self, why: &str) {
        self.update(|v| v.counts.skipped += 1);
        self.save_counts();
        self.store.add_event("telegram_account_skipped", "info", why, now_ms());
    }
}

fn kind_label(k: ChatKind) -> &'static str {
    match k {
        ChatKind::Private => "private",
        ChatKind::Group => "group",
        ChatKind::Channel => "channel",
    }
}

pub struct Engine {
    io: Arc<dyn TdIo>,
    shared: Arc<Shared>,
    creds: Credentials,
    dir: PathBuf,
    key: Vec<u8>,
    resume: bool,
    jobs: SyncSender<Job>,
    chats: HashMap<i64, (Option<ChatKind>, bool)>,
    parked: HashMap<i64, Vec<Parked>>,
    pending: HashMap<i64, Pending>,
    exit: Option<Exit>,
    closed: bool,
}

impl Engine {
    fn new(io: Arc<dyn TdIo>, shared: Arc<Shared>, creds: Credentials, dir: PathBuf, key: Vec<u8>, resume: bool, jobs: SyncSender<Job>) -> Self {
        Engine { io, shared, creds, dir, key, resume, jobs, chats: HashMap::new(), parked: HashMap::new(), pending: HashMap::new(), exit: None, closed: false }
    }

    fn send(&self, v: Value) {
        self.io.send(&v.to_string());
    }

    pub fn handle_str(&mut self, s: &str) {
        if let Ok(v) = serde_json::from_str::<Value>(s) {
            self.handle(&v);
        }
    }

    pub fn handle(&mut self, v: &Value) {
        match v["@type"].as_str().unwrap_or("") {
            "updateAuthorizationState" => self.on_auth(&v["authorization_state"]),
            "updateConnectionState" => self.on_connection(&v["state"]),
            "updateNewChat" => self.on_chat(&v["chat"]),
            "chat" => self.on_chat(v),
            "updateNewMessage" => self.on_message(&v["message"]),
            "updateFile" => self.on_file(&v["file"]),
            // The reply to downloadFile is the file itself. A file that is already complete locally gets no later updateFile.
            "file" if v["@extra"].as_str().map(|x| x.starts_with("dl:")).unwrap_or(false) => self.on_file(v),
            "user" if v["@extra"] == "me" => {
                let first: String = v["first_name"].as_str().unwrap_or("").chars().filter(|c| !c.is_control()).take(40).collect();
                self.shared.update(|s| s.display = Some(if first.is_empty() { "Your account".into() } else { first }));
            }
            "error" => self.on_error(v),
            _ => {}
        }
    }

    // ---- sign-in -----------------------------------------------------------------------------------------------

    fn on_auth(&mut self, st: &Value) {
        match st["@type"].as_str().unwrap_or("") {
            "authorizationStateWaitTdlibParameters" => {
                let key = base64::engine::general_purpose::STANDARD.encode(&self.key);
                self.send(json!({
                    "@type": "setTdlibParameters",
                    "use_test_dc": false,
                    "database_directory": self.dir.join("db").to_string_lossy(),
                    "files_directory": self.dir.join("files").to_string_lossy(),
                    "database_encryption_key": key,
                    // Minimum retention: no message history and no chat-info cache on disk, no secret chats.
                    "use_file_database": false,
                    "use_chat_info_database": false,
                    "use_message_database": false,
                    "use_secret_chats": false,
                    "api_id": self.creds.api_id,
                    "api_hash": self.creds.api_hash,
                    "system_language_code": "en",
                    "device_model": "SENTRIX Desktop",
                    "application_version": env!("CARGO_PKG_VERSION"),
                    "@extra": "auth",
                }));
            }
            "authorizationStateWaitPhoneNumber" => {
                if self.resume {
                    // We expected to be signed in already. Asking for a QR here would silently start a new login the
                    // user did not request, so treat it as an ended session and let them reconnect on purpose.
                    self.end(Exit::Revoked);
                } else {
                    self.send(json!({"@type": "requestQrCodeAuthentication", "other_user_ids": [], "@extra": "auth"}));
                }
            }
            "authorizationStateWaitOtherDeviceConfirmation" => {
                let link = st["link"].as_str().unwrap_or("").to_string();
                let svg = qr_svg(&link);
                self.shared.update(|v| {
                    v.link = LinkState::WaitingForScan;
                    v.qr_svg = svg;
                    v.login_link = Some(link.clone());
                });
            }
            "authorizationStateWaitPassword" => {
                // The QR was approved but this account has a cloud password. We never ask for it.
                self.end(Exit::Unsupported);
            }
            "authorizationStateWaitCode" | "authorizationStateWaitEmailAddress" | "authorizationStateWaitEmailCode" | "authorizationStateWaitRegistration" | "authorizationStateWaitPremiumPurchase" => {
                self.shared.update(|v| {
                    v.link = LinkState::Failed("Telegram asked for a sign-in step SENTRIX does not support. Nothing was entered or stored.".into());
                    v.qr_svg = None;
                    v.login_link = None;
                });
                self.end(Exit::Unsupported);
            }
            "authorizationStateReady" => {
                self.resume = true;
                self.shared.update(|v| {
                    v.link = LinkState::Connected;
                    v.qr_svg = None;
                    v.login_link = None;
                });
                self.send(json!({"@type": "getMe", "@extra": "me"}));
            }
            "authorizationStateLoggingOut" | "authorizationStateClosing" => {}
            "authorizationStateClosed" => {
                self.closed = true;
                if self.exit.is_none() {
                    // We did not ask for this: Telegram ended the session.
                    self.exit = Some(Exit::Revoked);
                }
            }
            _ => {}
        }
    }

    fn end(&mut self, why: Exit) {
        if self.exit.is_some() && why == Exit::Stop {
            return;
        }
        self.exit = Some(why);
        match why {
            Exit::Stop | Exit::Revoked | Exit::Failed => self.send(json!({"@type": "close"})),
            Exit::Disconnect | Exit::Unsupported => self.send(json!({"@type": "logOut"})),
        }
        if why == Exit::Unsupported {
            let msg = LinkState::TwoStepUnsupported;
            self.shared.update(|v| {
                if !matches!(v.link, LinkState::Failed(_)) {
                    v.link = msg;
                }
                v.qr_svg = None;
                v.login_link = None;
            });
        }
    }

    fn on_connection(&mut self, st: &Value) {
        let c = match st["@type"].as_str().unwrap_or("") {
            "connectionStateReady" => "ready",
            "connectionStateConnecting" | "connectionStateConnectingToProxy" => "connecting",
            "connectionStateWaitingForNetwork" => "waiting_for_network",
            "connectionStateUpdating" => "updating",
            _ => "unknown",
        };
        self.shared.update(|v| {
            v.connection = c.into();
            if c == "ready" {
                v.last_sync_at = Some(now_ms());
            }
        });
    }

    // ---- incoming attachments -----------------------------------------------------------------------------------

    fn on_chat(&mut self, chat: &Value) {
        let Some(id) = chat["id"].as_i64() else { return };
        let kind = match chat["type"]["@type"].as_str().unwrap_or("") {
            "chatTypePrivate" => Some(ChatKind::Private),
            "chatTypeBasicGroup" => Some(ChatKind::Group),
            "chatTypeSupergroup" => Some(if chat["type"]["is_channel"].as_bool().unwrap_or(false) { ChatKind::Channel } else { ChatKind::Group }),
            _ => None, // secret chats or anything unknown: not supported
        };
        self.chats.insert(id, (kind, chat["has_protected_content"].as_bool().unwrap_or(false)));
        if let Some(waiting) = self.parked.remove(&id) {
            for p in waiting {
                self.on_message(&p.msg);
            }
        }
    }

    fn on_message(&mut self, m: &Value) {
        if m["is_outgoing"].as_bool().unwrap_or(false) {
            return;
        }
        let (Some(chat_id), Some(msg_id)) = (m["chat_id"].as_i64(), m["id"].as_i64()) else { return };
        let opts = *self.shared.options.read().unwrap();
        let Some((file, name, is_media)) = extract(&m["content"]) else { return };
        if !opts.enabled {
            self.shared.skipped("A file was not looked at because Telegram account monitoring is switched off.");
            return;
        }
        if is_media && !opts.media {
            return;
        }
        // Redelivery (reconnect, restart): one message is handled once.
        let message_key = format!("m:{chat_id}:{msg_id}");
        if self.shared.was_seen(&message_key) || self.pending.values().any(|p| p.message_key == message_key) {
            return;
        }
        let Some(&(kind, protected)) = self.chats.get(&chat_id) else {
            self.parked.entry(chat_id).or_default().push(Parked { msg: m.clone() });
            self.send(json!({"@type": "getChat", "chat_id": chat_id}));
            return;
        };
        let Some(kind) = kind else {
            self.shared.skipped("A message in a chat type SENTRIX does not support (for example a secret chat) was not looked at.");
            return;
        };
        let allowed = match kind {
            ChatKind::Private => opts.prefs.private_chats,
            ChatKind::Group => opts.prefs.groups,
            ChatKind::Channel => opts.prefs.channels,
        };
        if !allowed {
            self.shared.skipped(&format!("A file in a {} was not looked at because that chat type is switched off.", kind_label(kind)));
            return;
        }
        let size = file["expected_size"].as_u64().filter(|s| *s > 0).or_else(|| file["size"].as_u64()).unwrap_or(0);
        let unique_id = file["remote"]["unique_id"].as_str().unwrap_or("").to_string();
        let Some(file_id) = file["id"].as_i64() else { return };
        // Same file content already checked (forwarded, re-posted): checked once.
        if !unique_id.is_empty() && self.shared.was_seen(&format!("f:{unique_id}")) {
            self.shared.mark_seen(&message_key);
            self.shared.skipped("A file that SENTRIX already checked was posted again.");
            return;
        }
        if protected || m["can_be_saved"].as_bool() == Some(false) {
            self.shared.mark_seen(&message_key);
            self.shared.unverified(kind, &name, size, "Telegram marks this content as protected. SENTRIX does not work around that, so it was not downloaded or checked.");
            return;
        }
        if size > opts.prefs.max_bytes {
            self.shared.mark_seen(&message_key);
            self.shared.unverified(kind, &name, size, &format!("The file is {} MB, above the {} MB limit, so it was not downloaded or checked.", size / 1_000_000, opts.prefs.max_bytes / 1_000_000));
            return;
        }
        if self.pending.len() >= MAX_IN_FLIGHT_DOWNLOADS {
            self.shared.unverified(kind, &name, size, "SENTRIX was busy with other files and did not download this one.");
            return;
        }
        self.pending.insert(file_id, Pending { name, kind, size, unique_id, message_key, started: Instant::now() });
        self.shared.set_downloading(self.pending.len());
        self.send(json!({"@type": "downloadFile", "file_id": file_id, "priority": 8, "offset": 0, "limit": 0, "synchronous": false, "@extra": format!("dl:{file_id}")}));
        // The file may already be complete locally (TDLib returns it immediately as an updateFile).
    }

    fn on_file(&mut self, f: &Value) {
        let Some(id) = f["id"].as_i64() else { return };
        if !self.pending.contains_key(&id) {
            return;
        }
        let local = &f["local"];
        if local["is_downloading_completed"].as_bool() != Some(true) {
            return; // partial: never scanned until complete
        }
        let Some(p) = self.pending.remove(&id) else { return };
        let path = PathBuf::from(local["path"].as_str().unwrap_or(""));
        let on_disk = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        // Completeness check against what Telegram declared: a short file is a failed transfer, not a small file.
        if p.size > 0 && on_disk != p.size {
            self.release(id, &path);
            self.shared.set_downloading(self.pending.len());
            self.shared.unverified(p.kind, &p.name, p.size, "The download did not finish completely, so the file could not be checked.");
            return;
        }
        let job = Job { file_id: id, path: path.clone(), name: p.name.clone(), kind: p.kind, size: p.size, unique_id: p.unique_id.clone(), message_key: p.message_key.clone() };
        self.shared.queued_delta(true);
        self.shared.set_downloading(self.pending.len());
        match self.jobs.try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.shared.queued_delta(false);
                self.release(id, &path);
                self.shared.unverified(p.kind, &p.name, p.size, "SENTRIX was busy checking other files and did not check this one.");
            }
        }
    }

    fn on_error(&mut self, v: &Value) {
        let extra = v["@extra"].as_str().unwrap_or("");
        if extra == "auth" {
            // Telegram refused a sign-in step (invalid API credentials, network blocked). Say so; never loop silently.
            let msg: String = v["message"].as_str().unwrap_or("request refused").chars().filter(|c| !c.is_control()).take(120).collect();
            self.shared.update(|s| {
                s.link = LinkState::Failed(format!("Telegram refused the sign-in: {msg}"));
                s.qr_svg = None;
                s.login_link = None;
            });
            self.end(Exit::Failed);
            return;
        }
        if let Some(id) = extra.strip_prefix("dl:").and_then(|s| s.parse::<i64>().ok()) {
            if let Some(p) = self.pending.remove(&id) {
                self.release(id, Path::new(""));
                self.shared.set_downloading(self.pending.len());
                // Message text is Telegram's; it is shown to the user but not stored beyond the event log.
                let msg: String = v["message"].as_str().unwrap_or("download failed").chars().filter(|c| !c.is_control()).take(120).collect();
                self.shared.unverified(p.kind, &p.name, p.size, &format!("Telegram would not provide this file ({msg}). It may have expired or be restricted."));
            }
        }
        if extra.is_empty() && v["code"].as_i64() == Some(401) {
            // Unauthorized: the session is no longer valid.
            self.end(Exit::Revoked);
        }
    }

    /// Ask TDLib to forget a downloaded file and remove our copy.
    fn release(&self, file_id: i64, path: &Path) {
        self.send(json!({"@type": "cancelDownloadFile", "file_id": file_id, "only_if_pending": false}));
        self.send(json!({"@type": "deleteFile", "file_id": file_id}));
        remove_inside(&self.dir.join("files"), path);
    }

    /// Housekeeping when nothing arrived for a moment.
    fn tick(&mut self) {
        let stalled: Vec<i64> = self.pending.iter().filter(|(_, p)| p.started.elapsed() > DOWNLOAD_STALL).map(|(id, _)| *id).collect();
        for id in stalled {
            if let Some(p) = self.pending.remove(&id) {
                self.release(id, Path::new(""));
                self.shared.set_downloading(self.pending.len());
                self.shared.unverified(p.kind, &p.name, p.size, "The download stalled and never completed, so the file could not be checked.");
            }
        }
    }
}

/// Pick the downloadable file and a display name out of a message. `bool` = is a media (non-document) type.
fn extract(content: &Value) -> Option<(Value, String, bool)> {
    let name_of = |v: &Value, fallback: &str| -> String { v.as_str().filter(|s| !s.is_empty()).unwrap_or(fallback).to_string() };
    let found = match content["@type"].as_str()? {
        "messageDocument" => Some((content["document"]["document"].clone(), name_of(&content["document"]["file_name"], "document"), false)),
        "messageVideo" => Some((content["video"]["video"].clone(), name_of(&content["video"]["file_name"], "video"), true)),
        "messageAudio" => Some((content["audio"]["audio"].clone(), name_of(&content["audio"]["file_name"], "audio"), true)),
        "messageAnimation" => Some((content["animation"]["animation"].clone(), name_of(&content["animation"]["file_name"], "animation"), true)),
        "messageVoiceNote" => Some((content["voice_note"]["voice"].clone(), "voice-message".into(), true)),
        "messageVideoNote" => Some((content["video_note"]["video"].clone(), "video-message".into(), true)),
        "messagePhoto" => {
            let sizes = content["photo"]["sizes"].as_array()?;
            Some((sizes.last()?["photo"].clone(), "photo.jpg".into(), true))
        }
        _ => None,
    };
    found.filter(|(f, _, _)| f["id"].is_i64())
}

/// Remove `path` only if it lies inside `root` (TDLib reports absolute paths; never delete outside our folder).
fn remove_inside(root: &Path, path: &Path) {
    if path.as_os_str().is_empty() {
        return;
    }
    if let (Ok(r), Ok(p)) = (root.canonicalize(), path.canonicalize()) {
        if p.starts_with(&r) && p != r {
            let _ = std::fs::remove_file(&p);
        }
    }
}

/// Login QR as a self-contained SVG: dark modules on white with the quiet zone the format requires.
pub fn qr_svg(link: &str) -> Option<String> {
    use qrcode::{Color, EcLevel, QrCode};
    if !link.starts_with("tg://login?token=") {
        return None;
    }
    let code = QrCode::with_error_correction_level(link.as_bytes(), EcLevel::M).ok()?;
    let w = code.width();
    let q = 4;
    let size = w + 2 * q;
    let mut d = String::new();
    for (i, c) in code.to_colors().iter().enumerate() {
        if *c == Color::Dark {
            d.push_str(&format!("M{},{}h1v1h-1z", (i % w) + q, (i / w) + q));
        }
    }
    Some(format!(r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" shape-rendering="crispEdges" role="img" aria-label="Telegram login QR code"><rect width="{size}" height="{size}" fill="#fff"/><path d="{d}" fill="#000"/></svg>"##))
}

// ---- scan thread -----------------------------------------------------------------------------------------------

fn scan_loop(rx: Receiver<Job>, shared: Arc<Shared>, io: Arc<dyn TdIo>, files_dir: PathBuf) {
    while let Ok(job) = rx.recv() {
        let result = match std::fs::File::open(&job.path) {
            Ok(mut f) => shared.scanner.scan(job.kind, &job.name, job.size.max(f.metadata().map(|m| m.len()).unwrap_or(0)), &mut f),
            Err(e) => Err(IngestError::Scan(format!("the downloaded file could not be opened: {e}"))),
        };
        // The untrusted copy goes away whatever happened.
        io.send(&json!({"@type": "deleteFile", "file_id": job.file_id}).to_string());
        remove_inside(&files_dir, &job.path);
        match result {
            Ok(r) => {
                let complete_clean_or_final = r.complete || r.verdict != Verdict::UnableToVerify;
                if complete_clean_or_final {
                    if !job.unique_id.is_empty() {
                        shared.mark_seen(&format!("f:{}", job.unique_id));
                    }
                    shared.mark_seen(&job.message_key);
                }
                shared.update(|v| {
                    v.counts.scanned += 1;
                    match r.verdict {
                        Verdict::Malicious => v.counts.threats += 1,
                        Verdict::Suspicious => v.counts.suspicious += 1,
                        Verdict::UnableToVerify | Verdict::Pending => v.counts.inaccessible += 1,
                        Verdict::Clean => {}
                    }
                    v.last_scan_at = Some(now_ms());
                });
                shared.queued_delta(false);
                shared.save_counts();
                shared.push_recent(Recent { at: now_ms(), name: r.file.name.clone(), kind: kind_label(job.kind), verdict: r.verdict.label().into(), note: r.summary.chars().take(160).collect() });
                // `scan` already published the report (history, desktop notice, bot message per the user's preferences).
            }
            Err(e) => {
                shared.queued_delta(false);
                let why = match e {
                    IngestError::CategoryDisabled => "that chat type was switched off while the file was downloading".to_string(),
                    IngestError::TooLarge => "the file is larger than the allowed limit".to_string(),
                    IngestError::Busy => "SENTRIX was busy checking other files".to_string(),
                    IngestError::Scan(s) => s,
                };
                shared.unverified(job.kind, &job.name, job.size, &format!("The check could not be completed: {why}."));
            }
        }
    }
}

// ---- manager ---------------------------------------------------------------------------------------------------

type Factory = dyn Fn() -> Result<Arc<dyn TdIo>, String> + Send + Sync;

pub struct TdAccount {
    pub shared: Arc<Shared>,
    dir: PathBuf,
    vault: SessionVault,
    creds: Option<Credentials>,
    factory: Box<Factory>,
    ctl: Arc<AtomicU8>,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl TdAccount {
    /// `dir` holds the encrypted TDLib state and the isolated download folder. `unconfigured` is the reason the account
    /// feature cannot run here (no TDLib files, no API credentials), shown to the user verbatim.
    pub fn new(shared: Arc<Shared>, dir: &Path, creds: Option<Credentials>, factory: Box<Factory>, unconfigured: Option<String>) -> Arc<Self> {
        let _ = std::fs::create_dir_all(dir);
        let me = Arc::new(TdAccount { shared, dir: dir.to_path_buf(), vault: SessionVault::new(dir), creds, factory, ctl: Arc::new(AtomicU8::new(CTL_NONE)), worker: Mutex::new(None) });
        // Anything left in the download folder by a crash is untrusted leftovers: remove it before doing anything else.
        let _ = std::fs::remove_dir_all(dir.join("files"));
        match unconfigured {
            Some(reason) => me.shared.update(|v| v.link = LinkState::Unconfigured(reason)),
            None => {
                let l = if me.vault.exists() { LinkState::Starting } else { LinkState::Disconnected };
                me.shared.update(|v| v.link = l);
            }
        }
        me
    }

    pub fn view(&self) -> AccountView {
        self.shared.snapshot()
    }

    pub fn is_running(&self) -> bool {
        self.worker.lock().unwrap().as_ref().map(|h| !h.is_finished()).unwrap_or(false)
    }

    /// Bring a saved session back after an app restart. Does nothing when there is no session.
    pub fn resume(self: &Arc<Self>) {
        if self.vault.exists() && !matches!(self.shared.snapshot().link, LinkState::Unconfigured(_)) {
            self.start(true);
        }
    }

    /// Begin a new sign-in (shows a QR code). A previous dead session is erased first.
    pub fn connect(self: &Arc<Self>) {
        if self.is_running() || matches!(self.shared.snapshot().link, LinkState::Unconfigured(_)) {
            return;
        }
        self.erase_local();
        self.start(false);
    }

    fn start(self: &Arc<Self>, resume: bool) {
        if self.is_running() {
            return;
        }
        let Some(creds) = self.creds.clone() else {
            self.shared.update(|v| v.link = LinkState::Unconfigured("No Telegram API credentials are configured in this build.".into()));
            return;
        };
        let io = match (self.factory)() {
            Ok(io) => io,
            Err(e) => {
                self.shared.update(|v| v.link = LinkState::Failed(format!("Could not start the Telegram client: {e}")));
                return;
            }
        };
        let key = if resume {
            match self.vault.load() {
                Some(k) if k.len() == 32 => k,
                _ => {
                    self.erase_local();
                    self.shared.update(|v| v.link = LinkState::Expired);
                    return;
                }
            }
        } else {
            use rand::RngCore;
            let mut k = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut k);
            if let Err(e) = self.vault.save(&k) {
                self.shared.update(|v| v.link = LinkState::Failed(format!("Could not protect the session key: {e}")));
                return;
            }
            k
        };
        let _ = std::fs::create_dir_all(self.dir.join("files"));
        self.ctl.store(CTL_NONE, Ordering::SeqCst);
        self.shared.update(|v| {
            v.link = LinkState::Starting;
            v.qr_svg = None;
            v.login_link = None;
            v.display = None;
        });
        let (tx, rx) = sync_channel::<Job>(SCAN_QUEUE);
        let engine = Engine::new(io.clone(), self.shared.clone(), creds, self.dir.clone(), key, resume, tx);
        let (shared, files, ctl, me) = (self.shared.clone(), self.dir.join("files"), self.ctl.clone(), self.clone());
        let handle = std::thread::Builder::new()
            .name("sentrix-tg-account".into())
            .spawn(move || {
                let scan_io = io.clone();
                let scan_thread = std::thread::spawn(move || scan_loop(rx, shared, scan_io, files));
                let exit = run(engine, &io, &ctl);
                let _ = scan_thread.join();
                me.after_exit(exit);
            })
            .ok();
        *self.worker.lock().unwrap() = handle;
    }

    /// Sign out at Telegram, then erase every local trace. Safe to call when not connected.
    pub fn disconnect(self: &Arc<Self>) {
        if self.is_running() {
            self.ctl.store(CTL_DISCONNECT, Ordering::SeqCst);
            // Take the handle first: the lock must not be held while waiting for the worker to finish.
            let handle = self.worker.lock().unwrap().take();
            if let Some(h) = handle {
                let _ = h.join();
            }
        } else {
            self.erase_local();
            self.shared.update(|v| {
                v.link = LinkState::Disconnected;
                v.qr_svg = None;
                v.login_link = None;
                v.display = None;
            });
        }
    }

    /// App shutdown: keep the session for the next start.
    pub fn stop(self: &Arc<Self>) {
        if self.is_running() {
            self.ctl.store(CTL_STOP, Ordering::SeqCst);
            // Take the handle first: the lock must not be held while waiting for the worker to finish.
            let handle = self.worker.lock().unwrap().take();
            if let Some(h) = handle {
                let _ = h.join();
            }
        }
    }

    pub fn set_options(&self, o: AccountOptions) {
        *self.shared.options.write().unwrap() = o;
        (self.shared.on_change)();
    }

    fn erase_local(&self) {
        self.vault.wipe();
        let _ = std::fs::remove_dir_all(self.dir.join("db"));
        let _ = std::fs::remove_dir_all(self.dir.join("files"));
        self.shared.forget_seen();
    }

    fn after_exit(&self, exit: Exit) {
        match exit {
            Exit::Stop => {
                self.shared.update(|v| {
                    v.link = LinkState::Disconnected;
                    v.qr_svg = None;
                    v.login_link = None;
                });
            }
            Exit::Disconnect => {
                self.erase_local();
                self.shared.update(|v| {
                    v.link = LinkState::Disconnected;
                    v.qr_svg = None;
                    v.login_link = None;
                    v.display = None;
                    v.pending = 0;
                });
            }
            Exit::Revoked => {
                self.erase_local();
                self.shared.update(|v| {
                    v.link = LinkState::Expired;
                    v.qr_svg = None;
                    v.login_link = None;
                    v.pending = 0;
                });
                self.shared.scanner.notice("account_expired", "Telegram ended this SENTRIX session, or it is no longer valid. Telegram files are not being checked. Open SENTRIX > Telegram and scan the QR code again to reconnect.");
            }
            Exit::Unsupported | Exit::Failed => {
                // The reason (`TwoStepUnsupported` / `Failed`) was already set on the view and is kept.
                self.erase_local();
                self.shared.update(|v| {
                    v.qr_svg = None;
                    v.login_link = None;
                    v.pending = 0;
                    v.display = None;
                });
            }
        }
    }
}

/// The worker loop. Returns how the session ended.
fn run(mut e: Engine, io: &Arc<dyn TdIo>, ctl: &AtomicU8) -> Exit {
    // TDLib delivers nothing (not even the first authorization state) until the client has been sent one request.
    io.send(r#"{"@type":"getOption","name":"version"}"#);
    let mut asked: Option<Instant> = None;
    loop {
        match ctl.swap(CTL_NONE, Ordering::SeqCst) {
            CTL_STOP => e.end(Exit::Stop),
            CTL_DISCONNECT => e.end(Exit::Disconnect),
            _ => {}
        }
        if e.exit.is_some() && asked.is_none() {
            asked = Some(Instant::now());
        }
        match io.receive(0.5) {
            Some(s) => e.handle_str(&s),
            None => e.tick(),
        }
        if e.closed {
            break;
        }
        // Telegram is unreachable while we are leaving: do not hang forever. Local erasure happens regardless.
        // Quitting the app waits briefly; an explicit disconnect gives Telegram longer to answer the sign-out.
        let limit = if e.exit == Some(Exit::Stop) { 5 } else { 15 };
        if asked.map(|t| t.elapsed() > Duration::from_secs(limit)).unwrap_or(false) {
            break;
        }
    }
    // Close the queue so the scan thread finishes what it already has, then stops.
    let exit = e.exit.unwrap_or(Exit::Stop);
    drop(e.jobs);
    exit
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// A scripted TDLib: records what we send; tests push updates in.
    #[derive(Default)]
    pub struct Fake {
        pub sent: Mutex<Vec<Value>>,
        pub inbox: Mutex<VecDeque<String>>,
    }
    impl TdIo for Fake {
        fn send(&self, r: &str) {
            self.sent.lock().unwrap().push(serde_json::from_str(r).unwrap());
        }
        fn receive(&self, _t: f64) -> Option<String> {
            self.inbox.lock().unwrap().pop_front()
        }
    }
    impl Fake {
        fn types(&self) -> Vec<String> {
            self.sent.lock().unwrap().iter().map(|v| v["@type"].as_str().unwrap_or("").to_string()).collect()
        }
        fn count(&self, t: &str) -> usize {
            self.types().iter().filter(|x| *x == t).count()
        }
    }

    struct StubScan {
        published: Mutex<Vec<ScanReport>>,
        notices: Mutex<Vec<String>>,
        scans: AtomicUsize,
    }
    impl AttachmentScanner for StubScan {
        fn scan(&self, _k: ChatKind, name: &str, _s: u64, c: &mut dyn Read) -> Result<ScanReport, IngestError> {
            let mut b = vec![];
            c.read_to_end(&mut b).unwrap();
            self.scans.fetch_add(1, Ordering::SeqCst);
            let mut r = unverified_report("Telegram personal chat", name, b.len() as u64, "stub");
            r.verdict = if b.starts_with(b"EVIL") { Verdict::Malicious } else { Verdict::Clean };
            r.complete = true;
            Ok(r)
        }
        fn publish(&self, r: &ScanReport) {
            self.published.lock().unwrap().push(r.clone());
        }
        fn notice(&self, k: &'static str, _d: &str) {
            self.notices.lock().unwrap().push(k.into());
        }
    }

    fn rig(opts: AccountOptions, resume: bool) -> (Engine, Arc<Fake>, Arc<StubScan>, Arc<Shared>, tempfile::TempDir, Receiver<Job>) {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("files")).unwrap();
        let fake = Arc::new(Fake::default());
        let scan = Arc::new(StubScan { published: Mutex::new(vec![]), notices: Mutex::new(vec![]), scans: AtomicUsize::new(0) });
        let shared = Shared::new(Arc::new(JobStore::open_in_memory().unwrap()), scan.clone(), Box::new(|| {}), opts, LinkState::Disconnected);
        let (tx, rx) = sync_channel(SCAN_QUEUE);
        let e = Engine::new(fake.clone(), shared.clone(), Credentials { api_id: 1, api_hash: "h".into() }, d.path().to_path_buf(), vec![7; 32], resume, tx);
        (e, fake, scan, shared, d, rx)
    }

    fn auth(t: &str) -> Value {
        json!({"@type": "updateAuthorizationState", "authorization_state": {"@type": t}})
    }

    fn doc_msg(chat: i64, id: i64, file_id: i64, name: &str, size: u64, uid: &str) -> Value {
        json!({"@type": "updateNewMessage", "message": {"id": id, "chat_id": chat, "is_outgoing": false, "can_be_saved": true,
            "content": {"@type": "messageDocument", "document": {"file_name": name, "document": {"id": file_id, "size": size, "expected_size": size, "remote": {"unique_id": uid}}}}}})
    }

    fn chat(id: i64, ty: Value, protected: bool) -> Value {
        json!({"@type": "updateNewChat", "chat": {"id": id, "type": ty, "has_protected_content": protected}})
    }

    fn private() -> Value {
        json!({"@type": "chatTypePrivate", "user_id": 5})
    }

    #[test]
    fn login_sends_parameters_then_asks_for_a_qr_code_and_never_for_a_phone_or_password() {
        let (mut e, fake, _s, shared, _d, _rx) = rig(AccountOptions::default(), false);
        e.handle(&auth("authorizationStateWaitTdlibParameters"));
        let p = fake.sent.lock().unwrap()[0].clone();
        assert_eq!(p["@type"], "setTdlibParameters");
        assert_eq!(p["use_message_database"], false);
        assert_eq!(p["use_secret_chats"], false);
        assert!(p["database_encryption_key"].as_str().unwrap().len() >= 40, "database is encrypted with the vault key");
        e.handle(&auth("authorizationStateWaitPhoneNumber"));
        assert_eq!(fake.count("requestQrCodeAuthentication"), 1);
        assert_eq!(fake.count("setAuthenticationPhoneNumber"), 0);
        e.handle(&json!({"@type": "updateAuthorizationState", "authorization_state": {"@type": "authorizationStateWaitOtherDeviceConfirmation", "link": "tg://login?token=AbCd"}}));
        let v = shared.snapshot();
        assert_eq!(v.link, LinkState::WaitingForScan);
        assert!(v.qr_svg.unwrap().starts_with("<svg"));
        e.handle(&auth("authorizationStateReady"));
        e.handle(&json!({"@type": "user", "@extra": "me", "first_name": "Sam", "last_name": "Q", "phone_number": "855000"}));
        let v = shared.snapshot();
        assert_eq!(v.link, LinkState::Connected);
        assert_eq!(v.display.as_deref(), Some("Sam"));
        assert!(v.qr_svg.is_none());
        assert!(!serde_json::to_string(&v).unwrap().contains("855000"), "the phone number is never kept");
    }

    #[test]
    fn a_cloud_password_account_is_refused_signed_out_and_never_asked_for_its_password() {
        let (mut e, fake, _s, shared, _d, _rx) = rig(AccountOptions::default(), false);
        e.handle(&auth("authorizationStateWaitPassword"));
        assert_eq!(shared.snapshot().link, LinkState::TwoStepUnsupported);
        assert_eq!(fake.count("logOut"), 1);
        assert_eq!(fake.count("checkAuthenticationPassword"), 0);
        assert_eq!(e.exit, Some(Exit::Unsupported));
    }

    #[test]
    fn a_refused_sign_in_request_ends_in_a_clear_failed_state() {
        let (mut e, fake, _s, shared, _d, _rx) = rig(AccountOptions::default(), false);
        e.handle(&json!({"@type": "error", "@extra": "auth", "code": 400, "message": "API_ID_INVALID"}));
        match shared.snapshot().link {
            LinkState::Failed(m) => assert!(m.contains("API_ID_INVALID"), "{m}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(fake.count("close"), 1);
        assert_eq!(e.exit, Some(Exit::Failed));
    }

    #[test]
    fn an_unexpected_sign_in_step_is_refused() {
        let (mut e, fake, _s, shared, _d, _rx) = rig(AccountOptions::default(), false);
        e.handle(&auth("authorizationStateWaitCode"));
        assert!(matches!(shared.snapshot().link, LinkState::Failed(_)));
        assert_eq!(fake.count("checkAuthenticationCode"), 0);
        assert_eq!(fake.count("logOut"), 1);
    }

    #[test]
    fn a_saved_session_that_asks_for_a_phone_number_is_expired_not_silently_relogged() {
        let (mut e, fake, _s, _shared, _d, _rx) = rig(AccountOptions::default(), true);
        e.handle(&auth("authorizationStateWaitPhoneNumber"));
        assert_eq!(fake.count("requestQrCodeAuthentication"), 0, "no login the user did not ask for");
        assert_eq!(e.exit, Some(Exit::Revoked));
    }

    #[test]
    fn a_session_ended_by_telegram_is_reported_as_expired() {
        let (mut e, _f, _s, _sh, _d, _rx) = rig(AccountOptions::default(), true);
        e.handle(&auth("authorizationStateReady"));
        e.handle(&auth("authorizationStateLoggingOut"));
        e.handle(&auth("authorizationStateClosed"));
        assert!(e.closed);
        assert_eq!(e.exit, Some(Exit::Revoked));
    }

    #[test]
    fn a_document_in_a_private_chat_is_downloaded_then_queued_once_complete() {
        let (mut e, fake, _s, shared, d, rx) = rig(AccountOptions::default(), true);
        e.handle(&chat(10, private(), false));
        e.handle(&doc_msg(10, 1, 77, "invoice.pdf", 5, "U1"));
        assert_eq!(fake.count("downloadFile"), 1);
        assert_eq!(shared.snapshot().pending, 1);
        let p = d.path().join("files").join("a.pdf");
        std::fs::write(&p, b"12345").unwrap();
        // A progress update is not completion.
        e.handle(&json!({"@type": "updateFile", "file": {"id": 77, "local": {"path": p.to_string_lossy(), "is_downloading_completed": false}}}));
        assert!(rx.try_recv().is_err(), "partial downloads are never scanned");
        e.handle(&json!({"@type": "updateFile", "file": {"id": 77, "local": {"path": p.to_string_lossy(), "is_downloading_completed": true}}}));
        let job = rx.try_recv().unwrap();
        assert_eq!(job.name, "invoice.pdf");
    }

    #[test]
    fn a_file_already_complete_in_the_reply_to_the_download_request_is_not_left_waiting() {
        let (mut e, _f, _s, _sh, d, rx) = rig(AccountOptions::default(), true);
        e.handle(&chat(10, private(), false));
        e.handle(&doc_msg(10, 1, 77, "x.pdf", 5, "U1"));
        let p = d.path().join("files").join("x.pdf");
        std::fs::write(&p, b"12345").unwrap();
        e.handle(&json!({"@type": "file", "@extra": "dl:77", "id": 77, "local": {"path": p.to_string_lossy(), "is_downloading_completed": true}}));
        assert_eq!(rx.try_recv().unwrap().name, "x.pdf");
    }

    #[test]
    fn a_short_download_is_reported_unable_to_verify_not_scanned() {
        let (mut e, _f, scan, shared, d, rx) = rig(AccountOptions::default(), true);
        e.handle(&chat(10, private(), false));
        e.handle(&doc_msg(10, 1, 77, "big.zip", 1000, "U1"));
        let p = d.path().join("files").join("b.zip");
        std::fs::write(&p, b"only part").unwrap();
        e.handle(&json!({"@type": "updateFile", "file": {"id": 77, "local": {"path": p.to_string_lossy(), "is_downloading_completed": true}}}));
        assert!(rx.try_recv().is_err());
        assert_eq!(shared.snapshot().counts.inaccessible, 1);
        let r = scan.published.lock().unwrap();
        assert_eq!(r[0].verdict, Verdict::UnableToVerify);
        assert!(!r[0].complete);
        assert!(!p.exists(), "the partial file is removed");
    }

    #[test]
    fn category_switches_are_respected_and_nothing_is_downloaded_for_a_disabled_chat_type() {
        let (mut e, fake, scan, shared, _d, _rx) = rig(AccountOptions::default(), true);
        e.handle(&chat(20, json!({"@type": "chatTypeSupergroup", "supergroup_id": 3, "is_channel": false}), false));
        e.handle(&chat(21, json!({"@type": "chatTypeSupergroup", "supergroup_id": 4, "is_channel": true}), false));
        e.handle(&doc_msg(20, 1, 1, "a.exe", 10, "A"));
        e.handle(&doc_msg(21, 1, 2, "b.exe", 10, "B"));
        assert_eq!(fake.count("downloadFile"), 0, "groups and channels are off by default");
        assert_eq!(shared.snapshot().counts.skipped, 2);
        assert!(scan.published.lock().unwrap().is_empty(), "a deliberate skip is not an alert");
    }

    #[test]
    fn switching_monitoring_off_stops_downloads_without_disconnecting() {
        let (mut e, fake, _s, shared, _d, _rx) = rig(AccountOptions { enabled: false, ..AccountOptions::default() }, true);
        e.handle(&chat(10, private(), false));
        e.handle(&doc_msg(10, 1, 5, "a.zip", 10, "A"));
        assert_eq!(fake.count("downloadFile"), 0);
        assert_eq!(shared.snapshot().counts.skipped, 1);
    }

    #[test]
    fn groups_work_when_the_user_turns_them_on() {
        let o = AccountOptions { enabled: true, prefs: AccountPrefs { groups: true, ..AccountPrefs::default() }, media: false };
        let (mut e, fake, _s, _sh, _d, _rx) = rig(o, true);
        e.handle(&chat(20, json!({"@type": "chatTypeBasicGroup", "basic_group_id": 3}), false));
        e.handle(&doc_msg(20, 1, 1, "a.exe", 10, "A"));
        assert_eq!(fake.count("downloadFile"), 1);
    }

    #[test]
    fn secret_chats_and_unknown_chat_types_are_not_supported_and_say_so() {
        let (mut e, fake, _s, shared, _d, _rx) = rig(AccountOptions::default(), true);
        e.handle(&chat(30, json!({"@type": "chatTypeSecret", "secret_chat_id": 1, "user_id": 2}), false));
        e.handle(&doc_msg(30, 1, 1, "x.bin", 10, "X"));
        assert_eq!(fake.count("downloadFile"), 0);
        assert_eq!(shared.snapshot().counts.skipped, 1);
    }

    #[test]
    fn protected_content_is_never_downloaded_and_is_reported_unable_to_verify() {
        let (mut e, fake, scan, shared, _d, _rx) = rig(AccountOptions::default(), true);
        e.handle(&chat(10, private(), true));
        e.handle(&doc_msg(10, 1, 5, "secret.pdf", 10, "P"));
        assert_eq!(fake.count("downloadFile"), 0);
        let r = scan.published.lock().unwrap();
        assert_eq!(r[0].verdict, Verdict::UnableToVerify);
        assert!(r[0].checks[0].note.as_deref().unwrap().contains("protected"));
        assert_eq!(shared.snapshot().counts.inaccessible, 1);
        // and a per-message flag does the same
        drop(r);
        let mut m = doc_msg(10, 2, 6, "n.pdf", 10, "Q");
        m["message"]["can_be_saved"] = json!(false);
        let (mut e2, f2, _s2, _sh2, _d2, _rx2) = rig(AccountOptions::default(), true);
        e2.handle(&chat(10, private(), false));
        e2.handle(&m);
        assert_eq!(f2.count("downloadFile"), 0);
    }

    #[test]
    fn oversize_files_are_not_downloaded_and_are_reported() {
        let o = AccountOptions { enabled: true, prefs: AccountPrefs { max_bytes: 100, ..AccountPrefs::default() }, media: false };
        let (mut e, fake, scan, _sh, _d, _rx) = rig(o, true);
        e.handle(&chat(10, private(), false));
        e.handle(&doc_msg(10, 1, 5, "huge.iso", 5_000_000_000, "H"));
        assert_eq!(fake.count("downloadFile"), 0);
        assert_eq!(scan.published.lock().unwrap()[0].verdict, Verdict::UnableToVerify);
    }

    #[test]
    fn the_same_message_delivered_twice_is_handled_once() {
        let (mut e, fake, _s, _sh, _d, _rx) = rig(AccountOptions::default(), true);
        e.handle(&chat(10, private(), false));
        let m = doc_msg(10, 1, 5, "a.zip", 10, "A");
        e.handle(&m);
        e.handle(&m);
        assert_eq!(fake.count("downloadFile"), 1);
    }

    #[test]
    fn outgoing_messages_and_plain_text_are_ignored() {
        let (mut e, fake, _s, shared, _d, _rx) = rig(AccountOptions::default(), true);
        e.handle(&chat(10, private(), false));
        let mut out = doc_msg(10, 1, 5, "mine.zip", 10, "M");
        out["message"]["is_outgoing"] = json!(true);
        e.handle(&out);
        e.handle(&json!({"@type": "updateNewMessage", "message": {"id": 2, "chat_id": 10, "is_outgoing": false, "content": {"@type": "messageText", "text": {"text": "hi"}}}}));
        assert_eq!(fake.count("downloadFile"), 0);
        assert_eq!(shared.snapshot().counts, Counts::default());
    }

    #[test]
    fn a_message_for_a_not_yet_known_chat_waits_for_the_chat_instead_of_guessing() {
        let (mut e, fake, _s, _sh, _d, _rx) = rig(AccountOptions::default(), true);
        e.handle(&doc_msg(10, 1, 5, "a.zip", 10, "A"));
        assert_eq!(fake.count("getChat"), 1);
        assert_eq!(fake.count("downloadFile"), 0, "no download until the chat type is known");
        e.handle(&json!({"@type": "chat", "id": 10, "type": private(), "has_protected_content": false}));
        assert_eq!(fake.count("downloadFile"), 1);
    }

    #[test]
    fn photos_and_voice_are_only_looked_at_when_media_is_switched_on() {
        let photo = json!({"@type": "updateNewMessage", "message": {"id": 1, "chat_id": 10, "is_outgoing": false, "can_be_saved": true,
            "content": {"@type": "messagePhoto", "photo": {"sizes": [{"photo": {"id": 8, "size": 10, "expected_size": 10, "remote": {"unique_id": "ph"}}}]}}}});
        let (mut e, fake, _s, _sh, _d, _rx) = rig(AccountOptions::default(), true);
        e.handle(&chat(10, private(), false));
        e.handle(&photo);
        assert_eq!(fake.count("downloadFile"), 0);
        let (mut e2, f2, _s2, _sh2, _d2, _rx2) = rig(AccountOptions { media: true, ..AccountOptions::default() }, true);
        e2.handle(&chat(10, private(), false));
        e2.handle(&photo);
        assert_eq!(f2.count("downloadFile"), 1);
    }

    #[test]
    fn a_failed_download_is_reported_and_cleaned_up() {
        let (mut e, fake, scan, shared, _d, _rx) = rig(AccountOptions::default(), true);
        e.handle(&chat(10, private(), false));
        e.handle(&doc_msg(10, 1, 5, "gone.zip", 10, "G"));
        e.handle(&json!({"@type": "error", "@extra": "dl:5", "code": 400, "message": "FILE_REFERENCE_EXPIRED"}));
        assert_eq!(shared.snapshot().pending, 0);
        assert_eq!(scan.published.lock().unwrap()[0].verdict, Verdict::UnableToVerify);
        assert!(fake.count("deleteFile") >= 1);
    }

    #[test]
    fn a_stalled_download_is_abandoned_and_reported() {
        let (mut e, _f, scan, shared, _d, _rx) = rig(AccountOptions::default(), true);
        e.handle(&chat(10, private(), false));
        e.handle(&doc_msg(10, 1, 5, "slow.zip", 10, "S"));
        for p in e.pending.values_mut() {
            p.started = Instant::now() - DOWNLOAD_STALL - Duration::from_secs(1);
        }
        e.tick();
        assert!(e.pending.is_empty());
        assert_eq!(shared.snapshot().counts.inaccessible, 1);
        assert_eq!(scan.published.lock().unwrap()[0].verdict, Verdict::UnableToVerify);
    }

    #[test]
    fn too_many_downloads_at_once_are_declined_not_queued_without_bound() {
        let (mut e, fake, scan, _sh, _d, _rx) = rig(AccountOptions::default(), true);
        e.handle(&chat(10, private(), false));
        for i in 0..(MAX_IN_FLIGHT_DOWNLOADS as i64 + 3) {
            e.handle(&doc_msg(10, i + 1, 100 + i, &format!("f{i}.zip"), 10, &format!("U{i}")));
        }
        assert_eq!(fake.count("downloadFile"), MAX_IN_FLIGHT_DOWNLOADS);
        assert_eq!(scan.published.lock().unwrap().len(), 3, "the overflow is declared");
    }

    #[test]
    fn the_scan_thread_scans_removes_the_copy_and_counts_verdicts() {
        let (mut e, fake, scan, shared, d, rx) = rig(AccountOptions::default(), true);
        e.handle(&chat(10, private(), false));
        e.handle(&doc_msg(10, 1, 7, "evil.exe", 8, "E1"));
        let p = d.path().join("files").join("evil.exe");
        std::fs::write(&p, b"EVILEVIL").unwrap();
        e.handle(&json!({"@type": "updateFile", "file": {"id": 7, "local": {"path": p.to_string_lossy(), "is_downloading_completed": true}}}));
        let io: Arc<dyn TdIo> = fake.clone();
        let (sh, files) = (shared.clone(), d.path().join("files"));
        drop(e.jobs);
        scan_loop(rx, sh, io, files);
        let v = shared.snapshot();
        assert_eq!(v.counts.scanned, 1);
        assert_eq!(v.counts.threats, 1);
        assert_eq!(v.recent[0].verdict, "MALICIOUS");
        assert!(!p.exists(), "the untrusted copy is deleted after the scan");
        assert_eq!(scan.scans.load(Ordering::SeqCst), 1);
        assert!(fake.count("deleteFile") >= 1);
        assert!(shared.was_seen("f:E1"), "a finished file is remembered, so it is not scanned twice");
    }

    #[test]
    fn the_same_file_posted_again_is_checked_once() {
        let (mut e, fake, _s, shared, _d, _rx) = rig(AccountOptions::default(), true);
        e.handle(&chat(10, private(), false));
        shared.mark_seen("f:SAME");
        e.handle(&doc_msg(10, 9, 5, "again.zip", 10, "SAME"));
        assert_eq!(fake.count("downloadFile"), 0);
        assert_eq!(shared.snapshot().counts.skipped, 1);
    }

    #[test]
    fn connection_state_and_last_sync_follow_telegram() {
        let (mut e, _f, _s, shared, _d, _rx) = rig(AccountOptions::default(), true);
        e.handle(&json!({"@type": "updateConnectionState", "state": {"@type": "connectionStateWaitingForNetwork"}}));
        assert_eq!(shared.snapshot().connection, "waiting_for_network");
        assert!(shared.snapshot().last_sync_at.is_none());
        e.handle(&json!({"@type": "updateConnectionState", "state": {"@type": "connectionStateReady"}}));
        assert_eq!(shared.snapshot().connection, "ready");
        assert!(shared.snapshot().last_sync_at.is_some());
    }

    #[test]
    fn the_qr_code_only_encodes_a_telegram_login_link() {
        assert!(qr_svg("tg://login?token=abc").is_some());
        assert!(qr_svg("https://evil.example/").is_none());
        assert!(qr_svg("").is_none());
    }

    #[test]
    fn removal_never_leaves_the_download_folder() {
        let d = tempfile::tempdir().unwrap();
        let files = d.path().join("files");
        std::fs::create_dir_all(&files).unwrap();
        let outside = d.path().join("keep.txt");
        std::fs::write(&outside, b"x").unwrap();
        remove_inside(&files, &outside);
        assert!(outside.exists());
        let inside = files.join("gone.bin");
        std::fs::write(&inside, b"x").unwrap();
        remove_inside(&files, &inside);
        assert!(!inside.exists());
    }

    #[test]
    fn seen_ids_survive_a_restart_and_are_bounded() {
        let store = Arc::new(JobStore::open_in_memory().unwrap());
        let scan: Arc<dyn AttachmentScanner> = Arc::new(StubScan { published: Mutex::new(vec![]), notices: Mutex::new(vec![]), scans: AtomicUsize::new(0) });
        let a = Shared::new(store.clone(), scan.clone(), Box::new(|| {}), AccountOptions::default(), LinkState::Disconnected);
        a.mark_seen("m:1:1");
        let b = Shared::new(store, scan, Box::new(|| {}), AccountOptions::default(), LinkState::Disconnected);
        assert!(b.was_seen("m:1:1"));
        for i in 0..(SEEN_MAX + 50) {
            b.mark_seen(&format!("m:2:{i}"));
        }
        assert!(b.seen.lock().unwrap().1.len() <= SEEN_MAX);
        assert!(!b.was_seen("m:1:1"), "oldest entries age out");
    }
}

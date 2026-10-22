//! The background protection service. UI-independent so it can be tested end to end without a window.
//!
//!   file events ─▶ enqueue (durable, deduplicated) ─▶ workers ─▶ scan ─▶ policy (quarantine / execution guard)
//!        ▲                                                         │
//!   reconciler (catches missed events and files that arrived while SENTRIX was off)
//!                                                                  ├─▶ hooks (history, local notification)
//!                                                                  └─▶ outbox ─▶ Telegram (separate, never affects scanning)
//!
//! Honesty rules enforced here: a failed/partial scan is never recorded as clean; transient failures retry and then
//! surface in "could not check"; a change during a scan marks the result stale and rescans; delivery problems are
//! confined to the outbox.

use crate::guard;
use crate::monitor::{is_temp_name, Monitor};
use crate::notify::{self, NotifyPrefs};
use crate::quarantine::{sanitize_filename, Quarantine};
use crate::queue::*;
use crate::scanner::{walk, EngineStatus, ScanOptions, Scanner};
use crate::hosted::HostedConfig;
use crate::telegram::{esc, safe_display_name, BotClient, Courier, Incoming, TgError, MAX_BOT_DOWNLOAD};
use crate::types::{ScanReport, Verdict};
use serde::Serialize;
use std::collections::VecDeque;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize)]
pub struct WatchRoot {
    pub path: PathBuf,
    /// Shown as the file's source: "Telegram Desktop", "Downloads folder", "Custom folder", "Removable drive"…
    pub label: String,
}

#[derive(Clone)]
pub struct ServiceConfig {
    pub realtime: bool,
    pub roots: Vec<WatchRoot>,
    pub exclude: Vec<PathBuf>,
    pub auto_quarantine: bool,
    pub execution_guard: bool,
    pub notify: NotifyPrefs,
    pub chat_id: Option<i64>,
    pub accept_submissions: bool,
    /// Group Shield master switch: the owner has agreed that groups the bot is in may be scanned on this computer.
    pub group_shield: bool,
    /// Shared-bot mode (the hosted SENTRIX bot): everyone who finds the bot can protect their own groups.
    pub hosted: Option<HostedConfig>,
    /// Reports go through the relay (`set_courier`) instead of a bot token held on this computer.
    pub relay: bool,
    pub workers: usize,
    /// Reconciliation only looks at files modified within this many days (a whole old Downloads folder is not rescanned).
    pub reconcile_lookback_days: i64,
    pub tmp_root: PathBuf,
}

impl ServiceConfig {
    pub fn new(tmp_root: PathBuf) -> Self {
        ServiceConfig { realtime: false, roots: vec![], exclude: vec![], auto_quarantine: false, execution_guard: true, notify: NotifyPrefs::default(), chat_id: None, accept_submissions: false, group_shield: false, hosted: None, relay: false, workers: 2, reconcile_lookback_days: 7, tmp_root }
    }
}

pub trait Hooks: Send + Sync {
    /// Called once per final result (never for a result that will be retried).
    fn on_report(&self, report: &ScanReport);
    fn on_health_changed(&self) {}
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RootHealth {
    pub path: String,
    pub label: String,
    pub exists: bool,
    pub watching: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionHealth {
    pub realtime_enabled: bool,
    pub monitor_running: bool,
    pub roots: Vec<RootHealth>,
    pub queue: QueueStats,
    pub outbox: OutboxStats,
    pub recent_events: Vec<EventRow>,
    pub could_not_check: Vec<FailedJob>,
    pub rejected_submissions: u64,
    pub last_reconcile_at: Option<i64>,
    pub last_file_event_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupView {
    pub id: i64,
    #[serde(flatten)]
    pub group: Group,
    pub stats: GroupStats,
}

pub(crate) struct Inner {
    pub(crate) scanner: Arc<Scanner>,
    pub(crate) quarantine: Arc<Quarantine>,
    pub(crate) store: Arc<JobStore>,
    pub(crate) hooks: Arc<dyn Hooks>,
    pub(crate) cfg: RwLock<ServiceConfig>,
    pub(crate) bot: RwLock<Option<Arc<BotClient>>>,
    pub(crate) courier: RwLock<Option<Arc<dyn Courier>>>,
    pub(crate) monitor: Mutex<Option<Monitor>>,
    pub(crate) stop: Arc<AtomicBool>,
    pub(crate) last_engine_state: Mutex<String>,
    pub(crate) rejected: AtomicU64,
    pub(crate) last_reconcile: AtomicI64,
    pub(crate) last_event: AtomicI64,
    pub(crate) submission_times: Mutex<VecDeque<Instant>>,

    pub(crate) groups: crate::group::GroupState,}

pub struct ProtectionService {
    inner: Arc<Inner>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

fn mtime_ms(m: &std::fs::Metadata) -> i64 {
    m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as i64).unwrap_or(0)
}

impl Inner {
    /// Sleep in small steps so shutdown is prompt. Returns false when the service is stopping.
    pub(crate) fn nap(&self, ms: u64) -> bool {
        let mut left = ms;
        while left > 0 {
            if self.stop.load(Ordering::Relaxed) {
                return false;
            }
            let step = left.min(100);
            std::thread::sleep(Duration::from_millis(step));
            left -= step;
        }
        !self.stop.load(Ordering::Relaxed)
    }

    fn label_for(&self, path: &Path) -> String {
        let cfg = self.cfg.read().unwrap();
        let key = path_key(path);
        let best = cfg.roots.iter().filter(|r| {
            let rk = path_key(&r.path);
            let rk = rk.trim_end_matches('\\');
            key == rk || key.starts_with(&format!("{rk}\\"))
        }).max_by_key(|r| path_key(&r.path).len());
        match best {
            Some(r) if r.label == "Telegram Desktop" => r.label.clone(),
            // Windows records where a download came from; browsers and mail clients write it.
            Some(_) if crate::scanner::zone_source(path).is_some() => "Browser download".into(),
            Some(r) => r.label.clone(),
            None => "Manual scan".into(),
        }
    }

    pub(crate) fn event(&self, kind: &str, severity: &str, msg: &str) {
        self.store.add_event(kind, severity, msg, now_ms());
        self.hooks.on_health_changed();
    }

    fn enqueue_path(&self, path: &Path) {
        if is_temp_name(path) {
            return;
        }
        let Ok(m) = std::fs::symlink_metadata(path) else { return };
        if !m.is_file() {
            return;
        }
        let source = self.label_for(path);
        match self.store.enqueue(path, &source, m.len(), mtime_ms(&m), now_ms()) {
            Ok(Enq::Overflow) => self.event("queue_overflow", "warning", "Too many files are waiting to be scanned; some new files were not queued. They will be picked up by the next folder check."),
            Ok(_) => {}
            Err(e) => self.event("queue_error", "warning", &format!("Could not queue a file: {e}")),
        }
    }

    // ---- monitor ------------------------------------------------------------------------------------------

    fn restart_monitor(self: &Arc<Self>) {
        if let Some(old) = self.monitor.lock().unwrap().take() {
            old.stop();
        }
        let cfg = self.cfg.read().unwrap().clone();
        if !cfg.realtime || cfg.roots.is_empty() {
            return;
        }
        let me = self.clone();
        let cb: Arc<dyn Fn(PathBuf) + Send + Sync> = Arc::new(move |p| {
            me.last_event.store(now_ms(), Ordering::Relaxed);
            me.enqueue_path(&p);
        });
        let dirs: Vec<PathBuf> = cfg.roots.iter().map(|r| r.path.clone()).collect();
        match Monitor::start(&dirs, cb) {
            Ok(m) => {
                for (p, e) in &m.status.failed {
                    self.event("folder_unavailable", "warning", &format!("Cannot watch {}: {e}", p.display()));
                }
                *self.monitor.lock().unwrap() = Some(m);
            }
            Err(e) => self.event("monitor_failed", "critical", &format!("Real-time monitoring could not start: {e}")),
        }
    }

    // ---- reconciliation -----------------------------------------------------------------------------------

    fn reconcile(&self) -> usize {
        let cfg = self.cfg.read().unwrap().clone();
        if !cfg.realtime {
            return 0;
        }
        let roots: Vec<PathBuf> = cfg.roots.iter().map(|r| r.path.clone()).collect();
        let cutoff = now_ms() - cfg.reconcile_lookback_days * 86_400_000;
        let mut found = Vec::new();
        const CAP: usize = 20_000;
        walk(&roots, &self.stop, &cfg.exclude, &mut |p| {
            if is_temp_name(&p) {
                return true;
            }
            if let Ok(m) = std::fs::symlink_metadata(&p) {
                let mt = mtime_ms(&m);
                if m.is_file() && mt >= cutoff && !self.store.is_current(&p, m.len(), mt).unwrap_or(false) {
                    found.push(p);
                }
            }
            found.len() < CAP
        }, &mut |_, _| {});
        let mut n = 0;
        for p in found {
            self.enqueue_path(&p);
            n += 1;
        }
        self.last_reconcile.store(now_ms(), Ordering::Relaxed);
        if n > 0 {
            self.event("reconciled", "info", &format!("Found {n} file(s) that arrived while real-time events were not being received (for example while SENTRIX was closed) and queued them."));
        }
        n
    }

    // ---- worker -------------------------------------------------------------------------------------------

    fn process(self: &Arc<Self>, job: Job) {
        let path = PathBuf::from(&job.path);
        let cfg = self.cfg.read().unwrap().clone();

        // Gate: don't scan something that is still being written.
        let Ok(pre) = std::fs::symlink_metadata(&path) else {
            let _ = self.store.discard(&job.id, now_ms());
            return;
        };
        let (pre_size, pre_mtime) = (pre.len(), mtime_ms(&pre));
        let settle_ms = if job.source == "Telegram Desktop" { 3000 } else { 1500 };
        if now_ms() - pre_mtime < settle_ms {
            let _ = self.store.defer(&job.id, now_ms() + settle_ms, now_ms());
            return;
        }

        let opts = ScanOptions { cancel: self.stop.clone(), use_cache: true, exclude: vec![], max_retained_reports: 1 };
        let mut report = self.scanner.scan_file(&path, &opts);
        if self.stop.load(Ordering::Relaxed) {
            let _ = self.store.defer(&job.id, now_ms(), now_ms()); // shutting down: not a result
            return;
        }
        report.origin = Some(job.source.clone());

        // Transient problem (locked file, engine not running yet)? Retry later instead of recording a non-answer.
        let transient = report.checks.iter().any(|c| c.retryable && c.status.is_gap());
        let mut gave_up = false;
        if transient && report.verdict != Verdict::Malicious {
            let why = report.checks.iter().find(|c| c.retryable && c.status.is_gap()).and_then(|c| c.note.clone()).unwrap_or_else(|| "temporary failure".into());
            match self.store.fail_transient(&job.id, &why, now_ms()) {
                Ok(Retry::At(_)) => return,
                Ok(Retry::GaveUp) => {
                    gave_up = true;
                    self.event("scan_failed", "warning", &format!("Could not check {} after several attempts: {why}", path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()));
                }
                Err(_) => return,
            }
        }

        // Did the file change while it was being scanned? Then this result describes old content.
        if let Ok(post) = std::fs::symlink_metadata(&path) {
            if post.len() != pre_size || mtime_ms(&post) != pre_mtime {
                let _ = self.store.enqueue(&path, &job.source, post.len(), mtime_ms(&post), now_ms());
                self.event("stale_result", "info", "A file changed while it was being scanned, so it will be scanned again.");
            }
        }

        // Policy: quarantine confirmed malware (only when the user enabled it), else fall back to the execution guard.
        // (A MALICIOUS verdict without a hash means the OS provider blocked our read; it is already handling that file.)
        if report.verdict == Verdict::Malicious && !report.file.sha256.is_empty() {
            if cfg.auto_quarantine {
                match self.quarantine.quarantine(&path, Some(&report.file.sha256), report.verdict, &report.summary, &report.file.detected_type) {
                    Ok(_) => {
                        report.quarantined = true;
                        self.event("quarantined", "warning", &format!("Quarantined {} ({}).", report.file.name, report.findings.iter().find(|f| f.kind == crate::types::FindingKind::Signature).map(|f| f.name.as_str()).unwrap_or("malicious")));
                    }
                    Err(e) => self.event("quarantine_failed", "warning", &format!("Could not quarantine {}: {e}", report.file.name)),
                }
            }
            if !report.quarantined && cfg.execution_guard {
                match guard::block_execution(&path) {
                    Ok(()) => {
                        report.blocked = true;
                        self.event("execution_blocked", "warning", &format!("Execution of {} is blocked (the file was left in place).", report.file.name));
                    }
                    Err(e) => self.event("guard_failed", "warning", &format!("Could not block {}: {e}", report.file.name)),
                }
            }
        }

        self.hooks.on_report(&report);

        if !gave_up {
            let verdict_label = report.verdict.label().replace(' ', "_");
            let _ = self.store.complete(&job.id, &report.id.to_string(), &verdict_label, &report.file.sha256, pre_size, pre_mtime, report.complete, now_ms());
        }
        self.queue_report_notification(&report, &cfg);
        self.hooks.on_health_changed();
    }

    /// Is there somewhere to send reports? Either the person's own bot chat, or the relay in front of the shared bot.
    pub(crate) fn reporting_ready(&self, cfg: &ServiceConfig) -> bool {
        if cfg.relay {
            self.courier.read().unwrap().is_some()
        } else {
            cfg.chat_id.is_some() && self.bot.read().unwrap().is_some()
        }
    }

    fn queue_report_notification(&self, report: &ScanReport, cfg: &ServiceConfig) {
        if !self.reporting_ready(cfg) {
            return;
        }
        if let Some(o) = notify::format_report(report, &cfg.notify, now_ms()) {
            let _ = self.store.enqueue_notification(&o.dedupe_key, &o.kind, &o.text, now_ms());
        }
    }

    // ---- health watcher -----------------------------------------------------------------------------------

    fn watch_health(self: &Arc<Self>) {
        let es: EngineStatus = self.scanner.engine_status();
        let prev = std::mem::replace(&mut *self.last_engine_state.lock().unwrap(), es.state.clone());
        let cfg = self.cfg.read().unwrap().clone();
        if prev != es.state && !prev.is_empty() {
            self.event("engine_state", if es.state == "running" { "info" } else { "warning" }, &format!("Detection engine: {}. {}", es.state, es.detail));
            let sys = match es.state.as_str() {
                "unavailable" | "stopped" => Some("engine_unavailable"),
                "degraded" => Some("signatures_outdated"),
                "running" if matches!(prev.as_str(), "unavailable" | "stopped") => Some("protection_restored"),
                _ => None,
            };
            if let (Some(k), true) = (sys, self.reporting_ready(&cfg)) {
                if let Some(o) = notify::format_system(k, &es.detail, &cfg.notify, now_ms()) {
                    let _ = self.store.enqueue_notification(&o.dedupe_key, &o.kind, &o.text, now_ms());
                }
            }
        }
        // Folders that were missing (unplugged drive) may be back.
        if cfg.realtime && !cfg.roots.is_empty() {
            let unwatched = {
                let m = self.monitor.lock().unwrap();
                match m.as_ref() {
                    None => true,
                    Some(m) => cfg.roots.iter().any(|r| r.path.exists() && !m.status.watching.contains(&r.path)),
                }
            };
            if unwatched && cfg.roots.iter().any(|r| r.path.exists()) {
                self.restart_monitor();
            }
        }
        if let Ok(n) = self.store.recover_stuck(now_ms(), STUCK_AFTER_MS) {
            if n > 0 {
                self.event("jobs_recovered", "warning", &format!("{n} scan(s) were stuck and have been queued again."));
            }
        }
    }

    // ---- ephemeral scans (bot submissions, account attachments) --------------------------------------------

    pub(crate) fn scan_ephemeral(&self, origin: &str, display_name: &str, reader: &mut dyn Read, max_bytes: u64) -> Result<ScanReport, String> {
        let cfg = self.cfg.read().unwrap().clone();
        let dir = cfg.tmp_root.join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).map_err(|e| format!("could not create a temporary folder: {e}"))?;
        /// Removes the isolated folder (and the untrusted file in it) on every exit path.
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        // The untrusted name is reduced to a safe leaf and placed in a folder we just created: it cannot escape it.
        let leaf = sanitize_filename(display_name);
        let file = dir.join(&leaf);
        {
            let mut out = std::fs::OpenOptions::new().write(true).create_new(true).open(&file).map_err(|e| format!("could not create the temporary file: {e}"))?;
            let mut limited = reader.take(max_bytes + 1);
            let n = std::io::copy(&mut limited, &mut out).map_err(|e| format!("could not store the file: {e}"))?;
            if n > max_bytes {
                return Err("the file is larger than the allowed limit".into());
            }
        }
        let mut r = self.scanner.scan_file(&file, &ScanOptions { cancel: self.stop.clone(), use_cache: true, exclude: vec![], max_retained_reports: 1 });
        r.origin = Some(origin.to_string());
        r.file.name = display_name.chars().filter(|c| !c.is_control()).take(120).collect();
        r.file.path = PathBuf::from(format!("[{origin}] {}", r.file.name));
        Ok(r)
    }

    pub(crate) fn handle_submission(&self, bot: &BotClient, chat_id: i64, u: &Incoming) {
        let reply = |key: String, text: String| {
            let _ = self.store.enqueue_notification(&key, "submission", &text, now_ms());
        };
        // Only the configured owner may use the bot: a private chat whose chat id and sender id both match.
        if !(u.chat_type == "private" && u.chat_id == chat_id && u.from_id == Some(chat_id)) {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            self.event("telegram_rejected_sender", "warning", "Ignored a message to your SENTRIX bot from someone who is not the configured owner.");
            return;
        }
        if let Some(t) = u.text.as_deref() {
            let t = t.trim();
            let text = if t.starts_with("/status") {
                let es = self.scanner.engine_status();
                let q = self.store.stats(now_ms()).ok();
                format!("<b>SENTRIX status</b>\nEngine: {}\nWaiting to scan: {}\nFiles checked: {}", esc(&es.state), q.as_ref().map(|s| s.queued).unwrap_or(0), q.as_ref().map(|s| s.files_scanned).unwrap_or(0))
            } else {
                "Send me a file as a <b>document</b> (attach it as a File, not a photo) and SENTRIX will scan it on your computer and reply with the result. Files over 20 MB cannot be received by a bot.\n\nCommands: /status".into()
            };
            reply(format!("sub:{}", u.update_id), text);
            return;
        }
        if u.other_media {
            reply(format!("sub:{}", u.update_id), "Telegram recompresses photos and videos, so they cannot be scanned reliably. Please send the original as a <b>File</b> (document).".into());
            return;
        }
        let Some(doc) = &u.document else { return };
        // Rate limit: 5 files per minute.
        {
            let mut t = self.submission_times.lock().unwrap();
            let now = Instant::now();
            while t.front().is_some_and(|x| now.duration_since(*x) > Duration::from_secs(60)) {
                t.pop_front();
            }
            if t.len() >= 5 {
                drop(t);
                reply(format!("sub:{}", u.update_id), "Too many files at once. Please wait a minute and send it again.".into());
                return;
            }
            t.push_back(now);
        }
        let name = doc.file_name.clone().unwrap_or_else(|| "file".into());
        let shown = safe_display_name(&name);
        if doc.file_size.is_some_and(|s| s > MAX_BOT_DOWNLOAD) {
            reply(format!("sub:{}", u.update_id), format!("<b>{shown}</b> is larger than the 20 MB Telegram lets a bot download, so it was not scanned. Scan it in the SENTRIX app instead."));
            return;
        }
        let (path, _) = match bot.get_file(&doc.file_id) {
            Ok(x) => x,
            Err(e) => {
                reply(format!("sub:{}", u.update_id), format!("<b>{shown}</b> could not be retrieved from Telegram ({}). It was not scanned.", esc(&e.user_message())));
                return;
            }
        };
        let mut buf: Vec<u8> = Vec::new();
        if let Err(e) = bot.download(&path, &mut buf, MAX_BOT_DOWNLOAD) {
            reply(format!("sub:{}", u.update_id), format!("<b>{shown}</b> could not be downloaded ({}). It was not scanned.", esc(&e.user_message())));
            return;
        }
        match self.scan_ephemeral("Telegram bot submission", &name, &mut buf.as_slice(), MAX_BOT_DOWNLOAD) {
            Ok(r) => {
                self.hooks.on_report(&r);
                // The user asked for this result, so it bypasses the "which events" preferences.
                let all = NotifyPrefs { malicious: true, suspicious: true, unable_to_verify: true, clean_scans: true, quarantined: true, include_hash: true, ..NotifyPrefs::default() };
                if let Some(o) = notify::format_report(&r, &all, now_ms()) {
                    reply(format!("sub:{}", u.update_id), o.text);
                }
            }
            Err(e) => reply(format!("sub:{}", u.update_id), format!("<b>{shown}</b> could not be scanned: {}.", esc(&e))),
        }
    }
}

impl ProtectionService {
    pub fn new(scanner: Arc<Scanner>, quarantine: Arc<Quarantine>, store: Arc<JobStore>, hooks: Arc<dyn Hooks>, cfg: ServiceConfig) -> Self {
        ProtectionService {
            inner: Arc::new(Inner {
                scanner,
                quarantine,
                store,
                hooks,
                cfg: RwLock::new(cfg),
                bot: RwLock::new(None),
                courier: RwLock::new(None),
                monitor: Mutex::new(None),
                stop: Arc::new(AtomicBool::new(false)),
                last_engine_state: Mutex::new(String::new()),
                rejected: AtomicU64::new(0),
                last_reconcile: AtomicI64::new(0),
                last_event: AtomicI64::new(0),
                submission_times: Mutex::new(VecDeque::new()),
                groups: Default::default(),
            }),
            threads: Mutex::new(vec![]),
        }
    }


    /// Registered groups with their last-24-hour numbers, for the app's Telegram page. No file names are kept.
    pub fn groups_view(&self) -> Vec<GroupView> {
        let i = &self.inner;
        let since = now_ms() - 86_400_000;
        i.store
            .groups_list()
            .unwrap_or_default()
            .into_iter()
            .filter(|g| g.left_at.is_none())
            .map(|g| {
                let stats = i.store.group_stats(g.chat_id, since).unwrap_or_default();
                GroupView { id: g.chat_id, group: g, stats }
            })
            .collect()
    }

    /// The owner stops protecting one group (and can no longer be consented away by it): turns protection and deletion off.
    pub fn group_disable(&self, chat_id: i64) {
        let _ = self.inner.store.group_set_enabled(chat_id, false, 0, now_ms());
        let _ = self.inner.store.group_set_auto_delete(chat_id, false, 0, now_ms());
    }

    /// Forget a group's local history and ask the bot to leave it.
    pub fn group_leave(&self, chat_id: i64) -> Result<(), String> {
        let bot = self.inner.bot.read().unwrap().clone();
        if let Some(b) = bot {
            b.leave_chat(chat_id).map_err(|e| e.user_message())?;
        }
        let _ = self.inner.store.group_forget(chat_id);
        Ok(())
    }

    pub fn group_totals(&self) -> GroupTotals {
        self.inner.store.group_totals(now_ms() - 86_400_000).unwrap_or_default()
    }

    /// Does Telegram privacy mode hide ordinary group messages from the bot? None when not yet known.
    pub fn privacy_mode_blocks(&self) -> Option<bool> {
        self.inner.store.kv_get("tg_privacy_blocking").map(|v| v == "1")
    }

    pub fn store(&self) -> &Arc<JobStore> {
        &self.inner.store
    }

    pub fn set_config(&self, cfg: ServiceConfig) {
        *self.inner.cfg.write().unwrap() = cfg;
        self.inner.restart_monitor();
        self.inner.hooks.on_health_changed();
    }

    pub fn set_bot(&self, bot: Option<Arc<BotClient>>) {
        *self.inner.bot.write().unwrap() = bot;
    }

    /// Where queued reports are delivered when `cfg.relay` is on (the relay in front of the shared bot).
    pub fn set_courier(&self, courier: Option<Arc<dyn Courier>>) {
        *self.inner.courier.write().unwrap() = courier;
    }

    /// Start workers and background loops. Anything left "scanning" by a previous run is recovered first.
    pub fn start(&self) {
        let inner = &self.inner;
        inner.stop.store(false, Ordering::Relaxed);
        if let Ok(n) = inner.store.recover_stuck(now_ms(), 0) {
            if n > 0 {
                inner.event("jobs_recovered", "info", &format!("Resumed {n} scan(s) that were interrupted when SENTRIX last stopped."));
            }
        }
        inner.restart_monitor();
        if inner.cfg.read().unwrap().hosted.is_some() && inner.store.kv_get("hosted_clean_default_v1").is_none() {
            // Groups linked before clean results were reported by default start reporting them once. Anyone can still turn
            // them off with /setup clean off, and that choice is kept.
            let _ = inner.store.group_enable_clean_reports();
            inner.store.kv_set("hosted_clean_default_v1", "1");
        }
        let mut th = self.threads.lock().unwrap();
        let spawn = |name: &str, f: Box<dyn FnOnce() + Send>| std::thread::Builder::new().name(name.into()).spawn(f).expect("thread");

        for i in 0..inner.cfg.read().unwrap().workers.clamp(1, 4) {
            let me = inner.clone();
            th.push(spawn(&format!("sentrix-worker-{i}"), Box::new(move || {
                while !me.stop.load(Ordering::Relaxed) {
                    match me.store.claim_due(now_ms(), 1) {
                        Ok(jobs) if !jobs.is_empty() => {
                            for j in jobs {
                                let m2 = me.clone();
                                // A panic inside one scan must not take down the worker or leave the job "scanning".
                                let id = j.id.clone();
                                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| m2.process(j))).is_err() {
                                    let _ = me.store.fail_transient(&id, "internal error while scanning", now_ms());
                                    me.event("worker_panic", "critical", "A scan crashed internally and was contained. It will be retried.");
                                }
                            }
                        }
                        _ => {
                            me.nap(400);
                        }
                    }
                }
            })));
        }

        let me = inner.clone();
        th.push(spawn("sentrix-reconciler", Box::new(move || {
            if !me.nap(2000) {
                return;
            }
            loop {
                me.reconcile();
                me.store.prune_outbox(now_ms());
                me.store.prune_group_scans(now_ms());
                if !me.nap(10 * 60 * 1000) {
                    return;
                }
            }
        })));

        let me = inner.clone();
        th.push(spawn("sentrix-health", Box::new(move || {
            while me.nap(5000) {
                me.watch_health();
            }
        })));

        let me = inner.clone();
        th.push(spawn("sentrix-outbox", Box::new(move || {
            while me.nap(1500) {
                let (cfg_chat, relay, hosted) = {
                    let c = me.cfg.read().unwrap();
                    (c.chat_id, c.relay, c.hosted.is_some())
                };
                // Through the relay, or straight through the bot. In shared-bot mode every row names its own chat.
                let courier: Option<Arc<dyn Courier>> = if relay { me.courier.read().unwrap().clone() } else { me.bot.read().unwrap().clone().map(|b| b as Arc<dyn Courier>) };
                let chat = if relay || hosted { Some(cfg_chat.unwrap_or(0)) } else { cfg_chat };
                if let (Some(courier), Some(chat)) = (courier, chat) {
                    let d = notify::deliver_due(&me.store, &*courier, chat, 5, Duration::from_millis(1100));
                    if d.sent + d.retrying + d.dead > 0 {
                        me.hooks.on_health_changed();
                    }
                }
            }
        })));

        let me = inner.clone();
        th.push(spawn("sentrix-tgbot", Box::new(move || {
            let mut backoff = 5u64;
            while me.nap(1000) {
                let (bot, chat, on, shield, hosted) = {
                    let c = me.cfg.read().unwrap();
                    (me.bot.read().unwrap().clone(), if c.hosted.is_some() { Some(c.chat_id.unwrap_or(0)) } else { c.chat_id }, c.accept_submissions, c.group_shield, c.hosted.is_some())
                };
                // One worker serves both features; it only runs while at least one of them is switched on.
                let (Some(bot), Some(chat), true) = (bot, chat, on || shield || hosted) else { continue };
                let offset = me.store.kv_get("tg_offset").and_then(|s| s.parse::<i64>().ok());
                match bot.get_updates(offset, 10, 20) {
                    Ok(updates) => {
                        backoff = 5;
                        me.store.kv_set("tg_poll_ok_at", &now_ms().to_string());
                        me.store.kv_delete("tg_poll_error");
                        for u in updates {
                            // One bad message must never stop the bot for everybody: a crash while handling it is contained,
                            // recorded, and the message is skipped (never replayed forever).
                            let handled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                if matches!(u.chat_type.as_str(), "group" | "supergroup") {
                                    if let Some(info) = me.bot_info(&bot) {
                                        me.handle_group_update(&bot, &info, &u);
                                    }
                                } else if hosted {
                                    if let Some(info) = me.bot_info(&bot) {
                                        me.handle_hosted_private(&bot, &info, &u);
                                    }
                                } else if on && u.member_change.is_none() {
                                    me.handle_submission(&bot, chat, &u);
                                }
                            }));
                            if handled.is_err() {
                                me.event("bot_update_panic", "critical", "A Telegram message crashed the handler internally. It was skipped and the bot keeps running.");
                            }
                            // Only after the update was handled (or contained), so a crash replays nothing.
                            me.store.kv_set("tg_offset", &(u.update_id + 1).to_string());
                        }
                    }
                    Err(e) => {
                        let msg = e.user_message();
                        me.store.kv_set("tg_poll_error", &msg);
                        if matches!(e, TgError::Api { code: 409, .. }) {
                            // Another program is reading this bot's messages (a second copy of the service, or an app that
                            // has this bot as its own). Only one can. Say so, and retry soon: the conflict ends the moment the
                            // other one stops.
                            me.event("telegram_poll", "warning", "Another program is reading this bot's messages at the same time (for example a second copy of the bot service, or the SENTRIX app connected to this same bot). Only one can. Stop the other one.");
                            me.nap(20 * 1000);
                        } else if matches!(e, TgError::Api { code: 401, .. }) {
                            me.event("telegram_poll", "critical", &msg);
                            me.nap(60 * 1000);
                        } else {
                            me.nap(backoff * 1000);
                            backoff = (backoff * 2).min(120);
                        }
                    }
                }
            }
        })));
    }

    pub fn stop(&self) {
        self.inner.stop.store(true, Ordering::Relaxed);
        if let Some(m) = self.inner.monitor.lock().unwrap().take() {
            m.stop();
        }
        for t in self.threads.lock().unwrap().drain(..) {
            let _ = t.join();
        }
    }

    /// Queue a path (used by tests and by "scan now" style actions).
    pub fn enqueue_path(&self, path: &Path) {
        self.inner.enqueue_path(path);
    }

    pub fn reconcile_now(&self) -> usize {
        self.inner.reconcile()
    }

    /// Scan bytes that never live in a user folder (a bot submission, an account attachment). Isolated temp folder,
    /// size-capped, always cleaned up.
    pub fn scan_ephemeral(&self, origin: &str, display_name: &str, reader: &mut dyn Read, max_bytes: u64) -> Result<ScanReport, String> {
        self.inner.scan_ephemeral(origin, display_name, reader, max_bytes)
    }

    /// Record a result produced outside the folder pipeline (bot submission, account attachment): history/UI hooks, plus
    /// a Telegram report if the user's preferences want one.
    pub fn publish_report(&self, r: &ScanReport) {
        self.inner.hooks.on_report(r);
        let cfg = self.inner.cfg.read().unwrap().clone();
        self.inner.queue_report_notification(r, &cfg);
        self.inner.hooks.on_health_changed();
    }

    /// An account-level notice (for example "Telegram authorization expired") through the user's own bot, if they want it.
    pub fn notify_system(&self, kind: &'static str, detail: &str) {
        let cfg = self.inner.cfg.read().unwrap().clone();
        if self.inner.reporting_ready(&cfg) {
            if let Some(o) = notify::format_system(kind, detail, &cfg.notify, now_ms()) {
                let _ = self.inner.store.enqueue_notification(&o.dedupe_key, &o.kind, &o.text, now_ms());
            }
        }
    }

    pub fn health(&self) -> ProtectionHealth {
        let i = &self.inner;
        let cfg = i.cfg.read().unwrap().clone();
        let m = i.monitor.lock().unwrap();
        let (watching, failed): (Vec<PathBuf>, Vec<(PathBuf, String)>) = match m.as_ref() {
            Some(m) => (m.status.watching.clone(), m.status.failed.clone()),
            None => (vec![], vec![]),
        };
        let roots = cfg
            .roots
            .iter()
            .map(|r| RootHealth {
                path: r.path.display().to_string(),
                label: r.label.clone(),
                exists: r.path.exists(),
                watching: watching.contains(&r.path),
                error: failed.iter().find(|(p, _)| p == &r.path).map(|(_, e)| e.clone()).or_else(|| (!r.path.exists()).then(|| "This folder does not exist or is not available.".to_string())),
            })
            .collect();
        let now = now_ms();
        let last = |a: &AtomicI64| Some(a.load(Ordering::Relaxed)).filter(|v| *v > 0);
        ProtectionHealth {
            realtime_enabled: cfg.realtime,
            monitor_running: m.is_some() && !watching.is_empty(),
            roots,
            queue: i.store.stats(now).unwrap_or_default(),
            outbox: i.store.outbox_stats(now).unwrap_or_default(),
            recent_events: i.store.recent_events(30).unwrap_or_default(),
            could_not_check: i.store.failed_jobs(20).unwrap_or_default(),
            rejected_submissions: i.rejected.load(Ordering::Relaxed),
            last_reconcile_at: last(&i.last_reconcile),
            last_file_event_at: last(&i.last_event),
        }
    }
}

impl Drop for ProtectionService {
    fn drop(&mut self) {
        self.stop();
    }
}

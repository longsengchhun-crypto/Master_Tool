//! Application state: settings, scan history and counters, persisted as small JSON files in the app-data directory
//! (writes are atomic: temp file + rename). Nothing here leaves the device.

use chrono::{DateTime, Utc};
use sentrix_core::clamav::ClamEngine;
use sentrix_core::notify::NotifyPrefs;
use sentrix_core::quarantine::Quarantine;
use sentrix_core::queue::JobStore;
use sentrix_core::service::{ProtectionService, WatchRoot};
use sentrix_core::telegram::TokenVault;
use sentrix_core::{ScanReport, Scanner};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const HISTORY_CAP: usize = 2000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub realtime_monitoring: bool,
    /// Any of: "downloads", "desktop", "documents", "removable".
    pub monitored_folders: Vec<String>,
    pub custom_folders: Vec<String>,
    /// "off" | "malicious_only". Never acts on SUSPICIOUS files.
    pub auto_quarantine: String,
    pub allow_restore_suspicious: bool,
    pub notifications: bool,
    pub max_file_size_mb: u32,
    pub archive_max_depth: u32,
    /// Optional anonymous operational telemetry to the control plane. Off by default. Never affects protection.
    pub telemetry_enabled: bool,
    /// "system" | "light" | "dark"
    pub theme: String,
    pub onboarding_done: bool,
    /// Block execution (deny-execute ACL) of files confirmed malicious that were not quarantined. Reversible.
    pub execution_guard: bool,
    /// Download and install new versions by itself (signature-checked), when nothing is being scanned. On by default.
    pub auto_update: bool,
    pub telegram: TelegramSettings,
}

/// Telegram bot notification settings. The bot TOKEN is not here: it lives only in the DPAPI-protected vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TelegramSettings {
    pub chat_id: Option<i64>,
    pub bot_username: Option<String>,
    pub notify: NotifyPrefs,
    /// Accept files the owner sends to their own bot (scanned locally).
    pub accept_submissions: bool,
    /// Telegram Desktop's download folder, as confirmed by the user.
    pub desktop_folder: Option<String>,
    /// Organization policy can forbid these (set from the console policy; the user sees why).
    pub bot_allowed: bool,
    pub account_allowed: bool,
    /// Group Shield master switch. Off by default: groups are only scanned after the owner turns this on.
    pub group_shield: bool,
    /// Organization policy can forbid scanning groups.
    pub groups_allowed: bool,
    /// What the connected personal account is allowed to look at. The account session itself is never in settings.
    pub account: AccountSettings,
    /// This app is linked to the person's chat with the shared SENTRIX bot (the token is in a protected file, never here).
    pub relay_linked: bool,
    pub relay_user: Option<String>,
    pub relay_linked_at: Option<i64>,
}

/// Personal-account monitoring choices. Private chats on; groups, channels and media are opt-in.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AccountSettings {
    pub enabled: bool,
    pub private_chats: bool,
    pub groups: bool,
    pub channels: bool,
    pub media: bool,
    /// Post each result into the person's Scan History group (or Saved Messages) from their own account.
    pub local_reports: bool,
}

impl Default for AccountSettings {
    fn default() -> Self {
        // Groups are on: checking the groups a person is in is the main job. Channels and media stay opt-in.
        AccountSettings { enabled: true, private_chats: true, groups: true, channels: false, media: false, local_reports: true }
    }
}

impl Default for TelegramSettings {
    fn default() -> Self {
        TelegramSettings { chat_id: None, bot_username: None, notify: NotifyPrefs::default(), accept_submissions: false, desktop_folder: None, bot_allowed: true, account_allowed: true, group_shield: false, groups_allowed: true, account: AccountSettings::default(), relay_linked: false, relay_user: None, relay_linked_at: None }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            execution_guard: true,
            auto_update: true,
            telegram: TelegramSettings::default(),
            realtime_monitoring: false, // enabled only after the user completes onboarding and consents
            monitored_folders: vec!["downloads".into()],
            custom_folders: vec![],
            auto_quarantine: "off".into(),
            allow_restore_suspicious: true,
            notifications: true,
            max_file_size_mb: 512,
            archive_max_depth: 3,
            telemetry_enabled: false,
            theme: "system".into(),
            onboarding_done: false,
        }
    }
}

impl Settings {
    /// Reject out-of-range or unknown values rather than silently accepting them.
    pub fn validate(&self) -> Result<(), String> {
        if !matches!(self.auto_quarantine.as_str(), "off" | "malicious_only") {
            return Err("autoQuarantine must be 'off' or 'malicious_only'".into());
        }
        if !matches!(self.theme.as_str(), "system" | "light" | "dark") {
            return Err("theme must be 'system', 'light' or 'dark'".into());
        }
        if !(1..=4096).contains(&self.max_file_size_mb) {
            return Err("maxFileSizeMb must be between 1 and 4096".into());
        }
        if self.archive_max_depth > 8 {
            return Err("archiveMaxDepth must be at most 8".into());
        }
        for f in &self.monitored_folders {
            if !matches!(f.as_str(), "downloads" | "desktop" | "documents" | "removable") {
                return Err(format!("unknown monitored folder '{f}'"));
            }
        }
        if self.custom_folders.len() > 20 {
            return Err("at most 20 custom folders".into());
        }
        for c in &self.custom_folders {
            if !Path::new(c).is_absolute() {
                return Err(format!("custom folder must be an absolute path: {c}"));
            }
        }
        if let Some(f) = &self.telegram.desktop_folder {
            if !Path::new(f).is_absolute() {
                return Err("the Telegram Desktop folder must be an absolute path".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Counters {
    pub last_signature_update: Option<DateTime<Utc>>,
    pub last_full_scan: Option<DateTime<Utc>>,
    pub scans_total: u64,
    /// Random, anonymous id used only to place this install in a staged-rollout cohort for app updates.
    pub install_id: Option<String>,
    /// SHA-256 hashes of SUSPICIOUS files whose warning the user dismissed (only where policy allows). Never MALICIOUS.
    pub dismissed: Vec<String>,
}

pub struct Store {
    dir: PathBuf,
    pub settings: Mutex<Settings>,
    pub counters: Mutex<Counters>,
    pub history: Mutex<Vec<ScanReport>>,
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

impl Store {
    pub fn open(dir: &Path) -> Store {
        let _ = std::fs::create_dir_all(dir);
        let read = |n: &str| std::fs::read(dir.join(n)).ok();
        let settings: Settings = read("settings.json").and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        let counters: Counters = read("counters.json").and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        let history: Vec<ScanReport> = read("history.json").and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        Store { dir: dir.to_path_buf(), settings: Mutex::new(settings), counters: Mutex::new(counters), history: Mutex::new(history) }
    }

    pub fn save_settings(&self) {
        let s = self.settings.lock().unwrap().clone();
        let _ = write_atomic(&self.dir.join("settings.json"), &serde_json::to_vec_pretty(&s).unwrap());
    }

    /// Stable anonymous install id (created on first use).
    pub fn install_id(&self) -> String {
        let id = {
            let mut c = self.counters.lock().unwrap();
            c.install_id.get_or_insert_with(|| uuid::Uuid::new_v4().to_string()).clone()
        };
        self.save_counters();
        id
    }

    pub fn save_counters(&self) {
        let c = self.counters.lock().unwrap().clone();
        let _ = write_atomic(&self.dir.join("counters.json"), &serde_json::to_vec_pretty(&c).unwrap());
    }

    pub fn save_history(&self) {
        let h = self.history.lock().unwrap();
        let _ = write_atomic(&self.dir.join("history.json"), &serde_json::to_vec(&*h).unwrap());
    }

    /// Newest first, capped. Re-scans of the same path replace nothing: history is a log.
    pub fn push_reports(&self, reports: &[ScanReport]) {
        {
            let mut h = self.history.lock().unwrap();
            for r in reports.iter().rev() {
                h.insert(0, r.clone());
            }
            h.truncate(HISTORY_CAP);
        }
        {
            let mut c = self.counters.lock().unwrap();
            c.scans_total += reports.len() as u64;
        }
        self.save_history();
        self.save_counters();
    }

    pub fn set_blocked(&self, report_id: uuid::Uuid, blocked: bool) {
        {
            let mut h = self.history.lock().unwrap();
            if let Some(r) = h.iter_mut().find(|r| r.id == report_id) {
                r.blocked = blocked;
            }
        }
        self.save_history();
    }

    pub fn mark_quarantined(&self, report_id: uuid::Uuid) {
        {
            let mut h = self.history.lock().unwrap();
            if let Some(r) = h.iter_mut().find(|r| r.id == report_id) {
                r.quarantined = true;
            }
        }
        self.save_history();
    }
}

pub struct AppState {
    pub data_dir: PathBuf,
    pub store: Arc<Store>,
    pub scanner: Arc<Scanner>,
    pub clam: Arc<ClamEngine>,
    pub quarantine: Arc<Quarantine>,
    pub portal: Arc<crate::portal::Portal>,
    pub scan_running: AtomicBool,
    pub cancel: Mutex<Option<Arc<AtomicBool>>>,
    /// Durable queue / outbox / events (SQLite) and the background service built on it.
    pub jobs: Arc<JobStore>,
    pub service: Arc<ProtectionService>,
    pub tg_vault: TokenVault,
    /// The device token for the shared SENTRIX bot's relay (protected for this Windows user).
    pub relay_vault: sentrix_core::secret::SecretFile,
    pub endpoints: Option<crate::hosted::Endpoints>,
    pub relay: crate::hosted::RelayState,
    /// Personal Telegram account protection (TDLib). Separate from the bot: either can be off while the other works.
    pub account: Arc<sentrix_core::account_td::TdAccount>,
    /// Hashes already notified this session, to prevent notification spam.
    pub notified: Mutex<HashSet<String>>,
}

impl AppState {
    pub fn begin_scan(&self) -> Result<Arc<AtomicBool>, String> {
        if self.scan_running.swap(true, Ordering::SeqCst) {
            return Err("A scan is already running. Wait for it to finish or cancel it first.".into());
        }
        let flag = Arc::new(AtomicBool::new(false));
        *self.cancel.lock().unwrap() = Some(flag.clone());
        Ok(flag)
    }

    pub fn end_scan(&self) {
        *self.cancel.lock().unwrap() = None;
        self.scan_running.store(false, Ordering::SeqCst);
    }
}

// ---- locations -------------------------------------------------------------------------------------------

/// Where the detection engine lives: explicit override, then next to the installed app, then the dev checkout.
pub fn resolve_clam_dir(exe_dir: &Path) -> PathBuf {
    if let Some(p) = std::env::var_os("SENTRIX_CLAMAV_DIR") {
        return PathBuf::from(p);
    }
    let bundled = exe_dir.join("engine").join("clamav");
    if bundled.join("clamd.exe").is_file() || bundled.join("clamd").is_file() {
        return bundled;
    }
    // Development: <repo>/third_party/clamav, found by walking up from the executable.
    let mut cur = Some(exe_dir);
    while let Some(d) = cur {
        let cand = d.join("third_party").join("clamav");
        if cand.is_dir() {
            return cand;
        }
        cur = d.parent();
    }
    bundled
}

#[cfg(windows)]
pub fn known_folder(kind: &str) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    // SHGetKnownFolderPath is called through a raw extern to avoid pulling in the whole Shell feature set.
    #[repr(C)]
    struct Guid(u32, u16, u16, [u8; 8]);
    #[link(name = "shell32")]
    extern "system" {
        fn SHGetKnownFolderPath(rfid: *const Guid, flags: u32, token: *mut core::ffi::c_void, out: *mut *mut u16) -> i32;
    }
    #[link(name = "ole32")]
    extern "system" {
        fn CoTaskMemFree(p: *mut core::ffi::c_void);
    }
    let id = match kind {
        "downloads" => Guid(0x374DE290, 0x123F, 0x4565, [0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B]),
        "desktop" => Guid(0xB4BFCC3A, 0xDB2C, 0x424C, [0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41]),
        "documents" => Guid(0xFDD39AD0, 0x238F, 0x46AF, [0xAD, 0xB4, 0x6C, 0x85, 0x48, 0x03, 0x69, 0xC7]),
        _ => return None,
    };
    unsafe {
        let mut out: *mut u16 = std::ptr::null_mut();
        if SHGetKnownFolderPath(&id, 0, std::ptr::null_mut(), &mut out) != 0 || out.is_null() {
            return None;
        }
        let mut len = 0;
        while *out.add(len) != 0 {
            len += 1;
        }
        let p = PathBuf::from(std::ffi::OsString::from_wide(std::slice::from_raw_parts(out, len)));
        CoTaskMemFree(out as *mut _);
        Some(p)
    }
}

#[cfg(not(windows))]
pub fn known_folder(kind: &str) -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    Some(match kind {
        "downloads" => home.join("Downloads"),
        "desktop" => home.join("Desktop"),
        "documents" => home.join("Documents"),
        _ => return None,
    })
}

/// Drive roots by type: (removable, fixed). Windows only; empty elsewhere.
#[cfg(windows)]
pub fn drive_roots() -> (Vec<PathBuf>, Vec<PathBuf>) {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_FIXED: u32 = 3;
    let (mut removable, mut fixed) = (vec![], vec![]);
    let mask = unsafe { GetLogicalDrives() };
    for i in 0..26u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let letter = (b'A' + i as u8) as char;
        let root = format!("{letter}:\\");
        let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
        match unsafe { GetDriveTypeW(wide.as_ptr()) } {
            DRIVE_REMOVABLE => removable.push(PathBuf::from(root)),
            DRIVE_FIXED => fixed.push(PathBuf::from(root)),
            _ => {}
        }
    }
    (removable, fixed)
}

#[cfg(not(windows))]
pub fn drive_roots() -> (Vec<PathBuf>, Vec<PathBuf>) {
    (vec![], vec![PathBuf::from("/")])
}

/// Resolve the user's monitoring choices to concrete folders. Missing folders are dropped here and surfaced by the
/// monitor status (it reports anything it failed to watch).
pub fn monitored_paths(s: &Settings) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = watch_roots(s).into_iter().map(|r| r.path).collect();
    out.sort();
    out.dedup();
    out
}

/// The folders to watch, each with the label that becomes the file's "Source" in reports. A Telegram Desktop folder
/// nested inside Downloads keeps its own, more specific label (the service picks the longest matching root).
pub fn watch_roots(s: &Settings) -> Vec<WatchRoot> {
    watch_roots_with(s, &|k| known_folder(k), &|| drive_roots().0)
}

pub fn watch_roots_with(s: &Settings, known: &dyn Fn(&str) -> Option<PathBuf>, removable: &dyn Fn() -> Vec<PathBuf>) -> Vec<WatchRoot> {
    let mut out: Vec<WatchRoot> = Vec::new();
    let mut add = |path: PathBuf, label: &str| {
        if !out.iter().any(|r| r.path == path) {
            out.push(WatchRoot { path, label: label.to_string() });
        }
    };
    for k in &s.monitored_folders {
        match k.as_str() {
            "removable" => removable().into_iter().for_each(|p| add(p, "Removable drive")),
            "downloads" => known(k).into_iter().for_each(|p| add(p, "Downloads folder")),
            "desktop" => known(k).into_iter().for_each(|p| add(p, "Desktop")),
            "documents" => known(k).into_iter().for_each(|p| add(p, "Documents")),
            _ => {}
        }
    }
    s.custom_folders.iter().for_each(|c| add(PathBuf::from(c), "Custom folder"));
    if s.telegram.desktop_folder.is_some() {
        // The user's explicit Telegram Desktop folder always wins its own label, even if it is also a custom folder.
        let p = PathBuf::from(s.telegram.desktop_folder.clone().unwrap());
        out.retain(|r| r.path != p);
        out.push(WatchRoot { path: p, label: "Telegram Desktop".into() });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_settings_are_valid_and_conservative() {
        let s = Settings::default();
        assert!(s.validate().is_ok());
        assert!(!s.realtime_monitoring, "real-time must be opt-in");
        assert_eq!(s.auto_quarantine, "off", "automatic quarantine must be opt-in");
        assert!(!s.telemetry_enabled);
        assert!(s.auto_update, "updates install by themselves unless the person turns that off");
    }

    #[test]
    fn invalid_settings_are_rejected() {
        let mut s = Settings::default();
        s.auto_quarantine = "everything".into();
        assert!(s.validate().is_err());
        let mut s = Settings::default();
        s.monitored_folders = vec!["system32".into()];
        assert!(s.validate().is_err());
        let mut s = Settings::default();
        s.custom_folders = vec!["relative/path".into()];
        assert!(s.validate().is_err());
        let mut s = Settings::default();
        s.max_file_size_mb = 0;
        assert!(s.validate().is_err());
    }

    #[test]
    fn watch_roots_carry_source_labels_and_telegram_wins_its_own_label() {
        let known = |k: &str| match k {
            "downloads" => Some(PathBuf::from("C:\\U\\Downloads")),
            "desktop" => Some(PathBuf::from("C:\\U\\Desktop")),
            _ => None,
        };
        let mut s = Settings::default();
        s.monitored_folders = vec!["downloads".into(), "desktop".into(), "removable".into(), "documents".into()];
        s.custom_folders = vec!["D:\\Shared".into(), "C:\\U\\Downloads\\Telegram Desktop".into()];
        s.telegram.desktop_folder = Some("C:\\U\\Downloads\\Telegram Desktop".into());
        let roots = watch_roots_with(&s, &known, &|| vec![PathBuf::from("E:\\")]);
        let label = |p: &str| roots.iter().find(|r| r.path == PathBuf::from(p)).map(|r| r.label.clone());
        assert_eq!(label("C:\\U\\Downloads").as_deref(), Some("Downloads folder"));
        assert_eq!(label("C:\\U\\Desktop").as_deref(), Some("Desktop"));
        assert_eq!(label("E:\\").as_deref(), Some("Removable drive"));
        assert_eq!(label("D:\\Shared").as_deref(), Some("Custom folder"));
        assert_eq!(label("C:\\U\\Downloads\\Telegram Desktop").as_deref(), Some("Telegram Desktop"));
        assert_eq!(roots.iter().filter(|r| r.path == PathBuf::from("C:\\U\\Downloads\\Telegram Desktop")).count(), 1, "no duplicate root");
        assert_eq!(label("C:\\U\\Documents"), None, "a folder that could not be resolved is simply absent");
    }

    #[test]
    fn settings_from_the_previous_release_still_load() {
        // A settings.json written before Phase 2 has no `executionGuard` or `telegram` keys.
        let old = r#"{"realtimeMonitoring":true,"monitoredFolders":["downloads"],"customFolders":[],"autoQuarantine":"off","allowRestoreSuspicious":true,"notifications":true,"maxFileSizeMb":512,"archiveMaxDepth":3,"telemetryEnabled":false,"theme":"dark","onboardingDone":true}"#;
        let s: Settings = serde_json::from_str(old).unwrap();
        assert!(s.realtime_monitoring && s.onboarding_done);
        assert!(s.execution_guard && s.telegram.bot_allowed && s.telegram.chat_id.is_none() && !s.telegram.accept_submissions);
        assert!(s.validate().is_ok());
    }

    #[test]
    fn telegram_defaults_are_private_by_default() {
        let t = TelegramSettings::default();
        assert!(!t.accept_submissions, "submissions are opt-in");
        assert!(t.chat_id.is_none() && t.desktop_folder.is_none());
        assert!(!t.notify.clean_scans && !t.notify.unable_to_verify, "the noisy reports are opt-in");
        let mut s = Settings::default();
        s.telegram.desktop_folder = Some("relative\\telegram".into());
        assert!(s.validate().is_err());
    }

    #[test]
    fn store_roundtrips_and_caps_history() {
        let d = tempfile::tempdir().unwrap();
        let st = Store::open(d.path());
        st.settings.lock().unwrap().theme = "dark".into();
        st.save_settings();
        let st2 = Store::open(d.path());
        assert_eq!(st2.settings.lock().unwrap().theme, "dark");
    }

    #[test]
    fn corrupt_settings_fall_back_to_defaults() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("settings.json"), b"{not json").unwrap();
        let st = Store::open(d.path());
        assert_eq!(st.settings.lock().unwrap().auto_quarantine, "off");
    }

    #[cfg(windows)]
    #[test]
    fn known_folders_resolve_on_windows() {
        for k in ["downloads", "desktop", "documents"] {
            let p = known_folder(k).unwrap_or_else(|| panic!("{k} did not resolve"));
            assert!(p.is_absolute(), "{p:?}");
        }
    }
}

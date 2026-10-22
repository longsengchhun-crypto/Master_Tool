//! Tauri commands: the only surface the UI can call. Each validates its inputs; the UI is never trusted with raw
//! filesystem access (no generic fs plugin is enabled).

use crate::state::*;
use chrono::{DateTime, Utc};
use sentrix_core::quarantine::{ListedRecord, RestoreOptions};
use sentrix_core::scanner::{BatchCounts, EngineStatus, Progress};
use sentrix_core::{report, Limits, ScanOptions, ScanReport, Scanner, Verdict};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_notification::NotificationExt;

pub type Shared<'a> = State<'a, Arc<AppState>>;
pub type Res<T> = Result<T, String>;

// ---- status ------------------------------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RealtimeStatus {
    /// "active" | "off" | "error"
    pub state: String,
    pub watching: Vec<String>,
    pub failed: Vec<(String, String)>,
    pub detail: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub malicious_files: usize,
    pub suspicious_files: usize,
    pub quarantined: usize,
    pub scans_total: u64,
    pub last_scan_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Protection {
    /// "protected" | "attention" | "at_risk"
    pub level: String,
    pub headline: String,
    pub reasons: Vec<String>,
}

/// What this build actually does. The UI shows these separately so scanning, warning and enforcement are never conflated.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    pub file_scanning: bool,
    pub folder_monitoring: bool,
    /// A kernel-level pre-execution filter. NOT available: it needs a signed driver.
    pub execution_blocking: bool,
    /// The user-mode deny-execute guard for confirmed-malicious files (reversible).
    pub execution_guard: bool,
    pub signature_verification: bool,
    pub platform: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStatus {
    pub version: String,
    pub engine: EngineStatus,
    pub realtime: RealtimeStatus,
    pub stats: Stats,
    pub protection: Protection,
    pub last_signature_update: Option<DateTime<Utc>>,
    pub last_full_scan: Option<DateTime<Utc>>,
    pub settings: Settings,
    pub capabilities: Capabilities,
    pub data_dir: String,
    pub scan_running: bool,
    /// Name of the organization whose policy controls protection settings, if this device is enrolled.
    pub managed_by: Option<String>,
    /// Authenticode status of THIS app, so the UI never claims a verified publisher it does not have.
    pub publisher: sentrix_core::SignatureInfo,
    pub dismissed_hashes: Vec<String>,
}

/// WinVerifyTrust on our own executable is slow-ish and cannot change while running, so it is computed once.
fn own_signature() -> &'static sentrix_core::SignatureInfo {
    static SIG: std::sync::OnceLock<sentrix_core::SignatureInfo> = std::sync::OnceLock::new();
    SIG.get_or_init(|| match std::env::current_exe() {
        Ok(p) => sentrix_core::signature::verify(&p),
        Err(_) => sentrix_core::SignatureInfo { state: "unknown".into(), detail: Some("Could not locate the application file.".into()) },
    })
}

pub fn realtime_status(st: &AppState) -> RealtimeStatus {
    let s = st.store.settings.lock().unwrap().clone();
    let h = st.service.health();
    let watching: Vec<String> = h.roots.iter().filter(|r| r.watching).map(|r| r.path.clone()).collect();
    let failed: Vec<(String, String)> = h.roots.iter().filter(|r| !r.watching).filter_map(|r| r.error.clone().map(|e| (r.path.clone(), e))).collect();
    if !s.realtime_monitoring {
        return RealtimeStatus { state: "off".into(), watching: vec![], failed: vec![], detail: "Real-time protection is turned off. Files are only scanned when you scan them.".into() };
    }
    if !watching.is_empty() && h.monitor_running {
        let detail = if failed.is_empty() { "New files in the watched folders are scanned after they finish downloading.".to_string() } else { "Some folders could not be watched; see details.".to_string() };
        RealtimeStatus { state: "active".into(), watching, failed, detail }
    } else {
        let detail = if h.roots.is_empty() { "Real-time protection is on but no folder is selected, so nothing is being watched.".to_string() } else { "Real-time protection is on but none of the selected folders could be watched.".to_string() };
        RealtimeStatus { state: "error".into(), watching: vec![], failed, detail }
    }
}
pub fn compute_stats(st: &AppState) -> Stats {
    let h = st.store.history.lock().unwrap();
    let mut mal = std::collections::HashSet::new();
    let mut sus = std::collections::HashSet::new();
    let dismissed: std::collections::HashSet<String> = st.store.counters.lock().unwrap().dismissed.iter().cloned().collect();
    // Count distinct files, not scans: identity is the content hash (or the path when the file was unreadable).
    let key = |r: &ScanReport| if r.file.sha256.is_empty() { r.file.path.display().to_string() } else { r.file.sha256.clone() };
    for r in h.iter() {
        match r.verdict {
            Verdict::Malicious => {
                mal.insert(key(r));
            }
            Verdict::Suspicious if !dismissed.contains(&r.file.sha256) => {
                sus.insert(key(r));
            }
            _ => {}
        }
    }
    let quarantined = st.quarantine.list().map(|l| l.iter().filter(|x| x.record.state == sentrix_core::quarantine::State::Quarantined).count()).unwrap_or(0);
    Stats {
        malicious_files: mal.len(),
        suspicious_files: sus.len(),
        quarantined,
        scans_total: st.store.counters.lock().unwrap().scans_total,
        last_scan_at: h.first().map(|r| r.finished_at),
    }
}

/// Protection is derived from facts. It can only say "protected" when the engine is running with fresh signatures AND
/// real-time monitoring is active; anything else is surfaced with the real reason.
pub fn compute_protection(engine: &EngineStatus, rt: &RealtimeStatus, queue: &sentrix_core::queue::QueueStats) -> Protection {
    let mut reasons = Vec::new();
    let mut level = "protected";
    match engine.state.as_str() {
        "running" => {}
        "degraded" => {
            level = "attention";
            reasons.push(engine.detail.clone());
        }
        "stopped" => {
            level = "attention";
            reasons.push(engine.detail.clone());
        }
        _ => {
            level = "at_risk";
            reasons.push(engine.detail.clone());
        }
    }
    match rt.state.as_str() {
        "active" => {
            if !rt.failed.is_empty() && level == "protected" {
                level = "attention";
                reasons.push("Some watched folders are unavailable.".into());
            }
        }
        "off" => {
            if level == "protected" {
                level = "attention";
            }
            reasons.push("Real-time protection is off.".into());
        }
        _ => {
            if level == "protected" {
                level = "attention";
            }
            reasons.push(rt.detail.clone());
        }
    }
    if queue.stuck > 0 {
        if level == "protected" {
            level = "attention";
        }
        reasons.push(format!("{} scan(s) appear to be stuck.", queue.stuck));
    }
    if queue.failed > 0 {
        if level == "protected" {
            level = "attention";
        }
        reasons.push(format!("{} file(s) could not be checked. They are NOT known to be safe: see Real-Time Protection.", queue.failed));
    }
    let headline = match level {
        "protected" => "Protection is active",
        "attention" => "Protection needs attention",
        _ => "Files cannot be verified right now",
    };
    Protection { level: level.into(), headline: headline.into(), reasons }
}

#[tauri::command]
pub async fn app_status(app: AppHandle, state: Shared<'_>) -> Res<AppStatus> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let engine = st.scanner.engine_status();
        let realtime = realtime_status(&st);
        let mut protection = compute_protection(&engine, &realtime, &st.jobs.stats(sentrix_core::queue::now_ms()).unwrap_or_default());
        if let Some(why) = crate::account::attention(&st.account.view()) {
            if protection.level == "protected" {
                protection.level = "attention".into();
                protection.headline = "Protection needs attention".into();
            }
            protection.reasons.push(why.into());
        }
        let c = st.store.counters.lock().unwrap().clone();
        AppStatus {
            version: app.package_info().version.to_string(),
            stats: compute_stats(&st),
            protection,
            engine,
            realtime,
            last_signature_update: c.last_signature_update,
            last_full_scan: c.last_full_scan,
            settings: st.store.settings.lock().unwrap().clone(),
            capabilities: Capabilities {
                file_scanning: true,
                folder_monitoring: cfg!(windows),
                execution_blocking: false,
                execution_guard: cfg!(windows),
                signature_verification: cfg!(windows),
                platform: std::env::consts::OS.to_string(),
            },
            data_dir: st.data_dir.display().to_string(),
            scan_running: st.scan_running.load(Ordering::SeqCst),
            managed_by: st.portal.org_name(),
            publisher: own_signature().clone(),
            dismissed_hashes: st.store.counters.lock().unwrap().dismissed.clone(),
        }
    })
    .await
    .map_err(|e| e.to_string())
}

// ---- engine & updates ----------------------------------------------------------------------------------------

#[tauri::command]
pub async fn start_engine(state: Shared<'_>) -> Res<EngineStatus> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        st.clam.start().map_err(|e| e.to_string())?;
        Ok(st.scanner.engine_status())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateOutcome {
    pub ok: bool,
    pub message: String,
    pub engine: EngineStatus,
}

/// Refresh malware signatures (blocking). Shared by the UI command and the console's `intel_update` request.
pub fn do_update_protection(st: &AppState) -> UpdateOutcome {
    match st.clam.update_signatures() {
        Ok(_) => {
            st.store.counters.lock().unwrap().last_signature_update = Some(Utc::now());
            st.store.save_counters();
            let restart = if st.clam.ping().is_ok() { st.clam.reload().map_err(|e| e.to_string()) } else { st.clam.start().map_err(|e| e.to_string()) };
            st.scanner.clear_cache();
            let engine = st.scanner.engine_status();
            match restart {
                Ok(()) => UpdateOutcome { ok: true, message: "Protection is up to date.".into(), engine },
                Err(e) => UpdateOutcome { ok: false, message: format!("Signatures were updated but the engine could not be started: {e}"), engine },
            }
        }
        Err(e) => UpdateOutcome { ok: false, message: format!("Update failed: {e}"), engine: st.scanner.engine_status() },
    }
}

/// Updates *malware signatures* only (ClamAV's freshclam verifies its signed .cvd files). Application updates are a
/// separate channel.
#[tauri::command]
pub async fn update_protection(app: AppHandle, state: Shared<'_>) -> Res<UpdateOutcome> {
    let st = state.inner().clone();
    let _ = app.emit("protection-update", "started");
    let res = tauri::async_runtime::spawn_blocking(move || do_update_protection(&st)).await.map_err(|e| e.to_string());
    let _ = app.emit("protection-update", "finished");
    res
}

// ---- scanning --------------------------------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchOut {
    /// Everything for small scans; only files that are not "clean and complete" for large ones (see `reports_truncated`).
    pub reports: Vec<ScanReport>,
    pub reports_truncated: bool,
    pub counts: BatchCounts,
    pub skipped: Vec<(String, String)>,
    pub skipped_total: usize,
    pub complete: bool,
    pub cancelled: bool,
    pub auto_quarantined: usize,
}

fn validate_scan_paths(paths: &[String]) -> Res<Vec<PathBuf>> {
    if paths.is_empty() {
        return Err("Choose at least one file or folder to scan.".into());
    }
    if paths.len() > 10_000 {
        return Err("Too many items selected at once.".into());
    }
    let mut out = Vec::new();
    for p in paths {
        let pb = PathBuf::from(p);
        if !pb.is_absolute() {
            return Err(format!("Not an absolute path: {p}"));
        }
        if std::fs::symlink_metadata(&pb).is_err() {
            return Err(format!("Cannot access: {p}"));
        }
        out.push(pb);
    }
    Ok(out)
}

/// Apply the user's automatic-quarantine policy. Only MALICIOUS verdicts from a signature engine qualify, never
/// heuristics, and only when the policy is explicitly enabled.
pub fn maybe_auto_quarantine(st: &AppState, r: &mut ScanReport) -> bool {
    let policy = st.store.settings.lock().unwrap().auto_quarantine.clone();
    if policy != "malicious_only" || r.verdict != Verdict::Malicious || r.file.sha256.is_empty() {
        return false;
    }
    match st.quarantine.quarantine(&r.file.path, Some(&r.file.sha256), r.verdict, &r.summary, &r.file.detected_type) {
        Ok(_) => {
            r.quarantined = true;
            true
        }
        Err(_) => false,
    }
}

pub(crate) fn notify_local(app: &AppHandle, st: &AppState, r: &ScanReport) {
    if !st.store.settings.lock().unwrap().notifications || !matches!(r.verdict, Verdict::Malicious | Verdict::Suspicious) {
        return;
    }
    let key = if r.file.sha256.is_empty() { r.file.path.display().to_string() } else { r.file.sha256.clone() };
    if !st.notified.lock().unwrap().insert(key) {
        return;
    }
    let (title, body) = match (r.verdict, r.quarantined) {
        (Verdict::Malicious, true) => ("Malicious file quarantined", format!("{} was identified as malicious and moved to quarantine.", r.file.name)),
        (Verdict::Malicious, false) => ("Malicious file detected", format!("{} was identified as malicious. Do not open it.", r.file.name)),
        _ => ("Suspicious file found", format!("{} has indicators that need a closer look. Do not open it until verified.", r.file.name)),
    };
    let _ = app.notification().builder().title(title).body(body).show();
}

pub(crate) async fn run_scan(app: AppHandle, state: Arc<AppState>, roots: Vec<PathBuf>, kind: &'static str, force: bool) -> Res<BatchOut> {
    let flag = state.begin_scan()?;
    let app2 = app.clone();
    let st = state.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        // SENTRIX's own data (encrypted quarantine, history) is never worth scanning and would only add noise.
        let opts = ScanOptions { cancel: flag, use_cache: !force, exclude: vec![st.data_dir.clone()], ..Default::default() };
        // Progress events are throttled: a fast scan can finish thousands of files per second.
        let last_emit = AtomicU64::new(0);
        let started = std::time::Instant::now();
        let progress = move |p: Progress| {
            let now = started.elapsed().as_millis() as u64;
            let prev = last_emit.load(Ordering::Relaxed);
            if (now.saturating_sub(prev) >= 150 || !p.discovering && p.done >= p.discovered) && last_emit.compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                let _ = app2.emit("scan-progress", p);
            }
        };
        let auto_q = AtomicUsize::new(0);
        // Auto-quarantine is applied as each report arrives, so a long scan acts on a threat immediately.
        let on_report = |r: &mut ScanReport| {
            if maybe_auto_quarantine(&st, r) {
                auto_q.fetch_add(1, Ordering::Relaxed);
            }
        };
        let scan_started = Utc::now();
        let batch = st.scanner.scan_paths(&roots, &opts, 2, &on_report, &progress);
        st.store.push_reports(&batch.reports);
        // Console reporting is metadata-only and requires BOTH enrollment and the user's own telemetry switch.
        if st.portal.is_enrolled() && st.store.settings.lock().unwrap().telemetry_enabled {
            let (p, reports, c) = (st.portal.clone(), batch.reports.clone(), batch.counts.clone());
            let k = if kind == "full" { "full" } else if roots.len() == 1 && roots[0].is_file() { "file" } else { "folder" };
            let complete = batch.complete;
            std::thread::spawn(move || p.report_scan(k, scan_started, c.total, c.unable_to_verify, complete, &reports));
        }
        if kind == "full" && !batch.cancelled {
            st.store.counters.lock().unwrap().last_full_scan = Some(Utc::now());
            st.store.save_counters();
        }
        BatchOut {
            reports: batch.reports,
            reports_truncated: batch.reports_truncated,
            counts: batch.counts,
            skipped: batch.skipped.into_iter().map(|(p, e)| (p.display().to_string(), e)).collect(),
            skipped_total: batch.skipped_total,
            complete: batch.complete,
            cancelled: batch.cancelled,
            auto_quarantined: auto_q.load(Ordering::Relaxed),
        }
    })
    .await
    .map_err(|e| e.to_string());
    state.end_scan();
    let out = result?;
    // Notify only for files that need attention, once each. A large scan can surface many; notify() de-duplicates by hash.
    for r in out.reports.iter().filter(|r| matches!(r.verdict, Verdict::Malicious | Verdict::Suspicious)).take(10) {
        notify_local(&app, &state, r);
    }
    Ok(out)
}

#[tauri::command]
pub async fn scan_paths(app: AppHandle, state: Shared<'_>, paths: Vec<String>, force: Option<bool>) -> Res<BatchOut> {
    let roots = validate_scan_paths(&paths)?;
    run_scan(app, state.inner().clone(), roots, "paths", force.unwrap_or(false)).await
}

/// Scans every fixed drive. This can take hours on a large disk; it can be cancelled at any time and reports exactly
/// what it could not read.
#[tauri::command]
pub async fn full_system_scan(app: AppHandle, state: Shared<'_>) -> Res<BatchOut> {
    let roots = drive_roots().1;
    if roots.is_empty() {
        return Err("No fixed drives were found to scan.".into());
    }
    run_scan(app, state.inner().clone(), roots, "full", false).await
}

#[tauri::command]
pub fn cancel_scan(state: Shared<'_>) -> bool {
    if let Some(f) = state.cancel.lock().unwrap().as_ref() {
        f.store(true, Ordering::SeqCst);
        true
    } else {
        false
    }
}

// ---- history & reports ---------------------------------------------------------------------------------------

#[tauri::command]
pub fn list_history(state: Shared<'_>, limit: Option<usize>) -> Vec<ScanReport> {
    let h = state.store.history.lock().unwrap();
    h.iter().take(limit.unwrap_or(500).min(2000)).cloned().collect()
}

#[tauri::command]
pub fn get_report(state: Shared<'_>, id: String) -> Res<ScanReport> {
    let id = uuid::Uuid::parse_str(&id).map_err(|_| "Invalid report id".to_string())?;
    state.store.history.lock().unwrap().iter().find(|r| r.id == id).cloned().ok_or_else(|| "Report not found".into())
}

#[tauri::command]
pub fn report_text(state: Shared<'_>, id: String) -> Res<String> {
    get_report(state, id).map(|r| report::to_text(&r))
}

#[tauri::command]
pub fn export_report(state: Shared<'_>, id: String, format: String, path: String) -> Res<()> {
    let r = get_report(state, id)?;
    let p = PathBuf::from(&path);
    if !p.is_absolute() {
        return Err("Export path must be absolute.".into());
    }
    let body = match format.as_str() {
        "json" => report::to_json(&r),
        "text" => report::to_text(&r),
        _ => return Err("Unknown export format.".into()),
    };
    std::fs::write(&p, body).map_err(|e| format!("Could not write the report: {e}"))
}

#[tauri::command]
pub fn clear_history(state: Shared<'_>) {
    state.store.history.lock().unwrap().clear();
    state.store.save_history();
    state.notified.lock().unwrap().clear();
}

// ---- quarantine ------------------------------------------------------------------------------------------------

#[tauri::command]
pub async fn quarantine_report(state: Shared<'_>, id: String) -> Res<()> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let rid = uuid::Uuid::parse_str(&id).map_err(|_| "Invalid report id".to_string())?;
        let r = st.store.history.lock().unwrap().iter().find(|r| r.id == rid).cloned().ok_or("Report not found")?;
        if r.file.sha256.is_empty() {
            return Err("This file could not be read, so SENTRIX cannot move it. Your security software may already have handled it.".to_string());
        }
        let reason = format!("{} {}", r.verdict.label(), r.summary);
        st.quarantine.quarantine(&r.file.path, Some(&r.file.sha256), r.verdict, &reason, &r.file.detected_type).map_err(|e| e.to_string())?;
        st.store.mark_quarantined(rid);
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Permanently delete the scanned original, with a guard: the file on disk must still be byte-identical to what was
/// scanned (a swapped file is refused), must be a regular file, and must not be a link.
#[tauri::command]
pub async fn delete_scanned_file(state: Shared<'_>, id: String) -> Res<()> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        use sentrix_core::hash::sha256_file;
        let rid = uuid::Uuid::parse_str(&id).map_err(|_| "Invalid report id".to_string())?;
        let r = st.store.history.lock().unwrap().iter().find(|r| r.id == rid).cloned().ok_or("Report not found")?;
        if r.file.sha256.is_empty() {
            return Err("This file could not be read when it was scanned, so SENTRIX will not delete it.".to_string());
        }
        let m = std::fs::symlink_metadata(&r.file.path).map_err(|_| "The file no longer exists.".to_string())?;
        if !m.is_file() || m.file_type().is_symlink() {
            return Err("Only regular files can be deleted from here.".into());
        }
        if sha256_file(&r.file.path).map_err(|e| format!("Could not read the file: {e}"))? != r.file.sha256 {
            return Err("The file changed after it was scanned. Scan it again before deleting.".into());
        }
        std::fs::remove_file(&r.file.path).map_err(|e| format!("Could not delete the file: {e}"))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Dismiss the warning for a SUSPICIOUS file (a user-judged false positive). Never allowed for MALICIOUS, and only
/// where the active policy lets users override suspicious findings.
#[tauri::command]
pub fn dismiss_warning(state: Shared<'_>, id: String) -> Res<()> {
    let rid = uuid::Uuid::parse_str(&id).map_err(|_| "Invalid report id".to_string())?;
    let r = state.store.history.lock().unwrap().iter().find(|r| r.id == rid).cloned().ok_or("Report not found")?;
    if r.verdict != Verdict::Suspicious {
        return Err("Only suspicious findings can be dismissed. Malicious files and unverified files cannot.".into());
    }
    if !state.store.settings.lock().unwrap().allow_restore_suspicious {
        return Err("Your organization does not allow dismissing warnings.".into());
    }
    if r.file.sha256.is_empty() {
        return Err("This file has no recorded hash.".into());
    }
    {
        let mut c = state.store.counters.lock().unwrap();
        if !c.dismissed.contains(&r.file.sha256) {
            c.dismissed.push(r.file.sha256.clone());
        }
    }
    state.store.save_counters();
    Ok(())
}

#[tauri::command]
pub fn list_quarantine(state: Shared<'_>) -> Res<Vec<ListedRecord>> {
    state.quarantine.list().map_err(|e| e.to_string())
}

/// `dest` defaults to the file's original folder. Restoring a MALICIOUS file requires `confirm_malicious`.
#[tauri::command]
pub async fn restore_quarantine(state: Shared<'_>, id: String, confirm_malicious: bool, dest: Option<String>) -> Res<String> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let rec = st.quarantine.list().map_err(|e| e.to_string())?.into_iter().find(|r| r.record.id.to_string() == id).ok_or("Quarantine record not found")?;
        let dir = match dest {
            Some(d) => PathBuf::from(d),
            None => rec.record.original_path.parent().map(Path::to_path_buf).ok_or("The original folder is unknown; choose where to restore.")?,
        };
        let allow = st.store.settings.lock().unwrap().allow_restore_suspicious;
        st.quarantine
            .restore(&id, &dir, RestoreOptions { confirm_malicious, allow_suspicious: allow })
            .map(|p| p.display().to_string())
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub fn delete_quarantine(state: Shared<'_>, id: String) -> Res<()> {
    state.quarantine.delete(&id).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn verify_quarantine_audit(state: Shared<'_>) -> Option<usize> {
    state.quarantine.verify_audit()
}

/// Opens the containing folder with the file selected. The file itself is never launched.
#[tauri::command]
pub fn reveal_in_folder(path: String) -> Res<()> {
    let p = PathBuf::from(&path);
    if !p.is_absolute() || std::fs::symlink_metadata(&p).is_err() {
        return Err("That location no longer exists.".into());
    }
    if path.contains('"') {
        return Err("Invalid path.".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        std::process::Command::new("explorer.exe").raw_arg(format!("/select,\"{path}\"")).spawn().map_err(|e| e.to_string())?;
    }
    #[cfg(not(windows))]
    {
        let dir = p.parent().unwrap_or(&p);
        std::process::Command::new("xdg-open").arg(dir).spawn().map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ---- settings & monitoring ----------------------------------------------------------------------------------

#[tauri::command]
pub fn get_settings(state: Shared<'_>) -> Settings {
    state.store.settings.lock().unwrap().clone()
}

#[tauri::command]
pub fn set_settings(app: AppHandle, state: Shared<'_>, settings: Settings) -> Res<RealtimeStatus> {
    settings.validate()?;
    // While enrolled, protection settings belong to the organization's policy. The user can read them and can leave
    // management at any time, but cannot silently drift from policy.
    if state.portal.is_enrolled() {
        let current = state.store.settings.lock().unwrap().clone();
        if crate::sync::managed_view(&current) != crate::sync::managed_view(&settings) {
            let org = state.portal.org_name().unwrap_or_else(|| "your organization".into());
            return Err(format!("These protection settings are managed by {org}. To change them yourself, leave management under Account and License."));
        }
    }
    {
        let mut l = state.scanner.limits();
        l.max_scan_bytes = settings.max_file_size_mb as u64 * 1024 * 1024;
        l.archive_max_depth = settings.archive_max_depth;
        state.scanner.set_limits(l);
        let mut s = state.store.settings.lock().unwrap();
        *s = settings;
    }
    state.store.save_settings();
    apply_monitoring(&app, state.inner());
    Ok(realtime_status(&state))
}

/// (Re)apply settings to the protection service (monitor, queue policy, Telegram). Idempotent.
pub fn apply_monitoring(app: &AppHandle, st: &Arc<AppState>) {
    crate::protection::apply(app, st);
}

#[tauri::command]
pub fn complete_onboarding(app: AppHandle, state: Shared<'_>, enable_realtime: bool) -> Res<()> {
    {
        let mut s = state.store.settings.lock().unwrap();
        s.onboarding_done = true;
        s.realtime_monitoring = enable_realtime;
    }
    state.store.save_settings();
    apply_monitoring(&app, state.inner());
    Ok(())
}

// ---- application updates (separate from malware signatures) ---------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub configured: bool,
    pub available: bool,
    pub current: String,
    pub version: Option<String>,
    pub notes: Option<String>,
    pub message: String,
}

/// Where new versions are announced when the device is not managed by a console: the release feed published with every
/// release (a JSON file next to the installer). The signature, not the address, is what makes an update trustworthy.
const PUBLIC_FEED: &str = "https://github.com/longsengchhun-crypto/Master_Tool/releases/latest/download/latest.json";

fn update_base(st: &AppState) -> Option<String> {
    option_env!("SENTRIX_UPDATE_BASE_URL").map(String::from).or_else(|| st.portal.status().portal_url)
}

/// A managed device asks its console (which can stage a rollout); everything else reads the public release feed.
fn feed_url(console: Option<String>, version: &str, install_id: &str) -> Result<String, String> {
    match console {
        Some(base) => {
            let base = crate::portal::validate_portal_url(&base)?;
            Ok(format!("{base}/api/updates/windows-x64/{version}?id={install_id}"))
        }
        None => Ok(option_env!("SENTRIX_UPDATE_FEED_URL").unwrap_or(PUBLIC_FEED).to_string()),
    }
}

/// The updater verifies the release's minisign signature against the public key compiled into this app before it
/// installs anything. The server (or a CDN, or a network attacker) cannot make it accept an unsigned or re-signed build.
pub(crate) fn updater_for(app: &AppHandle, st: &AppState) -> Res<tauri_plugin_updater::Updater> {
    use tauri_plugin_updater::UpdaterExt;
    let url = feed_url(update_base(st), &app.package_info().version.to_string(), &st.store.install_id())?;
    let url: tauri::Url = url.parse().map_err(|_| "The update address is not valid.".to_string())?;
    app.updater_builder().endpoints(vec![url]).map_err(|e| e.to_string())?.build().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn check_update(app: AppHandle, state: Shared<'_>) -> Res<UpdateInfo> {
    let current = app.package_info().version.to_string();
    let updater = match updater_for(&app, &state) {
        Ok(u) => u,
        Err(m) => return Ok(UpdateInfo { configured: false, available: false, current, version: None, notes: None, message: m }),
    };
    match updater.check().await {
        Ok(Some(u)) => Ok(UpdateInfo { configured: true, available: true, current, version: Some(u.version.clone()), notes: u.body.clone(), message: format!("SENTRIX {} is available.", u.version) }),
        Ok(None) => Ok(UpdateInfo { configured: true, available: false, current, version: None, notes: None, message: "You have the latest version.".into() }),
        Err(e) => Err(format!("Could not check for updates: {e}")),
    }
}

/// Download, verify the signature, install, and restart. A bad signature aborts before anything is installed.
#[tauri::command]
pub async fn install_update(app: AppHandle, state: Shared<'_>) -> Res<()> {
    let updater = updater_for(&app, &state)?;
    let update = updater.check().await.map_err(|e| e.to_string())?.ok_or("No update is available.")?;
    if let Err(e) = update.download_and_install(|_, _| {}, || {}).await {
        let msg = format!("The update was not installed: {e}");
        // Operational health, shared with the console only for enrolled devices that allowed health reporting.
        if state.portal.is_enrolled() && state.store.settings.lock().unwrap().telemetry_enabled {
            let (p, m) = (state.portal.clone(), msg.clone());
            std::thread::spawn(move || p.event("update_failed", "warning", &m));
        }
        return Err(msg);
    }
    app.restart();
}

// ---- account & console -----------------------------------------------------------------------------------------

#[tauri::command]
pub fn account_status(state: Shared<'_>) -> crate::portal::AccountStatus {
    state.portal.status()
}

#[tauri::command]
pub async fn enroll_device(app: AppHandle, state: Shared<'_>, portal_url: String, code: String) -> Res<crate::portal::AccountStatus> {
    let (st, app2) = (state.inner().clone(), app.clone());
    tauri::async_runtime::spawn_blocking(move || {
        let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown-host".into());
        let policy = st.portal.enroll(&portal_url, &code, &host, Some(std::env::consts::OS), &app2.package_info().version.to_string())?;
        crate::sync::apply_policy(&app2, &st, &policy);
        let _ = app2.emit("account-changed", ());
        let _ = app2.emit("engine-state-changed", ());
        Ok(st.portal.status())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Leaving management always works, even offline. Local settings stay as they are; the user regains control of them.
#[tauri::command]
pub async fn unenroll_device(app: AppHandle, state: Shared<'_>) -> Res<bool> {
    let st = state.inner().clone();
    let notified = tauri::async_runtime::spawn_blocking(move || st.portal.unenroll()).await.map_err(|e| e.to_string())?;
    let _ = app.emit("account-changed", ());
    Ok(notified)
}

#[tauri::command]
pub async fn sync_now(app: AppHandle, state: Shared<'_>) -> Res<crate::portal::AccountStatus> {
    let st = state.inner().clone();
    let st2 = st.clone();
    tauri::async_runtime::spawn_blocking(move || crate::sync::sync_once(&app, &st2)).await.map_err(|e| e.to_string())??;
    Ok(st.portal.status())
}

/// Build the shared Scanner from the user's limits settings.
pub fn build_scanner(settings: &Settings, clam: Arc<sentrix_core::clamav::ClamEngine>) -> Scanner {
    let mut l = Limits::default();
    l.max_scan_bytes = settings.max_file_size_mb as u64 * 1024 * 1024;
    l.archive_max_depth = settings.archive_max_depth;
    Scanner::new(l, Some(clam))
}

pub fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

#[cfg(test)]
mod feed_tests {
    use super::*;

    #[test]
    fn a_device_without_a_console_reads_the_public_release_feed() {
        let url = feed_url(None, "0.2.0", "abc").unwrap();
        assert!(url.starts_with("https://") && url.ends_with("/latest.json"), "{url}");
    }

    #[test]
    fn a_managed_device_asks_its_console_which_can_stage_a_rollout() {
        let url = feed_url(Some("https://console.example.com".into()), "0.2.0", "abc").unwrap();
        assert_eq!(url, "https://console.example.com/api/updates/windows-x64/0.2.0?id=abc");
        assert!(feed_url(Some("http://console.example.com".into()), "0.2.0", "abc").is_err(), "a console must be https");
    }
}

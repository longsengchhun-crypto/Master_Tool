//! Console synchronisation: heartbeat, policy application and the closed set of remote job kinds.

use crate::commands::{apply_monitoring, do_update_protection, run_scan};
use crate::portal::Job;
use crate::state::{monitored_paths, AppState, Settings};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tauri_plugin_notification::NotificationExt;

pub fn managed_view(s: &Settings) -> Value {
    let mut folders = s.monitored_folders.clone();
    folders.sort();
    json!({
        "realtimeMonitoring": s.realtime_monitoring,
        "monitoredFolders": folders,
        "autoQuarantine": s.auto_quarantine,
        "maxFileSizeMb": s.max_file_size_mb,
        "archiveMaxDepth": s.archive_max_depth,
        "allowRestoreSuspicious": s.allow_restore_suspicious,
    })
}

/// The settings an organization controls while a device is enrolled: real-time monitoring, watched folders,
/// auto-quarantine, scan limits and restore permission. Theme, notifications and start-at-login stay with the user.
/// Map the console's policy onto local settings. Unknown or out-of-range values are ignored rather than trusted.
pub fn apply_policy(app: &AppHandle, st: &Arc<AppState>, policy: &Value) {
    let mut changed;
    {
        let mut s = st.store.settings.lock().unwrap();
        let before = managed_view(&s);
        if let Some(v) = policy["realtimeMonitoring"].as_bool() {
            s.realtime_monitoring = v;
        }
        if let Some(arr) = policy["monitoredFolders"].as_array() {
            let f: Vec<String> = arr.iter().filter_map(|x| x.as_str()).filter(|x| matches!(*x, "downloads" | "desktop" | "documents" | "removable")).map(String::from).collect();
            s.monitored_folders = f;
        }
        if let Some(v) = policy["autoQuarantine"].as_str().filter(|v| matches!(*v, "off" | "malicious_only")) {
            s.auto_quarantine = v.to_string();
        }
        if let Some(v) = policy["maxFileSizeMb"].as_u64().filter(|v| (1..=4096).contains(v)) {
            s.max_file_size_mb = v as u32;
        }
        if let Some(v) = policy["archiveMaxDepth"].as_u64().filter(|v| *v <= 8) {
            s.archive_max_depth = v as u32;
        }
        if let Some(v) = policy["allowUserRestoreSuspicious"].as_bool() {
            s.allow_restore_suspicious = v;
        }
        changed = managed_view(&s) != before;
        let mut l = st.scanner.limits();
        l.max_scan_bytes = s.max_file_size_mb as u64 * 1024 * 1024;
        l.archive_max_depth = s.archive_max_depth;
        st.scanner.set_limits(l);
    }
    if let Some(h) = policy["maxIntelAgeHours"].as_u64() {
        st.scanner.set_max_intel_age_hours(h);
    }
    // An organization may switch the Telegram integrations off. Disabling the bot also removes the stored token,
    // so nothing keeps the integration alive behind the user's back. The user sees why on the Telegram page.
    let (bot_ok, acct_ok) = (policy["telegramBotAllowed"].as_bool().unwrap_or(true), policy["telegramAccountAllowed"].as_bool().unwrap_or(true));
    let groups_ok = policy["telegramGroupsAllowed"].as_bool().unwrap_or(true);
    {
        let mut s = st.store.settings.lock().unwrap();
        s.telegram.account_allowed = acct_ok;
        if s.telegram.groups_allowed != groups_ok {
            s.telegram.groups_allowed = groups_ok;
            changed = true;
        }
        if s.telegram.bot_allowed != bot_ok {
            s.telegram.bot_allowed = bot_ok;
            changed = true;
        }
    }
    if !bot_ok && st.tg_vault.exists() {
        st.tg_vault.wipe();
        {
            let mut s = st.store.settings.lock().unwrap();
            s.telegram.chat_id = None;
            s.telegram.bot_username = None;
            s.telegram.accept_submissions = false;
            s.telegram.group_shield = false;
        }
        st.jobs.groups_clear();
        st.jobs.clear_outbox();
        st.jobs.add_event("telegram_policy", "warning", "Your organization turned off Telegram notifications; the bot was disconnected and its token removed.", sentrix_core::queue::now_ms());
        changed = true;
    }
    st.store.save_settings();
    if changed {
        st.store.save_settings();
        apply_monitoring(app, st);
    }
}

fn heartbeat_payload(app: &AppHandle, st: &AppState) -> Value {
    let e = st.scanner.engine_status();
    let rt = crate::commands::realtime_status(st);
    let counters = st.store.counters.lock().unwrap().clone();
    let now = sentrix_core::queue::now_ms();
    let q = st.jobs.stats(now).unwrap_or_default();
    let ob = st.jobs.outbox_stats(now).unwrap_or_default();
    let gt = st.jobs.group_totals(now - 86_400_000).unwrap_or_default();
    let acct = st.account.view();
    json!({
        // Operational counts only. No file names, hashes, chat ids, tokens or message text are ever included here.
        "queue": { "queued": q.queued, "failed": q.failed, "stuck": q.stuck },
        // Counts only: never group names, chat ids, member names or file names.
        "groups": {
            "registered": gt.registered, "protected": gt.protected, "autoDelete": gt.auto_delete,
            "scans24h": gt.scans, "threats24h": gt.threats, "errors24h": gt.errors,
        },
        "telegram": {
            "botConnected": (st.tg_vault.exists() && st.store.settings.lock().unwrap().telegram.chat_id.is_some()) || crate::hosted::relay_out(st).linked,
            "deliveryFailures24h": ob.failed_24h,
            "accountState": account_state(&st.account.view().link),
            // Counts only. Never file names, chat names, account names or ids.
            "account": { "scanned": acct.counts.scanned, "threats": acct.counts.threats, "unverified": acct.counts.inaccessible },
        },
        "appVersion": app.package_info().version.to_string(),
        "engineVersion": e.clamav_version.as_deref().map(|v| v.split('/').next().unwrap_or(v).to_string()),
        "intelVersion": e.clamav_version.as_deref().and_then(|v| v.split('/').nth(1)).map(String::from),
        "intelUpdatedAt": counters.last_signature_update.map(|t| t.to_rfc3339()),
        "protection": {
            "engineState": e.state,
            "realtimeState": match rt.state.as_str() { "active" => "active", "off" => "paused", _ => "error" },
            "detail": e.detail.chars().take(300).collect::<String>(),
        }
    })
}

/// The console's account state vocabulary (see packages/contracts). `unavailable` covers every "cannot run here" case.
fn account_state(l: &sentrix_core::account_td::LinkState) -> &'static str {
    use sentrix_core::account_td::LinkState::*;
    match l {
        Connected => "connected",
        Expired => "expired",
        Unconfigured(_) => "not_available",
        _ => "disconnected",
    }
}

fn tell(app: &AppHandle, body: &str) {
    let _ = app.notification().builder().title("SENTRIX").body(body).show();
}

/// One check-in. Returns an error string for the UI; the account page shows it.
pub fn sync_once(app: &AppHandle, st: &Arc<AppState>) -> Result<(), String> {
    if !st.portal.is_enrolled() {
        return Ok(());
    }
    let org = st.portal.org_name().unwrap_or_else(|| "Your organization".into());
    let data = match st.portal.heartbeat(&heartbeat_payload(app, st)) {
        Ok(d) => d,
        Err(e) => {
            if !st.portal.is_enrolled() {
                tell(app, &e);
            }
            let _ = app.emit("account-changed", ());
            return Err(e);
        }
    };
    apply_policy(app, st, &data.policy);
    for job in data.jobs {
        run_job(app, st, &org, job);
    }
    let _ = app.emit("account-changed", ());
    let _ = app.emit("engine-state-changed", ());
    Ok(())
}

/// The only remote requests the app will honour. Each is announced to the user first and reported back.
fn run_job(app: &AppHandle, st: &Arc<AppState>, org: &str, job: Job) {
    match job.kind.as_str() {
        "intel_update" => {
            tell(app, &format!("{org} requested a protection update. Updating now."));
            let r = do_update_protection(st);
            st.portal.job_result(&job.id, r.ok, &r.message);
        }
        "scan_quick" => {
            let roots = monitored_paths(&st.store.settings.lock().unwrap());
            if roots.is_empty() {
                st.portal.job_result(&job.id, false, "No folders are configured to scan.");
                return;
            }
            tell(app, &format!("{org} requested a quick scan of your protected folders. It is running now."));
            let (app2, st2) = (app.clone(), st.clone());
            let out = tauri::async_runtime::block_on(run_scan(app2, st2, roots, "paths", false));
            match out {
                Ok(b) => st.portal.job_result(&job.id, true, &format!("Scanned {} files: {} malicious, {} suspicious, {} unable to verify.", b.counts.total, b.counts.malicious, b.counts.suspicious, b.counts.unable_to_verify)),
                Err(e) => st.portal.job_result(&job.id, false, &e),
            }
        }
        "app_update" => {
            // Application updates are not wired into this build; say so rather than pretending.
            st.portal.job_result(&job.id, false, "Application updates are not enabled in this build.");
        }
        other => st.portal.job_result(&job.id, false, &format!("Unsupported request '{}' ignored.", other.chars().take(40).collect::<String>())),
    }
}

/// Background loop: check in shortly after start, then every five minutes while enrolled.
pub fn spawn_loop(app: AppHandle, st: Arc<AppState>) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(20));
        let mut last_state = String::new();
        loop {
            if st.portal.is_enrolled() {
                let _ = sync_once(&app, &st);
                // Tell the console when protection degrades, but only if the user has allowed health reporting.
                if st.store.settings.lock().unwrap().telemetry_enabled {
                    let e = st.scanner.engine_status();
                    if e.state != "running" && e.state != last_state {
                        st.portal.event(&format!("engine_{}", e.state), if e.state == "unavailable" { "critical" } else { "warning" }, &e.detail);
                    }
                    last_state = e.state;
                }
            }
            std::thread::sleep(Duration::from_secs(300));
        }
    });
}

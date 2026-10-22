//! Glue between the UI-independent protection service (sentrix-core) and the desktop app: hooks, configuration built
//! from settings, and the Telegram / health commands.

use crate::commands::{notify_local, Res, Shared};
use crate::state::{watch_roots, AppState};
use sentrix_core::guard;
use sentrix_core::notify::{self, NotifyPrefs};
use sentrix_core::queue::now_ms;
use sentrix_core::service::{Hooks, ProtectionHealth, ServiceConfig};
use sentrix_core::telegram::BotClient;
use sentrix_core::telegram_desktop::{self, Detection};
use sentrix_core::{ScanReport, Verdict};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager};

/// Connects the service to history, local notifications, the UI event stream and (opt-in) console reporting.
pub struct AppHooks {
    pub app: AppHandle,
}

impl Hooks for AppHooks {
    fn on_report(&self, r: &ScanReport) {
        let Some(st) = self.app.try_state::<Arc<AppState>>() else { return };
        st.store.push_reports(std::slice::from_ref(r));
        notify_local(&self.app, &st, r);
        let _ = self.app.emit("realtime-report", r);
        // Console reporting: metadata only, only for enrolled devices that allowed health reporting, only findings.
        if r.verdict != Verdict::Clean && st.portal.is_enrolled() && st.store.settings.lock().unwrap().telemetry_enabled {
            let (p, rep) = (st.portal.clone(), r.clone());
            std::thread::spawn(move || p.report_scan("realtime", rep.started_at, 1, usize::from(!rep.complete), rep.complete, std::slice::from_ref(&rep)));
        }
    }

    fn on_health_changed(&self) {
        let _ = self.app.emit("protection-changed", ());
    }
}

pub fn build_config(st: &AppState) -> ServiceConfig {
    let s = st.store.settings.lock().unwrap().clone();
    let mut c = ServiceConfig::new(st.data_dir.join("tmp"));
    c.realtime = s.realtime_monitoring;
    c.roots = watch_roots(&s);
    c.exclude = vec![st.data_dir.clone()]; // never scan SENTRIX's own encrypted vault and databases
    c.auto_quarantine = s.auto_quarantine == "malicious_only";
    c.execution_guard = s.execution_guard;
    // Telegram is only used when the user connected a bot AND policy allows it.
    let bot_ok = s.telegram.bot_allowed && st.tg_vault.exists();
    c.notify = s.telegram.notify.clone();
    c.chat_id = if bot_ok { s.telegram.chat_id } else { None };
    c.accept_submissions = bot_ok && s.telegram.accept_submissions;
    c.group_shield = bot_ok && s.telegram.group_shield && s.telegram.groups_allowed;
    // Linked to the shared SENTRIX bot: reports go through the relay and the app holds no bot token. Groups are then
    // managed in the bot itself (it runs on SENTRIX's server), not here.
    c.relay = !bot_ok && s.telegram.bot_allowed && s.telegram.relay_linked && st.relay_vault.exists();
    c
}

pub fn refresh_bot(st: &AppState) {
    let allowed = st.store.settings.lock().unwrap().telegram.bot_allowed;
    if allowed {
        if let Some(tok) = st.tg_vault.load() {
            if let Ok(b) = BotClient::new(&tok) {
                st.service.set_bot(Some(Arc::new(b)));
                return;
            }
        }
    }
    st.service.set_bot(None);
}

/// (Re)apply settings to the running service. Idempotent.
pub fn apply(app: &AppHandle, st: &Arc<AppState>) {
    refresh_bot(st);
    crate::hosted::refresh_courier(st);
    // Organization policy can switch personal-account protection off: sign out and erase the session (off the UI thread).
    if !st.store.settings.lock().unwrap().telegram.account_allowed && (st.account.is_running() || !matches!(st.account.view().link, sentrix_core::account_td::LinkState::Disconnected | sentrix_core::account_td::LinkState::Unconfigured(_))) {
        let s2 = st.clone();
        std::thread::spawn(move || s2.account.disconnect());
    }
    st.service.set_config(build_config(st));
    let _ = app.emit("protection-changed", ());
}

// ---- health -----------------------------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthOut {
    #[serde(flatten)]
    pub health: ProtectionHealth,
    /// Does real-time protection come back after a reboot? Only if the user enabled start-at-login.
    pub resumes_after_restart: bool,
    pub engine: sentrix_core::scanner::EngineStatus,
}

#[tauri::command]
pub async fn protection_health(app: AppHandle, state: Shared<'_>) -> Res<HealthOut> {
    let st = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        use tauri_plugin_autostart::ManagerExt;
        HealthOut { health: st.service.health(), resumes_after_restart: app.autolaunch().is_enabled().unwrap_or(false), engine: st.scanner.engine_status() }
    })
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn retry_failed_jobs(state: Shared<'_>, id: Option<String>) -> Res<usize> {
    let now = now_ms();
    let ids: Vec<String> = match id {
        Some(i) => vec![i],
        None => state.jobs.failed_jobs(1000).map_err(|e| e.to_string())?.into_iter().map(|j| j.id).collect(),
    };
    Ok(ids.iter().filter(|i| state.jobs.retry_failed(i, now).unwrap_or(false)).count())
}

/// The user decides to allow a file the execution guard blocked.
#[tauri::command]
pub fn allow_execution(state: Shared<'_>, id: String) -> Res<()> {
    let rid = uuid::Uuid::parse_str(&id).map_err(|_| "Invalid report id".to_string())?;
    let r = state.store.history.lock().unwrap().iter().find(|r| r.id == rid).cloned().ok_or("Report not found")?;
    guard::allow_execution(&r.file.path).map_err(|e| e.to_string())?;
    state.store.set_blocked(rid, false);
    Ok(())
}

// ---- Telegram ---------------------------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BotStatus {
    pub configured: bool,
    /// Telegram confirmed both the token and delivery to the chat.
    pub connected: bool,
    pub username: Option<String>,
    /// Never the full id: just enough to recognise it.
    pub chat_hint: Option<String>,
    pub last_test_at: Option<i64>,
    pub last_test_ok: Option<bool>,
    pub last_test_error: Option<String>,
    pub last_delivery_at: Option<i64>,
    /// Set only while an unsent message currently has a delivery error.
    pub last_delivery_error: Option<String>,
    pub pending: i64,
    pub failed_24h: i64,
    pub dead: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopStatus {
    pub detection: Detection,
    pub folder: Option<String>,
    pub exists: bool,
    pub watching: bool,
    pub error: Option<String>,
    pub scanned: usize,
    pub threats: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TelegramStatus {
    pub allowed: bool,
    pub bot: BotStatus,
    pub accept_submissions: bool,
    pub notify: NotifyPrefs,
    pub desktop: DesktopStatus,
    pub account: crate::account::AccountOut,
    /// The shared SENTRIX bot: link state, reachability, and where to find the bot.
    pub relay: crate::hosted::RelayOut,
    pub groups: GroupsStatus,
    pub rejected_submissions: u64,
    pub recent_notifications: Vec<sentrix_core::queue::OutboxRow>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupsStatus {
    /// The owner's master switch.
    pub shield: bool,
    /// Organization policy.
    pub allowed: bool,
    /// Telegram privacy mode hides ordinary group messages from the bot (None = not known yet).
    pub privacy_blocks: Option<bool>,
    pub list: Vec<sentrix_core::service::GroupView>,
}

fn mask_chat(id: i64) -> String {
    let s = id.to_string();
    format!("•••{}", &s[s.len().saturating_sub(3)..])
}

fn detect_desktop() -> Detection {
    let env = |k: &str| std::env::var_os(k).map(PathBuf::from).unwrap_or_default();
    let pf: Vec<PathBuf> = ["ProgramFiles", "ProgramFiles(x86)"].iter().map(|k| env(k)).filter(|p| !p.as_os_str().is_empty()).collect();
    telegram_desktop::detect(&env("APPDATA"), &env("LOCALAPPDATA"), &pf, crate::state::known_folder("downloads").as_deref(), crate::state::known_folder("documents").as_deref())
}

pub fn telegram_status(st: &AppState) -> TelegramStatus {
    let s = st.store.settings.lock().unwrap().clone();
    let now = now_ms();
    let ob = st.jobs.outbox_stats(now).unwrap_or_default();
    let configured = st.tg_vault.exists() && s.telegram.chat_id.is_some();
    let kv = |k: &str| st.jobs.kv_get(k);
    let verified = kv("tg_verified_at").is_some();
    let health = st.service.health();
    let desktop_root = health.roots.iter().find(|r| r.label == "Telegram Desktop");
    let (scanned, threats) = {
        let h = st.store.history.lock().unwrap();
        let tg: Vec<&ScanReport> = h.iter().filter(|r| r.origin.as_deref() == Some("Telegram Desktop")).collect();
        (tg.len(), tg.iter().filter(|r| matches!(r.verdict, Verdict::Malicious | Verdict::Suspicious)).count())
    };
    TelegramStatus {
        allowed: s.telegram.bot_allowed,
        bot: BotStatus {
            configured,
            connected: configured && verified,
            username: s.telegram.bot_username.clone(),
            chat_hint: s.telegram.chat_id.map(mask_chat),
            last_test_at: kv("tg_last_test_at").and_then(|v| v.parse().ok()),
            last_test_ok: kv("tg_last_test_ok").map(|v| v == "1"),
            last_test_error: kv("tg_last_test_error"),
            last_delivery_at: ob.last_sent_at,
            last_delivery_error: ob.last_error.clone(),
            pending: ob.pending,
            failed_24h: ob.failed_24h,
            dead: ob.dead,
        },
        accept_submissions: s.telegram.accept_submissions,
        notify: s.telegram.notify.clone(),
        desktop: DesktopStatus {
            detection: detect_desktop(),
            folder: s.telegram.desktop_folder.clone(),
            exists: desktop_root.map(|r| r.exists).unwrap_or(false),
            watching: desktop_root.map(|r| r.watching).unwrap_or(false),
            error: desktop_root.and_then(|r| r.error.clone()),
            scanned,
            threats,
        },
        account: crate::account::account_out(st),
        relay: crate::hosted::relay_out(st),
        groups: GroupsStatus { shield: s.telegram.group_shield && s.telegram.groups_allowed, allowed: s.telegram.groups_allowed, privacy_blocks: st.service.privacy_mode_blocks(), list: st.service.groups_view() },
        rejected_submissions: health.rejected_submissions,
        recent_notifications: st.jobs.recent_notifications(15).unwrap_or_default(),
    }
}

#[tauri::command]
pub fn tg_status(state: Shared<'_>) -> TelegramStatus {
    telegram_status(&state)
}

fn require_allowed(st: &AppState) -> Res<()> {
    if st.store.settings.lock().unwrap().telegram.bot_allowed {
        Ok(())
    } else {
        Err("Your organization does not allow Telegram notifications on this device.".into())
    }
}

/// Ask Telegram which private chats have messaged this bot, so the user does not have to find their chat id by hand.
/// Nothing is stored. The token is used only for this one request.
#[tauri::command]
pub async fn tg_detect_chat(token: String) -> Res<Vec<i64>> {
    tauri::async_runtime::spawn_blocking(move || {
        let bot = BotClient::new(token.trim()).map_err(|e| e.user_message())?;
        bot.get_me().map_err(|e| e.user_message())?;
        let ups = bot.get_updates(None, 0, 25).map_err(|e| e.user_message())?;
        let mut ids: Vec<i64> = ups.iter().filter(|u| u.chat_type == "private").map(|u| u.chat_id).collect();
        ids.sort_unstable();
        ids.dedup();
        Ok(ids)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Save nothing until Telegram has confirmed the token AND delivered a test message to the chat.
#[tauri::command]
pub async fn tg_connect_bot(app: AppHandle, state: Shared<'_>, token: String, chat_id: i64) -> Res<TelegramStatus> {
    require_allowed(&state)?;
    if state.store.settings.lock().unwrap().telegram.relay_linked {
        return Err("This computer is linked to the SENTRIX bot. Unlink it first if you want to use your own bot.".into());
    }
    if chat_id == 0 {
        return Err("Enter your Telegram chat ID (a number).".into());
    }
    let (st, app2) = (state.inner().clone(), app.clone());
    tauri::async_runtime::spawn_blocking(move || {
        let token = token.trim().to_string();
        let bot = BotClient::new(&token).map_err(|e| e.user_message())?;
        let me = bot.get_me().map_err(|e| e.user_message())?;
        let test = notify::format_system("test", "SENTRIX is now connected to this chat. Security reports will arrive here.", &NotifyPrefs::default(), now_ms()).expect("test notice");
        bot.send_message(chat_id, &test.text).map_err(|e| e.user_message())?;
        st.tg_vault.save(&token)?;
        {
            let mut s = st.store.settings.lock().unwrap();
            s.telegram.chat_id = Some(chat_id);
            s.telegram.bot_username = me.username.clone();
        }
        st.store.save_settings();
        st.jobs.kv_set("tg_verified_at", &now_ms().to_string());
        st.jobs.kv_set("tg_last_test_at", &now_ms().to_string());
        st.jobs.kv_set("tg_last_test_ok", "1");
        st.jobs.kv_delete("tg_last_test_error");
        st.jobs.add_event("telegram_connected", "info", "Telegram bot connected.", now_ms());
        apply(&app2, &st);
        Ok(telegram_status(&st))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn tg_test_connection(app: AppHandle, state: Shared<'_>) -> Res<TelegramStatus> {
    require_allowed(&state)?;
    let (st, app2) = (state.inner().clone(), app.clone());
    tauri::async_runtime::spawn_blocking(move || {
        let chat = st.store.settings.lock().unwrap().telegram.chat_id.ok_or("No bot is connected.")?;
        let token = st.tg_vault.load().ok_or("The saved bot token could not be read. Reconnect the bot.")?;
        let bot = BotClient::new(&token).map_err(|e| e.user_message())?;
        let now = now_ms().to_string();
        st.jobs.kv_set("tg_last_test_at", &now);
        let res = bot.get_me().and_then(|_| {
            let test = notify::format_system("test", "Connection test: SENTRIX can reach this chat.", &NotifyPrefs::default(), now_ms()).expect("test notice");
            bot.send_message(chat, &test.text)
        });
        match res {
            Ok(_) => {
                st.jobs.kv_set("tg_last_test_ok", "1");
                st.jobs.kv_set("tg_verified_at", &now);
                st.jobs.kv_delete("tg_last_test_error");
            }
            Err(e) => {
                st.jobs.kv_set("tg_last_test_ok", "0");
                st.jobs.kv_set("tg_last_test_error", &e.user_message());
            }
        }
        apply(&app2, &st);
        Ok(telegram_status(&st))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Removes the token (wiped on disk), the chat, queued message texts (they may name private files), and stops everything.
#[tauri::command]
pub fn tg_disconnect_bot(app: AppHandle, state: Shared<'_>) -> Res<TelegramStatus> {
    let wiped = state.tg_vault.wipe();
    {
        let mut s = state.store.settings.lock().unwrap();
        s.telegram.chat_id = None;
        s.telegram.bot_username = None;
        s.telegram.accept_submissions = false;
        s.telegram.group_shield = false;
    }
    state.jobs.groups_clear();
    state.store.save_settings();
    for k in ["tg_verified_at", "tg_last_test_at", "tg_last_test_ok", "tg_last_test_error", "tg_offset"] {
        state.jobs.kv_delete(k);
    }
    state.jobs.clear_outbox();
    state.jobs.add_event("telegram_disconnected", "info", "Telegram bot disconnected and its token removed.", now_ms());
    apply(&app, state.inner());
    if !wiped {
        return Err("The token file could not be fully removed. Close SENTRIX and delete telegram-bot.token in its data folder.".into());
    }
    Ok(telegram_status(&state))
}

#[tauri::command]
pub fn tg_set_options(app: AppHandle, state: Shared<'_>, notify: NotifyPrefs, accept_submissions: bool) -> Res<TelegramStatus> {
    require_allowed(&state)?;
    if accept_submissions && !state.tg_vault.exists() {
        return Err("Connect a bot first.".into());
    }
    {
        let mut s = state.store.settings.lock().unwrap();
        s.telegram.notify = notify;
        s.telegram.accept_submissions = accept_submissions;
    }
    state.store.save_settings();
    apply(&app, state.inner());
    Ok(telegram_status(&state))
}

#[tauri::command]
pub fn tg_detect_desktop() -> Detection {
    detect_desktop()
}

/// `None` stops watching a Telegram folder. A folder must exist, be a real directory (not a link) and be absolute.
#[tauri::command]
pub fn tg_set_desktop_folder(app: AppHandle, state: Shared<'_>, path: Option<String>) -> Res<TelegramStatus> {
    if let Some(p) = &path {
        let pb = PathBuf::from(p);
        let m = std::fs::symlink_metadata(&pb).map_err(|_| "That folder does not exist.".to_string())?;
        if !pb.is_absolute() || !m.is_dir() || m.file_type().is_symlink() {
            return Err("Choose a real folder (not a shortcut or link).".into());
        }
    }
    {
        let mut s = state.store.settings.lock().unwrap();
        s.telegram.desktop_folder = path;
    }
    state.store.save_settings();
    apply(&app, state.inner());
    Ok(telegram_status(&state))
}

/// The owner's master switch for Group Shield. Turning it on does not protect any group by itself: each group's own
/// administrators still have to send /setup on in that group.
#[tauri::command]
pub fn tg_set_group_shield(app: AppHandle, state: Shared<'_>, enabled: bool) -> Res<TelegramStatus> {
    require_allowed(&state)?;
    if !state.store.settings.lock().unwrap().telegram.groups_allowed {
        return Err("Your organization does not allow Telegram group protection on this device.".into());
    }
    if enabled && !state.tg_vault.exists() {
        return Err("Connect a bot first.".into());
    }
    {
        let mut s = state.store.settings.lock().unwrap();
        s.telegram.group_shield = enabled;
    }
    state.store.save_settings();
    state.jobs.add_event("group_shield", "info", if enabled { "Group Shield was turned on." } else { "Group Shield was turned off." }, now_ms());
    apply(&app, state.inner());
    Ok(telegram_status(&state))
}

/// Stop protecting one group (also turns its automatic deletion off).
#[tauri::command]
pub fn tg_group_disable(app: AppHandle, state: Shared<'_>, id: i64) -> Res<TelegramStatus> {
    state.service.group_disable(id);
    apply(&app, state.inner());
    Ok(telegram_status(&state))
}

/// Ask the bot to leave a group and forget everything stored about it.
#[tauri::command]
pub async fn tg_group_leave(app: AppHandle, state: Shared<'_>, id: i64) -> Res<TelegramStatus> {
    let st = state.inner().clone();
    let app2 = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        st.service.group_leave(id)?;
        apply(&app2, &st);
        Ok(telegram_status(&st))
    })
    .await
    .map_err(|e| e.to_string())?
}

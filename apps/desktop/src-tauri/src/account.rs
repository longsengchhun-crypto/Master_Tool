//! Desktop glue for personal Telegram account protection: where the TDLib files and API credentials come from, the
//! settings-to-options mapping, and the commands the UI calls. The protocol work is in `sentrix_core::account_td`.

use crate::commands::{Res, Shared};
use crate::state::{AccountSettings, AppState, Settings};
use sentrix_core::account::{AccountPrefs, AttachmentGate};
use sentrix_core::account_td::{AccountOptions, AccountView, Credentials, LinkState, ServiceScanner, Shared as AccountShared, TdAccount};
use sentrix_core::queue::JobStore;
use sentrix_core::service::ProtectionService;
use sentrix_core::tdjson::{self, TdIo, TdLib};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tauri::{AppHandle, Emitter};

/// The pinned TDLib files: explicit override, next to the installed app, then the development checkout.
pub fn resolve_tdlib_dir(exe_dir: &Path) -> Option<PathBuf> {
    let has = |d: &Path| d.join("tdjson.dll").is_file() || d.join("libtdjson.so").is_file() || d.join("libtdjson.dylib").is_file();
    if let Some(p) = std::env::var_os("SENTRIX_TDLIB_DIR") {
        let p = PathBuf::from(p);
        return has(&p).then_some(p);
    }
    let bundled = exe_dir.join("engine").join("tdlib");
    if has(&bundled) {
        return Some(bundled);
    }
    let mut cur = Some(exe_dir);
    while let Some(d) = cur {
        let cand = d.join("third_party").join("tdlib");
        if has(&cand) {
            return Some(cand);
        }
        cur = d.parent();
    }
    None
}

fn parse_credentials(id: &str, hash: &str) -> Option<Credentials> {
    let api_id: i32 = id.trim().parse().ok().filter(|n| *n > 0)?;
    let h = hash.trim();
    (h.len() == 32 && h.chars().all(|c| c.is_ascii_hexdigit())).then(|| Credentials { api_id, api_hash: h.to_string() })
}

/// The Telegram API ID/hash identify THIS APPLICATION to Telegram (every Telegram client has one). They do not give
/// access to any account. Order: process environment, compile-time values (release builds), then in development the
/// gitignored `.sentrix-dev/telegram-api.env`.
pub fn resolve_credentials(exe_dir: &Path) -> Option<Credentials> {
    if let (Ok(i), Ok(h)) = (std::env::var("SENTRIX_TG_API_ID"), std::env::var("SENTRIX_TG_API_HASH")) {
        if let Some(c) = parse_credentials(&i, &h) {
            return Some(c);
        }
    }
    if let (Some(i), Some(h)) = (option_env!("SENTRIX_TG_API_ID"), option_env!("SENTRIX_TG_API_HASH")) {
        if let Some(c) = parse_credentials(i, h) {
            return Some(c);
        }
    }
    if cfg!(debug_assertions) {
        let mut cur = Some(exe_dir);
        while let Some(d) = cur {
            let f = d.join(".sentrix-dev").join("telegram-api.env");
            if let Ok(text) = std::fs::read_to_string(&f) {
                let get = |k: &str| text.lines().find_map(|l| l.trim().strip_prefix(&format!("{k}=")).map(str::to_string)).unwrap_or_default();
                return parse_credentials(&get("SENTRIX_TG_API_ID"), &get("SENTRIX_TG_API_HASH"));
            }
            cur = d.parent();
        }
    }
    None
}

/// Telegram files can be gigabytes. The account worker downloads a private copy of every file it checks, so it never
/// downloads more than this, whatever the general scan limit is. Larger files are reported UNABLE TO VERIFY.
pub const ACCOUNT_MAX_MB: u32 = 200;

pub fn options_from(s: &Settings) -> AccountOptions {
    let a = &s.telegram.account;
    AccountOptions {
        enabled: a.enabled,
        prefs: AccountPrefs { private_chats: a.private_chats, groups: a.groups, channels: a.channels, max_bytes: u64::from(s.max_file_size_mb.clamp(1, ACCOUNT_MAX_MB)) * 1024 * 1024 },
        media: a.media,
        local_reports: a.local_reports,
    }
}

pub fn build(app: &AppHandle, data_dir: &Path, exe_dir: &Path, service: Arc<ProtectionService>, jobs: Arc<JobStore>, settings: &Settings) -> Arc<TdAccount> {
    let dir = resolve_tdlib_dir(exe_dir);
    let creds = resolve_credentials(exe_dir);
    let unconfigured = match (&dir, &creds) {
        (None, _) => Some("The Telegram client component is not installed with this copy of SENTRIX, so account protection is unavailable.".to_string()),
        (Some(d), _) if tdjson::verify_dir(d, tdjson::PINS).is_err() => Some("The Telegram client component failed its integrity check and was not loaded. Reinstall SENTRIX.".to_string()),
        (_, None) => Some("This copy of SENTRIX was built without Telegram API credentials, so account protection is unavailable.".to_string()),
        _ => None,
    };
    let opts = options_from(settings);
    let gate = Arc::new(AttachmentGate::new(opts.prefs, 2));
    let handle = app.clone();
    let shared = AccountShared::new(jobs, Arc::new(ServiceScanner { svc: service, gate }), Box::new(move || { let _ = handle.emit("tg-account-changed", ()); }), opts, LinkState::Disconnected);
    let load_dir = dir.unwrap_or_default();
    let factory = Box::new(move || TdLib::load(&load_dir).map(|l| Arc::new(l.new_client()) as Arc<dyn TdIo>));
    TdAccount::new(shared, &data_dir.join("tg-account"), creds, factory, unconfigured)
}

/// Something the user relied on has stopped: shown on Home so a green "protected" never hides it. A plain
/// "not connected" is the user's choice and is not flagged.
pub fn attention(v: &AccountView) -> Option<&'static str> {
    match v.link {
        LinkState::Expired => Some("Telegram account protection stopped: the session ended. Sign in again under Telegram."),
        LinkState::Connected if v.connection != "ready" && v.connection != "updating" => Some("Telegram account protection is offline: files sent to you may not be checked until it reconnects."),
        _ => None,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountOut {
    #[serde(flatten)]
    pub view: AccountView,
    /// Organization policy.
    pub allowed: bool,
    pub options: AccountSettings,
}

pub fn account_out(st: &AppState) -> AccountOut {
    let s = st.store.settings.lock().unwrap();
    AccountOut { view: st.account.view(), allowed: s.telegram.account_allowed, options: s.telegram.account.clone() }
}

#[tauri::command]
pub fn tg_account_status(state: Shared<'_>) -> AccountOut {
    account_out(&state)
}

#[tauri::command]
pub fn tg_account_connect(state: Shared<'_>) -> Res<AccountOut> {
    let st = state.inner().clone();
    if !st.store.settings.lock().unwrap().telegram.account_allowed {
        return Err("Your organization has turned off Telegram account protection for this computer.".into());
    }
    st.account.connect();
    Ok(account_out(&st))
}

/// Signs out at Telegram and erases the local session. Runs off the UI thread: Telegram may take a few seconds to answer.
#[tauri::command]
pub async fn tg_account_disconnect(state: Shared<'_>) -> Res<AccountOut> {
    let st = state.inner().clone();
    let st2 = st.clone();
    tauri::async_runtime::spawn_blocking(move || st2.account.disconnect()).await.map_err(|e| e.to_string())?;
    Ok(account_out(&st))
}

#[tauri::command]
pub fn tg_account_set_options(app: AppHandle, state: Shared<'_>, options: AccountSettings) -> Res<AccountOut> {
    let st = state.inner().clone();
    {
        let mut s = st.store.settings.lock().unwrap();
        s.telegram.account = options;
    }
    st.store.save_settings();
    let s = st.store.settings.lock().unwrap().clone();
    st.account.set_options(options_from(&s));
    let _ = app.emit("tg-account-changed", ());
    Ok(account_out(&st))
}

/// Point one of the person's groups at one of their Scan History groups (`room` = None: all of them).
#[tauri::command]
pub fn tg_account_set_route(state: Shared<'_>, chat_id: i64, room: Option<i64>) -> AccountOut {
    state.account.shared.set_route(chat_id, room);
    account_out(&state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_must_look_like_telegram_api_credentials() {
        assert!(parse_credentials("12345", "0123456789abcdef0123456789abcdef").is_some());
        assert!(parse_credentials("", "0123456789abcdef0123456789abcdef").is_none());
        assert!(parse_credentials("-5", "0123456789abcdef0123456789abcdef").is_none());
        assert!(parse_credentials("12345", "short").is_none());
        assert!(parse_credentials("12345", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_none());
    }

    #[test]
    fn a_dead_or_offline_session_is_flagged_but_a_deliberate_disconnect_is_not() {
        let v = |l: LinkState, c: &str| {
            let mut a = AccountView::new(l);
            a.connection = c.into();
            a
        };
        assert!(attention(&v(LinkState::Expired, "unknown")).is_some());
        assert!(attention(&v(LinkState::Connected, "waiting_for_network")).is_some());
        assert!(attention(&v(LinkState::Connected, "ready")).is_none());
        assert!(attention(&v(LinkState::Disconnected, "unknown")).is_none());
        assert!(attention(&v(LinkState::Failed("x".into()), "unknown")).is_none(), "a sign-in that never worked is not a lost protection");
    }

    #[test]
    fn defaults_watch_private_chats_and_groups_but_not_channels_or_media() {
        let o = options_from(&Settings::default());
        assert!(o.enabled && o.prefs.private_chats && o.prefs.groups && !o.prefs.channels && !o.media && o.local_reports);
    }
}

//! Shared-bot mode on the desktop: link this app to the person's own chat with the SENTRIX bot.
//!
//! The person finds the SENTRIX bot in Telegram, presses Start, and the bot gives them a one-time code. They type it here.
//! The relay answers with a device token that is stored protected for this Windows user. From then on the app's existing
//! report queue (retry, de-duplication, rate limits) delivers through the relay, and the app never holds the bot's token.
//! What the relay and the bot see is the text of a report, nothing else; files are scanned on this computer.

use crate::commands::{Res, Shared};
use crate::protection::{apply, telegram_status, TelegramStatus};
use crate::state::AppState;
use sentrix_core::edge;
use sentrix_core::queue::now_ms;
use sentrix_core::relay::{self, RelayClient};
use sentrix_core::telegram::MAX_BOT_DOWNLOAD;
use sentrix_core::telegram::Courier;
use serde::Serialize;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tauri::AppHandle;

/// Where the relay is and what the bot is called. Both are public facts, not secrets.
#[derive(Debug, Clone)]
pub struct Endpoints {
    pub relay_url: String,
    pub bot_username: String,
}

fn parse_endpoints(url: &str, bot: &str) -> Option<Endpoints> {
    let relay_url = relay::validate_relay_url(url).ok()?;
    let bot = bot.trim().trim_start_matches('@');
    (bot.len() >= 5 && bot.len() <= 32 && bot.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')).then(|| Endpoints { relay_url, bot_username: bot.to_string() })
}

/// Order: process environment, values compiled into the build, then (development only) `.sentrix-dev/bot.env`.
pub fn resolve_endpoints(exe_dir: &Path) -> Option<Endpoints> {
    if let (Ok(u), Ok(b)) = (std::env::var("SENTRIX_RELAY_URL"), std::env::var("SENTRIX_BOT_USERNAME")) {
        if let Some(e) = parse_endpoints(&u, &b) {
            return Some(e);
        }
    }
    if let (Some(u), Some(b)) = (option_env!("SENTRIX_RELAY_URL"), option_env!("SENTRIX_BOT_USERNAME")) {
        if let Some(e) = parse_endpoints(u, b) {
            return Some(e);
        }
    }
    if cfg!(debug_assertions) {
        let mut cur = Some(exe_dir);
        while let Some(d) = cur {
            if let Ok(text) = std::fs::read_to_string(d.join(".sentrix-dev").join("bot.env")) {
                let get = |k: &str| text.lines().find_map(|l| l.trim().strip_prefix(&format!("{k}=")).map(str::to_string)).unwrap_or_default();
                return parse_endpoints(&get("SENTRIX_RELAY_URL"), &get("SENTRIX_BOT_USERNAME"));
            }
            cur = d.parent();
        }
    }
    None
}

#[derive(Default)]
struct Last {
    checked_at: Option<i64>,
    reachable: Option<bool>,
    error: Option<String>,
    /// The bot's owner unlinked this computer from the bot menu.
    removed_remotely: bool,
}

#[derive(Default)]
pub struct RelayState {
    last: Mutex<Last>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayOut {
    /// This build knows where the shared bot is. Without it only "use my own bot" is offered.
    pub available: bool,
    pub linked: bool,
    pub bot_username: Option<String>,
    pub bot_link: Option<String>,
    pub user_name: Option<String>,
    pub linked_at: Option<i64>,
    /// The bot can write to the person right now (they pressed Start and have not blocked it). `None` = not checked yet.
    pub reachable: Option<bool>,
    pub checked_at: Option<i64>,
    pub error: Option<String>,
    /// The link was removed from the bot's menu, so this computer was unlinked and its token erased.
    pub removed_remotely: bool,
}

pub fn relay_out(st: &AppState) -> RelayOut {
    let s = st.store.settings.lock().unwrap();
    let l = st.relay.last.lock().unwrap();
    let ep = st.endpoints.as_ref();
    RelayOut {
        available: ep.is_some(),
        linked: s.telegram.relay_linked && st.relay_vault.exists(),
        bot_username: ep.map(|e| e.bot_username.clone()),
        bot_link: ep.map(|e| format!("https://t.me/{}", e.bot_username)),
        user_name: s.telegram.relay_user.clone(),
        linked_at: s.telegram.relay_linked_at,
        reachable: l.reachable,
        checked_at: l.checked_at,
        error: l.error.clone(),
        removed_remotely: l.removed_remotely,
    }
}

fn client(st: &AppState) -> Option<RelayClient> {
    let ep = st.endpoints.as_ref()?;
    let token = String::from_utf8(st.relay_vault.load()?).ok()?;
    RelayClient::new(&ep.relay_url, &token).ok()
}

/// Make the service deliver through the relay when this app is linked, and through nothing relay-related otherwise.
pub fn refresh_courier(st: &AppState) {
    let s = st.store.settings.lock().unwrap();
    let on = s.telegram.bot_allowed && s.telegram.relay_linked && st.relay_vault.exists();
    drop(s);
    let courier: Option<Arc<dyn Courier>> = if on { client(st).map(|c| Arc::new(c) as Arc<dyn Courier>) } else { None };
    st.service.set_courier(courier);
}

/// Erase the local link (token and settings). The relay is told separately, best effort.
fn forget_locally(st: &AppState, removed_remotely: bool) {
    st.relay_vault.wipe();
    {
        let mut s = st.store.settings.lock().unwrap();
        s.telegram.relay_linked = false;
        s.telegram.relay_user = None;
        s.telegram.relay_linked_at = None;
    }
    st.store.save_settings();
    st.jobs.clear_outbox();
    let mut l = st.relay.last.lock().unwrap();
    *l = Last { removed_remotely, ..Last::default() };
}

fn computer_name() -> String {
    std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).ok().map(|s| s.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(40).collect::<String>()).filter(|s| !s.trim().is_empty()).unwrap_or_else(|| "My computer".into())
}

/// Files posted in groups this person protects through the bot are handed to this computer to be checked here, with this
/// computer's own scan engine, not on the bot's server. Returns how many were answered (0 when there was nothing to do,
/// or this computer is not linked, or the relay could not be reached).
pub fn edge_poll(st: &Arc<AppState>) -> usize {
    if !st.store.settings.lock().unwrap().telegram.bot_allowed {
        return 0;
    }
    let Some(c) = (if relay_out(st).linked { client(st) } else { None }) else { return 0 };
    let scan = |origin: &str, name: &str, bytes: &[u8]| st.service.scan_ephemeral(origin, name, &mut &bytes[..], MAX_BOT_DOWNLOAD);
    match edge::run_once(&c, &scan) {
        Ok(n) => {
            if n > 0 {
                st.jobs.add_event("group_files_checked", "info", &format!("{n} file(s) from your protected Telegram groups were checked on this computer."), now_ms());
            }
            n
        }
        Err(_) => 0,
    }
}

/// Called every minute or so. Detects that the person unlinked this computer in the bot, and that the bot cannot reach them.
pub fn check_link(app: &AppHandle, st: &Arc<AppState>) {
    let Some(c) = (if relay_out(st).linked { client(st) } else { None }) else { return };
    match c.status() {
        Ok((true, reachable)) => {
            let mut l = st.relay.last.lock().unwrap();
            l.checked_at = Some(now_ms());
            l.reachable = Some(reachable);
            l.error = None;
            l.removed_remotely = false;
        }
        Ok((false, _)) => {
            forget_locally(st, true);
            st.jobs.add_event("relay_unlinked", "warning", "This computer was unlinked from the SENTRIX bot. Reports are not being delivered until it is linked again.", now_ms());
            apply(app, st);
        }
        Err(e) => {
            let mut l = st.relay.last.lock().unwrap();
            l.checked_at = Some(now_ms());
            l.error = Some(e);
        }
    }
}

/// Link this app with the one-time code the SENTRIX bot showed. The code is exchanged for a token, which is stored protected.
#[tauri::command]
pub async fn tg_relay_link(app: AppHandle, state: Shared<'_>, code: String) -> Res<TelegramStatus> {
    let (st, app2) = (state.inner().clone(), app.clone());
    tauri::async_runtime::spawn_blocking(move || {
        if !st.store.settings.lock().unwrap().telegram.bot_allowed {
            return Err("Your organization has turned off Telegram on this computer.".to_string());
        }
        if st.tg_vault.exists() {
            return Err("You are using your own bot. Disconnect it first, then link the SENTRIX bot.".into());
        }
        let ep = st.endpoints.clone().ok_or("This copy of SENTRIX does not know where the SENTRIX bot is.")?;
        let linked = relay::link(&ep.relay_url, &code, &computer_name())?;
        st.relay_vault.save(linked.token.as_bytes())?;
        {
            let mut s = st.store.settings.lock().unwrap();
            s.telegram.relay_linked = true;
            s.telegram.relay_user = Some(linked.user_name.chars().filter(|c| !c.is_control()).take(40).collect()).filter(|n: &String| !n.is_empty());
            s.telegram.relay_linked_at = Some(now_ms());
        }
        st.store.save_settings();
        *st.relay.last.lock().unwrap() = Last { checked_at: Some(now_ms()), reachable: Some(true), ..Last::default() };
        st.jobs.add_event("relay_linked", "info", "This computer was linked to the SENTRIX bot.", now_ms());
        apply(&app2, &st);
        Ok(telegram_status(&st))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Unlink. The relay forgets this computer (if it can be reached) and the token is erased here either way.
#[tauri::command]
pub async fn tg_relay_unlink(app: AppHandle, state: Shared<'_>) -> Res<TelegramStatus> {
    let (st, app2) = (state.inner().clone(), app.clone());
    tauri::async_runtime::spawn_blocking(move || {
        if let Some(c) = client(&st) {
            let _ = c.unlink();
        }
        forget_locally(&st, false);
        st.jobs.add_event("relay_unlinked", "info", "This computer was unlinked from the SENTRIX bot.", now_ms());
        apply(&app2, &st);
        Ok(telegram_status(&st))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Send a test message to the person's chat with the bot, right now, and report exactly what happened.
#[tauri::command]
pub async fn tg_relay_test(app: AppHandle, state: Shared<'_>) -> Res<TelegramStatus> {
    let (st, app2) = (state.inner().clone(), app.clone());
    tauri::async_runtime::spawn_blocking(move || {
        let c = client(&st).ok_or("This computer is not linked to the SENTRIX bot.")?;
        let res = c.send_reply(0, "<b>SENTRIX test</b>\nThis message came from the SENTRIX app on your computer. Reports will arrive here.", None);
        {
            let mut l = st.relay.last.lock().unwrap();
            l.checked_at = Some(now_ms());
            match &res {
                Ok(_) => {
                    l.reachable = Some(true);
                    l.error = None;
                }
                Err(e) => l.error = Some(e.user_message()),
            }
        }
        apply(&app2, &st);
        res.map_err(|e| e.user_message())?;
        Ok(telegram_status(&st))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_need_an_https_relay_and_a_real_looking_bot_name() {
        assert!(parse_endpoints("https://relay.example.com", "@SentrixBot").is_some_and(|e| e.bot_username == "SentrixBot"));
        assert!(parse_endpoints("http://relay.example.com", "SentrixBot").is_none(), "plain http is refused");
        assert!(parse_endpoints("http://127.0.0.1:8787", "SentrixBot").is_some(), "this machine is fine for development");
        assert!(parse_endpoints("https://relay.example.com", "bad name").is_none());
        assert!(parse_endpoints("https://relay.example.com", "x").is_none());
        assert!(parse_endpoints("", "").is_none());
    }
}

//! Keeps the app up to date by itself.
//!
//! A little after start-up and then every few hours the app asks the release feed whether a newer version exists. If one
//! does, it is downloaded, its signature is verified against the public key built into this app (a bad signature installs
//! nothing), and the app restarts into the new version. It never interrupts a scan: while one is running it waits.
//! People can switch this off in Settings; "Check for updates" there still works by hand.

use crate::state::AppState;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter};

const FIRST_CHECK: Duration = Duration::from_secs(90);
const EVERY: Duration = Duration::from_secs(6 * 3600);
const AFTER_A_FAILURE: Duration = Duration::from_secs(3600);

pub fn spawn_loop(app: AppHandle, st: Arc<AppState>) {
    std::thread::spawn(move || {
        std::thread::sleep(FIRST_CHECK);
        loop {
            let wait = match tick(&app, &st) {
                Ok(()) => EVERY,
                Err(e) => {
                    eprintln!("[update] {e}");
                    AFTER_A_FAILURE
                }
            };
            std::thread::sleep(wait);
        }
    });
}

fn tick(app: &AppHandle, st: &Arc<AppState>) -> Result<(), String> {
    if !st.store.settings.lock().unwrap().auto_update {
        return Ok(());
    }
    let updater = crate::commands::updater_for(app, st)?;
    let Some(update) = tauri::async_runtime::block_on(updater.check()).map_err(|e| format!("could not check for updates: {e}"))? else {
        return Ok(());
    };
    // Never restart in the middle of a scan: wait for it, up to half an hour, then try again at the next check.
    for _ in 0..30 {
        if !st.scan_running.load(Ordering::SeqCst) {
            break;
        }
        std::thread::sleep(Duration::from_secs(60));
    }
    if st.scan_running.load(Ordering::SeqCst) {
        return Ok(());
    }
    let _ = app.emit("update-installing", update.version.clone());
    std::thread::sleep(Duration::from_secs(3)); // let the notice show before the window goes away
    tauri::async_runtime::block_on(update.download_and_install(|_, _| {}, || {})).map_err(|e| format!("the update was not installed: {e}"))?;
    app.restart()
}

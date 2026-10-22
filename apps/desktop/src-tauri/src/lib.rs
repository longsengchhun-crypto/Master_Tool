mod account;
mod commands;
pub mod portal;
mod protection;
mod state;
mod sync;

use account::*;
use commands::*;
use protection::*;
use sentrix_core::clamav::ClamEngine;
use sentrix_core::quarantine::Quarantine;
use sentrix_core::queue::JobStore;
use sentrix_core::service::ProtectionService;
use sentrix_core::telegram::TokenVault;
use state::*;
use std::collections::HashSet;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager, WindowEvent};
use tauri_plugin_autostart::MacosLauncher;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_autostart::init(MacosLauncher::LaunchAgent, Some(vec!["--minimized"])))
        .setup(|app| {
            let handle = app.handle().clone();
            let data_dir = app.path().app_data_dir().expect("no app data dir");
            std::fs::create_dir_all(&data_dir)?;

            let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.to_path_buf())).unwrap_or_default();
            let clam_dir = resolve_clam_dir(&exe_dir);
            let clam = Arc::new(ClamEngine::new(clam_dir, data_dir.clone()));
            let store = Arc::new(Store::open(&data_dir));
            let settings = store.settings.lock().unwrap().clone();
            let scanner = Arc::new(build_scanner(&settings, clam.clone()));
            let quarantine = Arc::new(Quarantine::open(data_dir.join("quarantine")).map_err(|e| format!("quarantine unavailable: {e}"))?);

            // Durable queue/outbox/event log: a crash or reboot loses nothing and recovery is deterministic.
            let jobs = Arc::new(JobStore::open(&data_dir.join("protection.db")).map_err(|e| format!("protection database unavailable: {e}"))?);
            let service = Arc::new(ProtectionService::new(scanner.clone(), quarantine.clone(), jobs.clone(), Arc::new(protection::AppHooks { app: handle.clone() }), sentrix_core::service::ServiceConfig::new(data_dir.join("tmp"))));

            let account = account::build(&handle, &data_dir, &exe_dir, service.clone(), jobs.clone(), &settings);
            let st = Arc::new(AppState {
                data_dir: data_dir.clone(),
                store,
                scanner,
                clam: clam.clone(),
                quarantine,
                portal: Arc::new(portal::Portal::open(&data_dir)),
                scan_running: AtomicBool::new(false),
                cancel: Mutex::new(None),
                jobs,
                service,
                tg_vault: TokenVault::new(&data_dir),
                account,
                notified: Mutex::new(HashSet::new()),
            });
            app.manage(st.clone());

            build_tray(app)?;
            sync::spawn_loop(handle.clone(), st.clone());

            // Start the engine and monitor off the UI thread: loading signatures takes several seconds.
            {
                let (h, s) = (handle.clone(), st.clone());
                std::thread::spawn(move || {
                    if s.clam.is_installed() && s.clam.has_database() {
                        let _ = s.clam.start();
                    }
                    // Resume protection: recovers interrupted scans, reconciles files that arrived while we were off.
                    protection::apply(&h, &s);
                    s.service.start();
                    // A Telegram account session saved by an earlier run comes back on its own (never starts a new login).
                    if s.store.settings.lock().unwrap().telegram.account_allowed {
                        s.account.resume();
                    }
                    let _ = h.emit("engine-state-changed", ());
                });
            }
            // Removable drives can appear after start-up; re-evaluate the watch list periodically if enabled.
            {
                let (h, s) = (handle.clone(), st.clone());
                std::thread::spawn(move || {
                    let mut last = drive_roots().0;
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(15));
                        let wants = {
                            let cfg = s.store.settings.lock().unwrap();
                            cfg.realtime_monitoring && cfg.monitored_folders.iter().any(|f| f == "removable")
                        };
                        let now = drive_roots().0;
                        if wants && now != last {
                            apply_monitoring(&h, &s);
                            let _ = h.emit("engine-state-changed", ());
                        }
                        last = now;
                    }
                });
            }

            // Autostart launches with --minimized so login does not throw a window at the user.
            if std::env::args().any(|a| a == "--minimized") {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.hide();
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window keeps real-time protection running in the tray, but only if it is on.
            if let WindowEvent::CloseRequested { api, .. } = event {
                let st = window.app_handle().state::<Arc<AppState>>();
                let rt_on = st.store.settings.lock().unwrap().realtime_monitoring;
                if rt_on {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            app_status,
            start_engine,
            update_protection,
            scan_paths,
            full_system_scan,
            cancel_scan,
            list_history,
            get_report,
            report_text,
            export_report,
            clear_history,
            quarantine_report,
            delete_scanned_file,
            dismiss_warning,
            list_quarantine,
            restore_quarantine,
            delete_quarantine,
            verify_quarantine_audit,
            reveal_in_folder,
            get_settings,
            set_settings,
            complete_onboarding,
            protection_health,
            retry_failed_jobs,
            allow_execution,
            tg_status,
            tg_detect_chat,
            tg_connect_bot,
            tg_test_connection,
            tg_disconnect_bot,
            tg_set_options,
            tg_detect_desktop,
            tg_set_desktop_folder,
            tg_set_group_shield,
            tg_account_status,
            tg_account_connect,
            tg_account_disconnect,
            tg_account_set_options,
            tg_group_disable,
            tg_group_leave,
            account_status,
            enroll_device,
            unenroll_device,
            sync_now,
            check_update,
            install_update,
        ])
        .build(tauri::generate_context!())
        .expect("error while building SENTRIX")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                // Stop the detection engine and monitor cleanly on quit.
                if let Some(st) = app.try_state::<Arc<AppState>>() {
                    st.account.stop();
                    st.service.stop();
                    st.clam.stop();
                }
            }
        });
}

fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open SENTRIX", true, None::<&str>)?;
    let scan = MenuItem::with_id(app, "scan", "Scan a fileâ€¦", true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", "Turn real-time protection on/off", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit SENTRIX", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&open, &scan, &toggle, &sep, &quit])?;

    TrayIconBuilder::with_id("main")
        .icon(app.default_window_icon().cloned().expect("no window icon"))
        .tooltip("SENTRIX")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, ev| match ev.id.as_ref() {
            "open" => show_main(app),
            "scan" => {
                show_main(app);
                let _ = app.emit("navigate", "scan");
            }
            "toggle" => {
                let st = app.state::<Arc<AppState>>().inner().clone();
                {
                    let mut s = st.store.settings.lock().unwrap();
                    s.realtime_monitoring = !s.realtime_monitoring;
                }
                st.store.save_settings();
                apply_monitoring(app, &st);
                let _ = app.emit("engine-state-changed", ());
            }
            "quit" => {
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, ev| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = ev {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

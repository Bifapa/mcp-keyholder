#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod client;
mod clipboard;
mod commands;
mod desktop;
mod hello;
mod service;
mod session_watch;
mod state;

use std::sync::Arc;

use kh_core::Vault;
use kh_daemon::{Daemon, Runtime};
use serde_json::json;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager, WindowEvent};

use crate::state::{show_main, AppState, Core, ServiceSlot, TauriEvents};

fn main() {
    // `--test-secure-desktop [--no-switch]`: open the separate-desktop prompt once with an
    // 8-second timer and write what happened to %TEMP%\keyholder-desktop-test.txt (no app, no
    // vault). `--no-switch` shows the same window on the current desktop; `--hang` (debug builds)
    // freezes the window to exercise the watchdog.
    if std::env::args().any(|a| a == "--test-secure-desktop") {
        desktop_test();
        return;
    }
    let background = std::env::args().any(|a| a == "--background");
    // A debug build on its own test vault (KH_DATA_DIR) may run next to the installed app.
    let test_vault = cfg!(debug_assertions) && std::env::var_os("KH_DATA_DIR").is_some();

    let mut builder = tauri::Builder::default();
    if !test_vault {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            if !args.iter().any(|a| a == "--background") {
                show_main(app);
            }
        }));
    }
    builder
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .setup(move |app| build(app, background))
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                match window.label() {
                    // Closing the main window keeps KeyHolder running in the tray for agents.
                    "main" => {
                        api.prevent_close();
                        let _ = window.hide();
                    }
                    "approve" => {
                        api.prevent_close();
                        let app = window.app_handle().clone();
                        tauri::async_runtime::spawn(async move {
                            commands::close_front(&app).await;
                        });
                    }
                    _ => {}
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::kh_call,
            commands::status,
            commands::copy_value,
            commands::import_read,
            commands::import_commit,
            commands::setup_begin,
            commands::qr_svg,
            commands::approval_native,
            commands::approval_closed,
            commands::stepup_native,
            commands::hello_available,
            commands::stepup_hello,
            commands::approval_hello,
            commands::unlock_native,
            commands::login_native,
            commands::export_vault_file,
            commands::save_vault_backup,
            commands::import_vault_native,
            commands::import_vault_file,
            commands::service_status,
            commands::install_service,
            commands::uninstall_service,
        ])
        .run(tauri::generate_context!())
        .expect("KeyHolder failed to start");
}

fn desktop_test() {
    desktop::GIVE_UP_OVERRIDE_MS.store(8_000, std::sync::atomic::Ordering::Relaxed);
    if std::env::args().any(|a| a == "--no-switch") {
        // The screen stays usable, so the window may stay longer for a look.
        desktop::TEST_NO_SWITCH.store(true, std::sync::atomic::Ordering::Relaxed);
        desktop::GIVE_UP_OVERRIDE_MS.store(20_000, std::sync::atomic::Ordering::Relaxed);
    }
    if std::env::args().any(|a| a == "--hang") {
        desktop::TEST_HANG.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let started = std::time::Instant::now();
    let r = desktop::prompt(desktop::Prompt {
        heading: "Confirmation window test".into(),
        facts: vec![("What is this".into(), "test: the window closes by itself in a few seconds".into())],
        agent_note: None,
        antiphish: "test".into(),
        field: desktop::Field::Password,
        noise: if std::env::args().any(|a| a == "--plain") {
            None
        } else {
            kh_core::parse_noise_colors(&kh_core::default_noise_colors())
        },
    });
    let report = format!(
        "available={} elapsed_ms={} result={}\n",
        desktop::available(),
        started.elapsed().as_millis(),
        match r {
            Ok(_) => "ok (a value was entered)".to_string(),
            Err(e) => format!("err: {e}"),
        }
    );
    let _ = std::fs::write(std::env::temp_dir().join("keyholder-desktop-test.txt"), report);
}

fn build(app: &mut tauri::App, background: bool) -> Result<(), Box<dyn std::error::Error>> {
    // No crash dumps: they would contain decrypted keys.
    kh_core::mem::exclude_from_wer(if cfg!(windows) { "keyholder.exe" } else { "keyholder" });
    // KH_DATA_DIR: a separate vault for development and end-to-end tests.
    let data_dir = match std::env::var_os("KH_DATA_DIR") {
        Some(d) => std::path::PathBuf::from(d),
        None => app.path().app_data_dir()?,
    };
    let kh_name = if cfg!(windows) { "kh.exe" } else { "kh" };
    let kh_path = std::env::current_exe()?.with_file_name(kh_name).to_string_lossy().to_string();
    let sid = kh_core::ipc::current_user_sid().unwrap_or_default();

    let service_cfg = service::installed();
    let service_installed = service_cfg.is_some();

    // In service mode the app starts with Windows so approval windows can appear.
    service::set_autostart(service_installed);
    service::remember_install_dir();
    let core = if service_installed {
        // The service owns the vault: the portable file from before the move is put aside.
        service::retire_portable(&data_dir.join("vault.db"));
        let slot = Arc::new(ServiceSlot::new(app.handle().clone()));
        // First connection now; if the service is still starting, the next call retries.
        let s2 = slot.clone();
        let _ = tauri::async_runtime::block_on(async move { s2.call("status", json!({})).await });
        Core::Service(slot)
    } else {
        let vault = Vault::open(&data_dir.join("vault.db"))?;
        let d = Daemon::new(vault, Runtime::Portable, kh_path.clone(), data_dir.clone());
        d.set_events(Arc::new(TauriEvents::new(app.handle().clone())));
        // Debug only: KH_NO_AGENT_PIPE=1 leaves the agent channel to the installed app.
        if !(cfg!(debug_assertions) && std::env::var("KH_NO_AGENT_PIPE").as_deref() == Ok("1")) {
            tauri::async_runtime::spawn(kh_daemon::channel::serve_agent(d.clone(), sid));
        }
        tauri::async_runtime::spawn(kh_daemon::autolock::run(d.clone()));
        Core::Local(d)
    };

    app.manage(AppState { core, data_dir, service_installed });

    let open = MenuItem::with_id(app, "open", "Open MCP Keyholder", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", "Lock", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &lock, &sep, &quit])?;
    let mut tray = TrayIconBuilder::with_id("main")
        .tooltip("MCP Keyholder")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, e| match e.id.as_ref() {
            "open" => show_main(app),
            "lock" => {
                let st = app.state::<AppState>();
                if let Some(d) = st.local().cloned() {
                    d.lock_vault("the vault was locked");
                } else if let Some(c) = st.service_client() {
                    tauri::async_runtime::spawn(async move {
                        let _ = c.call("lock", json!({})).await;
                    });
                }
            }
            "quit" => {
                if let Some(d) = app.state::<AppState>().local() {
                    d.vault().lock();
                }
                let _ = app.emit("kh-quit", ());
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, e| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = e {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;

    // Lock on session lock, sleep and logoff; in service mode the app tells the service.
    session_watch::spawn(app.handle().clone());

    // Debug builds only: allow screenshots of the UI for design review.
    #[cfg(debug_assertions)]
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.set_content_protected(false);
    }
    if !background {
        show_main(app.handle());
    }
    Ok(())
}

//! KeyHolder service: the core under `NT SERVICE\KeyHolder`.
//!
//!   keyholder-service                       run as a Windows service (started by the SCM)
//!   keyholder-service --console [--data-dir DIR] [--owner SID]
//!   keyholder-service install [--source vault.db] [--owner SID]
//!   keyholder-service uninstall [--restore DIR]
//!   keyholder-service status
//!
//! `install` and `uninstall` need administrator rights; the app starts them through UAC.

mod app;
#[cfg(windows)]
mod win;

use std::path::PathBuf;

#[derive(Debug)]
pub enum Cmd {
    /// Started by the service control manager.
    Run,
    Console {
        data_dir: Option<PathBuf>,
        owner: Option<String>,
    },
    Install {
        source: Option<PathBuf>,
        owner: Option<String>,
        app: Option<String>,
    },
    Uninstall {
        restore: Option<PathBuf>,
    },
    Status,
    Help,
}

fn parse(args: Vec<String>) -> Cmd {
    let mut console = false;
    let mut data_dir = None;
    let mut owner = None;
    let mut source = None;
    let mut restore = None;
    let mut app = None;
    let mut sub: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "install" | "uninstall" | "status" | "help" | "--help" | "-h" if sub.is_none() => {
                sub = Some(args[i].clone());
            }
            "--console" => console = true,
            "--data-dir" => {
                i += 1;
                data_dir = args.get(i).map(PathBuf::from);
            }
            "--owner" => {
                i += 1;
                owner = args.get(i).cloned();
            }
            "--source" => {
                i += 1;
                source = args.get(i).map(PathBuf::from);
            }
            "--restore" => {
                i += 1;
                restore = args.get(i).map(PathBuf::from);
            }
            "--app" => {
                i += 1;
                app = args.get(i).cloned();
            }
            "--log" => {
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    match sub.as_deref() {
        Some("install") => Cmd::Install { source, owner, app },
        Some("uninstall") => Cmd::Uninstall { restore },
        Some("status") => Cmd::Status,
        Some(_) => Cmd::Help,
        None if console => Cmd::Console { data_dir, owner },
        None => Cmd::Run,
    }
}

fn usage() -> ! {
    eprintln!(
        "keyholder-service — ядро MCP Keyholder под отдельной учётной записью\n\
         \n  keyholder-service                         запуск службы (из диспетчера служб)\
         \n  keyholder-service --console [--data-dir DIR] [--owner SID]\
         \n  keyholder-service install [--source vault.db] [--owner SID] [--app keyholder.exe] [--log FILE]\
         \n  keyholder-service uninstall [--restore DIR]\
         \n  keyholder-service status\n"
    );
    std::process::exit(2)
}

/// Windows consoles interpret bytes with the OEM code page; UTF-8 keeps the Russian text readable.
#[cfg(windows)]
fn utf8_console() {
    use windows_sys::Win32::System::Console::{SetConsoleCP, SetConsoleOutputCP};
    unsafe {
        SetConsoleOutputCP(65001);
        SetConsoleCP(65001);
    }
}

#[cfg(not(windows))]
fn utf8_console() {}

fn main() {
    utf8_console();
    // No crash dumps: they would contain decrypted keys.
    kh_core::mem::exclude_from_wer(if cfg!(windows) { "keyholder-service.exe" } else { "keyholder-service" });
    let cmd = parse(std::env::args().skip(1).collect());
    let result = match cmd {
        Cmd::Help => usage(),
        #[cfg(windows)]
        Cmd::Run => win::dispatch().map_err(|e| anyhow::anyhow!(e)),
        #[cfg(not(windows))]
        Cmd::Run => Err(anyhow::anyhow!("служба есть только в Windows; используйте --console")),
        Cmd::Console { data_dir, owner } => {
            let data_dir = data_dir.unwrap_or_else(default_dev_dir);
            let owner = match owner {
                Some(o) => o,
                None => kh_core::ipc::current_user_sid().unwrap_or_default(),
            };
            let kh_path = std::env::current_exe()
                .ok()
                .map(|p| p.with_file_name(if cfg!(windows) { "kh.exe" } else { "kh" }).to_string_lossy().to_string())
                .unwrap_or_else(|| "kh".into());
            eprintln!("MCP Keyholder: режим консоли, данные в {}", data_dir.display());
            let (tx, rx) = tokio::sync::oneshot::channel();
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build();
            let r = match rt {
                Ok(rt) => rt.block_on(app::serve(
                    app::Settings { data_dir, kh_path, owner_sid: owner },
                    rx,
                )),
                Err(e) => Err(anyhow::anyhow!(e)),
            };
            // Ctrl+C in the console is the stop signal for development mode.
            let _ = tx;
            r
        }
        #[cfg(windows)]
        Cmd::Install { source, owner, app } => win::install(source, owner, app),
        #[cfg(not(windows))]
        Cmd::Install { .. } => Err(anyhow::anyhow!("режим службы есть только в Windows")),
        #[cfg(windows)]
        Cmd::Uninstall { restore } => win::uninstall(restore),
        #[cfg(not(windows))]
        Cmd::Uninstall { .. } => Err(anyhow::anyhow!("режим службы есть только в Windows")),
        #[cfg(windows)]
        Cmd::Status => win::status(),
        #[cfg(not(windows))]
        Cmd::Status => Err(anyhow::anyhow!("режим службы есть только в Windows")),
    };
    if let Err(e) = result {
        eprintln!("Ошибка: {e:#}");
        // The app starts install/uninstall elevated without a console: leave the reason in a file.
        if let Some(path) = log_path() {
            let _ = std::fs::write(path, format!("{e:#}"));
        }
        std::process::exit(1);
    }
}

fn log_path() -> Option<PathBuf> {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == "--log").and_then(|i| args.get(i + 1)).map(PathBuf::from)
}

fn default_dev_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .unwrap_or_else(std::env::temp_dir);
    base.join("KeyHolder").join("service-dev")
}

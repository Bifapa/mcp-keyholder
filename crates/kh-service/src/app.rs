//! The daemon side of the service: open the vault, serve both channels, publish events.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use kh_core::LoginMode;
use kh_core::Vault;
use kh_daemon::channel::{self, UiEvents};
use kh_daemon::{autolock, Daemon, Events, Runtime};

pub struct Settings {
    pub data_dir: PathBuf,
    pub kh_path: String,
    pub owner_sid: String,
}

/// Events for the app: the service has no windows, so everything goes over the interface channel.
struct ChannelEvents {
    tx: UiEvents,
}

impl Events for ChannelEvents {
    fn changed(&self, what: &str) {
        let _ = self.tx.send(what.to_string());
    }
    fn show_approval(&self) {
        let _ = self.tx.send("approvals".into());
    }
    fn show_main(&self) {
        let _ = self.tx.send("unlock-needed".into());
    }
    fn close_approval(&self) {
        let _ = self.tx.send("approvals".into());
    }
}

pub async fn serve(s: Settings, shutdown: tokio::sync::oneshot::Receiver<()>) -> Result<()> {
    std::fs::create_dir_all(&s.data_dir).with_context(|| format!("каталог данных {}", s.data_dir.display()))?;
    let mut vault = Vault::open(&s.data_dir.join("vault.db")).context("открытие хранилища")?;

    // Keys live under DPAPI for the service account, so the service starts without a human.
    let full_lock = vault.startup_full_lock();
    if vault.is_initialized() && !full_lock {
        match vault.unlock_dpapi() {
            Ok(true) => eprintln!("MCP Keyholder: ключи восстановлены (DPAPI)"),
            Ok(false) => eprintln!("MCP Keyholder: хранилище ждёт мастер-пароль"),
            Err(e) => eprintln!("MCP Keyholder: ключи службы не открылись: {e}"),
        }
    } else if full_lock {
        eprintln!("MCP Keyholder: полная блокировка — нужен мастер-пароль");
    }

    let d = Daemon::new(vault, Runtime::Service, s.kh_path, s.data_dir.clone());
    let events = channel::ui_events();
    d.set_events(Arc::new(ChannelEvents { tx: events.clone() }));

    // The interface is opened by "nothing", PIN, OTP or the password; agents keep working either way.
    if d.vault().is_unlocked() {
        let mode = d.vault().settings().map(|x| x.login_mode).unwrap_or(LoginMode::Password);
        d.set_ui_unlocked(mode == LoginMode::Nothing);
    } else {
        d.set_ui_unlocked(false);
    }

    tokio::spawn(channel::serve_agent(d.clone(), s.owner_sid.clone()));
    tokio::spawn(channel::serve_ui(d.clone(), s.owner_sid.clone(), events));
    tokio::spawn(autolock::run(d.clone()));

    // Run until the process is asked to stop.
    tokio::select! {
        _ = shutdown => eprintln!("MCP Keyholder: остановка службы"),
        _ = std::future::pending::<()>() => {}
    }
    Ok(())
}

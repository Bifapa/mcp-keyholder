//! KeyHolder daemon: everything that touches the vault, agent sessions and approvals,
//! with no UI dependencies.
//!
//! The same code runs in two places:
//!   * inside the app (portable mode) — `Runtime::Portable`;
//!   * inside `keyholder-service.exe` under `NT SERVICE\KeyHolder` (protected mode) —
//!     `Runtime::Service`, where the app talks to it over the interface channel and
//!     `call(method, params)` is the only entry point from the UI.
//!
//! UI work (windows, secure desktop, clipboard) lives in the app and is reached through
//! the [`Events`] trait so the daemon never depends on a windowing library.

pub mod agent;
pub mod autolock;
pub mod broker;
pub mod channel;
pub mod ui;

use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use kh_core::vault::PendingSetup;
use kh_core::{now_ms, Vault};
use serde::Serialize;

use crate::broker::Broker;

/// How long a step-up (master password + code) stays valid.
pub const STEPUP_MS: i64 = 3 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Runtime {
    /// The core runs inside the app, under the user's account.
    Portable,
    /// The core runs as a Windows service under a separate account.
    Service,
}

impl Runtime {
    pub fn as_str(self) -> &'static str {
        match self {
            Runtime::Portable => "portable",
            Runtime::Service => "service",
        }
    }
}

/// Callbacks into the UI process. Never called from the service for window work — in
/// service mode the daemon only publishes change events over the interface channel.
pub trait Events: Send + Sync {
    /// Something the UI shows has changed (`vault`, `grants`, `approvals`, `lock`, …).
    fn changed(&self, what: &str);
    /// Show (or refresh) the approval surface.
    fn show_approval(&self);
    /// Bring the main window up — the vault needs the human.
    fn show_main(&self);
    /// Remove the approval surface (nothing left to decide).
    fn close_approval(&self);
    /// Ask the human to prove presence (Windows Hello) with `message` shown in the system
    /// dialog. Only implementations that run the dialog themselves may return `Ok`.
    fn verify_presence(&self, _message: &str) -> Result<(), String> {
        Err("Windows Hello is not available here".into())
    }
}

pub struct Daemon {
    pub vault: Mutex<Vault>,
    pub broker: Broker,
    pub pending_setup: Mutex<Option<PendingSetup>>,
    pub elevated_until: AtomicI64,
    /// Last activity of anyone (human or agent): portable auto-lock and service full lock.
    pub last_activity: AtomicI64,
    /// Last thing the human did in the interface: service-mode interface lock.
    pub ui_activity: AtomicI64,
    pub unlock_notify: tokio::sync::Notify,
    pub pipe_alarm: Mutex<Option<String>>,
    /// Absolute path of `kh.exe` shipped next to the app (for MCP config snippets).
    pub kh_path: String,
    pub runtime: Runtime,
    pub data_dir: PathBuf,
    /// Service mode only: whether the interface is unlocked (nothing / PIN / OTP gate).
    ui_unlocked: std::sync::atomic::AtomicBool,
    /// `.mcpkey` files in transit: the interface channel carries them in chunks.
    pub transfer: Mutex<Transfer>,
    events: RwLock<Option<Arc<dyn Events>>>,
}

#[derive(Default)]
pub struct Transfer {
    pub export: Option<Vec<u8>>,
    pub import: Vec<u8>,
}

impl Daemon {
    pub fn new(vault: Vault, runtime: Runtime, kh_path: String, data_dir: PathBuf) -> Arc<Daemon> {
        Arc::new(Daemon {
            vault: Mutex::new(vault),
            broker: Broker::default(),
            pending_setup: Mutex::new(None),
            elevated_until: AtomicI64::new(0),
            last_activity: AtomicI64::new(now_ms()),
            ui_activity: AtomicI64::new(now_ms()),
            unlock_notify: tokio::sync::Notify::new(),
            pipe_alarm: Mutex::new(None),
            kh_path,
            runtime,
            data_dir,
            ui_unlocked: std::sync::atomic::AtomicBool::new(true),
            transfer: Mutex::new(Transfer::default()),
            events: RwLock::new(None),
        })
    }

    pub fn vault(&self) -> MutexGuard<'_, Vault> {
        self.vault.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_events(&self, events: Arc<dyn Events>) {
        *self.events.write().unwrap_or_else(|e| e.into_inner()) = Some(events);
    }

    pub fn emit(&self, what: &str) {
        if let Some(e) = self.events.read().unwrap_or_else(|x| x.into_inner()).as_ref() {
            e.changed(what);
        }
    }

    pub fn show_approval(&self) {
        if let Some(e) = self.events.read().unwrap_or_else(|x| x.into_inner()).as_ref() {
            e.show_approval();
        }
    }

    pub fn show_main(&self) {
        if let Some(e) = self.events.read().unwrap_or_else(|x| x.into_inner()).as_ref() {
            e.show_main();
        }
    }

    pub fn close_approval(&self) {
        if let Some(e) = self.events.read().unwrap_or_else(|x| x.into_inner()).as_ref() {
            e.close_approval();
        }
    }

    /// Runs the presence check through the UI process. Blocks until the human answers.
    pub fn verify_presence(&self, message: &str) -> Result<(), String> {
        let events = self.events.read().unwrap_or_else(|x| x.into_inner()).clone();
        match events {
            Some(e) => e.verify_presence(message),
            None => Err("Windows Hello is not available here".into()),
        }
    }

    pub fn ui_unlocked(&self) -> bool {
        self.ui_unlocked.load(Ordering::Relaxed)
    }

    pub fn set_ui_unlocked(&self, v: bool) {
        self.ui_unlocked.store(v, Ordering::Relaxed);
        self.emit(if v { "unlock" } else { "lock" });
    }

    /// Agent activity: keeps the vault open in portable mode, not the service interface.
    pub fn touch(&self) {
        self.last_activity.store(now_ms(), Ordering::Relaxed);
    }

    /// Something the human did in the interface.
    pub fn touch_ui(&self) {
        let now = now_ms();
        self.last_activity.store(now, Ordering::Relaxed);
        self.ui_activity.store(now, Ordering::Relaxed);
    }

    pub fn is_elevated(&self) -> bool {
        self.elevated_until.load(Ordering::Relaxed) > now_ms()
    }

    pub fn require_elevated(&self) -> Result<(), String> {
        if self.is_elevated() {
            Ok(())
        } else {
            Err("stepup_required".into())
        }
    }

    /// Locks the vault and drops every grant, ticket and pending request.
    pub fn lock_vault(&self, why: &str) {
        self.vault().lock();
        self.elevated_until.store(0, Ordering::Relaxed);
        self.broker.clear_all(why);
        self.close_approval();
        self.emit("lock");
    }

    /// Before the vault moves into the service: drop the keys and make the file self-contained.
    pub fn prepare_migration(&self) -> Result<(), String> {
        self.lock_vault("switching to service mode");
        self.vault().checkpoint().map_err(err_str)
    }

    /// The Windows session locked, went to sleep or the user logged off.
    ///
    /// Portable mode drops the keys; the service only closes the interface unless full lock
    /// is on, because agents keep working through it.
    pub fn lock_ui(&self) {
        let full_lock = self.vault().settings().map(|s| s.full_lock).unwrap_or(false);
        if self.runtime == Runtime::Service && !full_lock {
            self.elevated_until.store(0, Ordering::Relaxed);
            self.set_ui_unlocked(false);
        } else {
            self.lock_vault("the Windows session was locked");
        }
    }

    pub fn set_pipe_alarm(&self, msg: Option<String>) {
        *self.pipe_alarm.lock().unwrap_or_else(|e| e.into_inner()) = msg.clone();
        if let Some(m) = msg {
            self.emit(&format!("alarm:{m}"));
        }
    }

    pub fn pipe_alarm(&self) -> Option<String> {
        self.pipe_alarm.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Data shown in the UI header and in `kh status`.
    pub fn status(&self) -> serde_json::Value {
        let v = self.vault();
        serde_json::json!({
            "initialized": v.is_initialized(),
            "unlocked": v.is_unlocked(),
            "version": env!("CARGO_PKG_VERSION"),
            "pipeAlarm": self.pipe_alarm(),
            "otpLockedUntil": v.otp_locked_until(),
            "elevatedUntil": self.elevated_until.load(Ordering::Relaxed),
            "khPath": self.kh_path,
            "vaultPath": v.path().display().to_string(),
            "pending": self.broker.queue_len(),
            "hasPin": v.is_unlocked() && v.has_pin(),
            "runtime": self.runtime.as_str(),
            "uiLocked": self.runtime == Runtime::Service && !self.ui_unlocked(),
            "dataDir": self.data_dir.display().to_string(),
            "loginMode": v.settings().map(|s| s.login_mode.as_str()).unwrap_or("password"),
        })
    }
}

/// Result of a UI call: JSON on success, a human-readable message on failure.
pub type CallResult = Result<serde_json::Value, String>;

pub(crate) fn err_str(e: kh_core::Error) -> String {
    e.to_string()
}

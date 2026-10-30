//! App state: either the core running in-process (portable mode) or a client for the
//! KeyHolder service, plus window helpers shared by both.

use std::sync::Arc;

use kh_daemon::{Daemon, Events};
use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager};

use crate::client::ServiceClient;

pub enum Core {
    /// Portable mode: the daemon lives in this process.
    Local(Arc<Daemon>),
    /// Service mode: every command goes over the interface channel. We never open a second,
    /// shadow vault next to the service, even when it is unreachable.
    Service(Arc<ServiceSlot>),
}

/// Connection to the service that comes back by itself after a service restart.
pub struct ServiceSlot {
    app: AppHandle,
    client: tokio::sync::Mutex<Option<Arc<ServiceClient>>>,
    last_error: std::sync::Mutex<Option<String>>,
}

impl ServiceSlot {
    pub fn new(app: AppHandle) -> ServiceSlot {
        ServiceSlot { app, client: tokio::sync::Mutex::new(None), last_error: std::sync::Mutex::new(None) }
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    async fn client(&self) -> Result<Arc<ServiceClient>, String> {
        let mut g = self.client.lock().await;
        if let Some(c) = g.as_ref() {
            if c.is_alive() {
                return Ok(c.clone());
            }
        }
        match ServiceClient::connect(self.app.clone()).await {
            Ok(c) => {
                let reconnect = g.is_some();
                *g = Some(c.clone());
                *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = None;
                if reconnect {
                    let _ = self.app.emit("kh-changed", "reconnected");
                }
                Ok(c)
            }
            Err(e) => {
                let msg = format!("Режим службы включён, но служба недоступна: {e}");
                *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(msg.clone());
                Err(msg)
            }
        }
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        self.client().await?.call(method, params).await
    }
}

pub struct AppState {
    pub core: Core,
    pub data_dir: std::path::PathBuf,
    pub service_installed: bool,
}

impl AppState {
    pub fn local(&self) -> Option<&Arc<Daemon>> {
        match &self.core {
            Core::Local(d) => Some(d),
            _ => None,
        }
    }

    pub fn service_client(&self) -> Option<Arc<ServiceSlot>> {
        match &self.core {
            Core::Service(c) => Some(c.clone()),
            _ => None,
        }
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        match &self.core {
            Core::Local(d) => {
                let d = d.clone();
                let m = method.to_string();
                tokio::task::spawn_blocking(move || d.call(&m, params))
                    .await
                    .map_err(|e| format!("ошибка ядра: {e}"))?
            }
            Core::Service(c) => c.call(method, params).await,
        }
    }

}

/// Tells every window that something changed; the UI re-fetches what it shows.
pub fn changed(app: &AppHandle, what: &str) {
    let _ = app.emit("kh-changed", what);
}

pub fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

pub fn close_approval_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("approve") {
        let _ = w.destroy();
    }
}

/// Opens (or refreshes) the approval popup: on top, excluded from screen capture,
/// and not stealing keyboard focus until clicked.
pub fn show_approval_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("approve") {
        let _ = w.show();
        changed(app, "approvals");
        return;
    }
    let built = tauri::WebviewWindowBuilder::new(app, "approve", tauri::WebviewUrl::App("approve.html".into()))
        .title("MCP Keyholder — запрос доступа")
        .inner_size(480.0, 830.0)
        .resizable(false)
        .maximizable(false)
        .minimizable(false)
        .always_on_top(true)
        .content_protected(!cfg!(debug_assertions))
        .focused(false)
        .center()
        .build();
    if let Err(e) = built {
        eprintln!("approval window: {e}");
    }
}

/// Service mode: the service publishes "approvals" as an event; open or close the popup
/// to match what is actually queued there.
pub fn sync_approval_window(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let Some(st) = app.try_state::<AppState>() else { return };
        let Ok(v) = st.call("approval_current", serde_json::json!({})).await else { return };
        if v.get("request").map(|r| !r.is_null()).unwrap_or(false) {
            show_approval_window(&app);
        } else {
            close_approval_window(&app);
        }
    });
}

/// Bridges daemon events to the webview and to windows.
pub struct TauriEvents {
    app: AppHandle,
}

impl TauriEvents {
    pub fn new(app: AppHandle) -> Self {
        TauriEvents { app }
    }
}

impl Events for TauriEvents {
    fn changed(&self, what: &str) {
        let _ = self.app.emit("kh-changed", what);
    }

    fn show_approval(&self) {
        show_approval_window(&self.app);
    }

    fn show_main(&self) {
        show_main(&self.app);
    }

    fn close_approval(&self) {
        close_approval_window(&self.app);
    }

    /// Portable mode only: the core asks, this process shows the Windows Hello dialog.
    fn verify_presence(&self, message: &str) -> Result<(), String> {
        crate::hello::verify(message)
    }
}

//! Client for the core when it runs as the KeyHolder service.
//!
//! One connection carries every `call(method, params)` the UI makes, and change events
//! from the service are forwarded to the webview so it refreshes just like in portable mode.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kh_core::protocol::{ClientMsg, ServerMsg, PROTOCOL_VERSION};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};
use tauri::{AppHandle, Emitter};

const CALL_TIMEOUT: Duration = Duration::from_secs(200);

type Pending = Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>;

pub struct ServiceClient {
    tx: mpsc::UnboundedSender<String>,
    pending: Arc<Pending>,
    next: AtomicU64,
    alive: Arc<std::sync::atomic::AtomicBool>,
}

impl ServiceClient {
    pub async fn connect(app: AppHandle) -> Result<Arc<ServiceClient>, String> {
        let sid = kh_core::ipc::current_user_sid().map_err(|e| format!("не удалось определить пользователя: {e}"))?;
        let name = kh_core::ipc::ui_pipe_name(&sid);
        let stream = tokio::time::timeout(Duration::from_secs(3), kh_core::ipc::connect_named(&name))
            .await
            .map_err(|_| "служба MCP Keyholder не отвечает".to_string())?
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => "служба MCP Keyholder не запущена".to_string(),
                _ => format!("не удалось подключиться к службе MCP Keyholder: {e}"),
            })?;

        let (rd, mut wr) = tokio::io::split(stream);
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));

        let ok = serde_json::to_string(&ClientMsg::Hello {
            protocol: PROTOCOL_VERSION,
            token: None,
            purpose: "ui".into(),
            pid: std::process::id(),
        })
        .unwrap_or_default();
        wr.write_all(format!("{ok}\n").as_bytes()).await.map_err(|e| e.to_string())?;
        wr.flush().await.map_err(|e| e.to_string())?;

        let client = Arc::new(ServiceClient {
            tx,
            pending: Arc::new(Mutex::new(HashMap::new())),
            next: AtomicU64::new(1),
            alive: alive.clone(),
        });

        // Writer.
        tokio::spawn(async move {
            while let Some(line) = rx.recv().await {
                if wr.write_all(line.as_bytes()).await.is_err() || wr.flush().await.is_err() {
                    break;
                }
            }
        });

        // Reader: responses to waiting calls, events to every window.
        let pending = client.pending.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(rd).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let Ok(msg) = serde_json::from_str::<ServerMsg>(&line) else { continue };
                match msg {
                    ServerMsg::Response { id, ok, result, error } => {
                        if let Some(tx) = pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&id) {
                            let _ = tx.send(if ok { Ok(result) } else { Err(error.unwrap_or_else(|| "ошибка".into())) });
                        }
                    }
                    ServerMsg::Event { what } => {
                        let _ = app.emit("kh-changed", what.clone());
                        if what == "approvals" {
                            // The service cannot show windows: the app opens the approval surface.
                            crate::state::sync_approval_window(&app);
                        }
                    }
                    ServerMsg::Welcome { .. } => {}
                    ServerMsg::Fatal { message } => {
                        let _ = app.emit("kh-changed", format!("fatal:{message}"));
                        break;
                    }
                }
            }
            alive.store(false, Ordering::Relaxed);
            // Fail everything still waiting.
            let mut p = pending.lock().unwrap_or_else(|e| e.into_inner());
            for (_, tx) in p.drain() {
                let _ = tx.send(Err("соединение со службой MCP Keyholder потеряно".into()));
            }
        });

        Ok(client)
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        if !self.is_alive() {
            return Err("служба MCP Keyholder не отвечает — проверьте, запущена ли она".into());
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).insert(id, tx);
        let line = serde_json::to_string(&ClientMsg::Request { id, method: method.to_string(), params })
            .map_err(|e| e.to_string())?;
        if self.tx.send(format!("{line}\n")).is_err() {
            return Err("соединение со службой MCP Keyholder потеряно".into());
        }
        match tokio::time::timeout(CALL_TIMEOUT, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err("соединение со службой MCP Keyholder потеряно".into()),
            Err(_) => {
                self.pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
                Err("служба MCP Keyholder не ответила".into())
            }
        }
    }
}

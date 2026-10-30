//! Dev helper (not shipped): drives the KeyHolder interface channel the way the app does,
//! so service mode can be checked end to end without a window.
//!
//!   cargo run -p kh-service --example ui_client -- <data-dir> <owner-sid> <password> <totp-seed> [otp-key]
//!
//! 1. connect to the interface channel and print the status before unlocking;
//! 2. unlock with the password, print the status and the key list;
//! 3. if an OTP-tier key name is given, answer the agent's pending request with a real code.

use std::time::Duration;

use kh_core::protocol::{ClientMsg, ServerMsg, PROTOCOL_VERSION};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};

struct Ui {
    tx: mpsc::UnboundedSender<String>,
    pending: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<u64, oneshot::Sender<Result<Value, String>>>>>,
    next: std::sync::atomic::AtomicU64,
}

impl Ui {
    async fn connect(sid: &str) -> anyhow::Result<Ui> {
        let name = kh_core::ipc::ui_pipe_name(sid);
        let stream = kh_core::ipc::connect_named(&name).await?;
        let (rd, mut wr) = tokio::io::split(stream);
        let hello = serde_json::to_string(&ClientMsg::Hello {
            protocol: PROTOCOL_VERSION,
            token: None,
            purpose: "ui".into(),
            pid: std::process::id(),
        })?;
        wr.write_all(format!("{hello}\n").as_bytes()).await?;
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            while let Some(line) = rx.recv().await {
                if wr.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
                let _ = wr.flush().await;
            }
        });
        let pending: std::sync::Arc<
            std::sync::Mutex<std::collections::HashMap<u64, oneshot::Sender<Result<Value, String>>>>,
        > = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let p2 = pending.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(rd).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if let Ok(ServerMsg::Response { id, ok, result, error }) = serde_json::from_str::<ServerMsg>(&line) {
                    if let Some(tx) = p2.lock().unwrap().remove(&id) {
                        let _ = tx.send(if ok { Ok(result) } else { Err(error.unwrap_or_default()) });
                    }
                }
            }
        });
        Ok(Ui { tx, pending, next: std::sync::atomic::AtomicU64::new(1) })
    }

    async fn call(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let id = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        let line = serde_json::to_string(&ClientMsg::Request { id, method: method.into(), params })?;
        self.tx.send(format!("{line}\n"))?;
        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(Ok(v))) => Ok(v),
            Ok(Ok(Err(e))) => Err(anyhow::anyhow!("{e}")),
            Ok(Err(_)) => Err(anyhow::anyhow!("interface channel closed")),
            Err(_) => Err(anyhow::anyhow!("call {method} timed out")),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let sid = args.first().cloned().ok_or_else(|| anyhow::anyhow!("owner SID required"))?;
    let password = args.get(1).cloned().unwrap_or_default();
    let seed = args.get(2).cloned().unwrap_or_default();
    let otp_key = args.get(3).cloned();

    let ui = Ui::connect(&sid).await?;
    println!("before unlock: {}", ui.call("status", json!({})).await?);
    if password == "login" {
        // Service mode: `login` opens the interface with the method from the settings.
        let credential = args.get(2).cloned().unwrap_or_default();
        let r = ui.call("login", json!({ "credential": credential })).await;
        println!("login: {r:?}");
        println!("status: {}", ui.call("status", json!({})).await?);
        return Ok(());
    }
    if password == "hello" {
        // Presence proof: approve the pending request as if Windows Hello had verified the human.
        for _ in 0..120 {
            let cur = ui.call("approval_current", json!({})).await?;
            if let Some(req) = cur.get("request").filter(|r| !r.is_null()) {
                let id = req["id"].as_str().unwrap_or_default().to_string();
                let names: Vec<String> = req["keys"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|k| k["name"].as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                std::thread::sleep(Duration::from_millis(1600));
                let r = ui
                    .call(
                        "approval_decide",
                        json!({
                            "id": id, "approve": true, "keep": names,
                            "ttl_minutes": 15, "code": null, "block_session": false, "hello": true
                        }),
                    )
                    .await;
                println!("hello decision: {r:?}");
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
        println!("no request arrived");
        return Ok(());
    }

    if !password.is_empty() {
        ui.call("unlock", json!({ "password": password })).await?;
        println!("after unlock: {}", ui.call("status", json!({})).await?);
        let keys = ui.call("list_keys", json!({})).await?;
        let names: Vec<String> = keys["keys"]
            .as_array()
            .map(|a| a.iter().filter_map(|k| k["name"].as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        println!("keys: {names:?}");
    }

    if let Some(key) = otp_key {
        // Wait for the agent's request and approve it with a real code, like the human would.
        for _ in 0..120 {
            let cur = ui.call("approval_current", json!({})).await?;
            if let Some(req) = cur.get("request").filter(|r| !r.is_null()) {
                let id = req["id"].as_str().unwrap_or_default().to_string();
                let names: Vec<String> = req["keys"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|k| k["name"].as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                println!("request: {} · {}", req["client"], names.join(", "));
                if names.iter().any(|n| n == &key) {
                    std::thread::sleep(Duration::from_millis(1600)); // the 1.5 s guard
                    let step = kh_core::totp::step_at(kh_core::now_ms() / 1000);
                    let raw = data_encoding::BASE32_NOPAD.decode(seed.as_bytes())?;
                    let code = kh_core::totp::code_at_step(&raw, step);
                    let r = ui
                        .call(
                            "approval_decide",
                            json!({
                                "id": id, "approve": true, "keep": names,
                                "ttl_minutes": 15, "code": code, "block_session": false
                            }),
                        )
                        .await;
                    println!("decision: {r:?}");
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        println!("no request arrived");
    }
    Ok(())
}

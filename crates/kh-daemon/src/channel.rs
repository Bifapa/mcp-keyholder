//! Local IPC servers: one session per connection, newline-delimited JSON.
//!
//! Two channels, both restricted by DACL to the user who owns the install (and SYSTEM):
//!   * the agent channel (`keyholder-<sid hash>`) — what `kh mcp` / `kh run` / `kh scan` use;
//!   * the interface channel (`keyholder-ui-<sid hash>`) — what the app uses when the core
//!     runs in the service. Interface commands are never reachable over the agent channel.

use std::sync::Arc;

use kh_core::protocol::{ClientMsg, ServerMsg, MAX_LINE, PROTOCOL_VERSION};
use kh_core::now_ms;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, mpsc};
use zeroize::Zeroizing;

use crate::broker::SessionInfo;
use crate::Daemon;

/// Change notifications for the app, published by the service and forwarded to the webview.
pub type UiEvents = broadcast::Sender<String>;

pub fn ui_events() -> UiEvents {
    broadcast::channel(64).0
}

#[cfg(windows)]
async fn agent_server(owner_sid: &str, first: bool) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    kh_core::ipc::create_server_for(&kh_core::ipc::agent_pipe_name(owner_sid), owner_sid, first)
}

#[cfg(windows)]
async fn ui_server(owner_sid: &str, first: bool) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    kh_core::ipc::create_server_for(&kh_core::ipc::ui_pipe_name(owner_sid), owner_sid, first)
}

/// Serves the agent channel for the user with SID `owner_sid`.
#[cfg(windows)]
pub async fn serve_agent(d: Arc<Daemon>, owner_sid: String) {
    use kh_core::ipc;
    let mut server = match agent_server(&owner_sid, true).await {
        Ok(s) => s,
        Err(e) => {
            d.set_pipe_alarm(Some(format!(
                "Канал MCP Keyholder уже занят другим процессом ({e}). Агенты не смогут подключиться. \
                 Если MCP Keyholder не запущен второй раз, кто-то может выдавать себя за MCP Keyholder — проверьте компьютер."
            )));
            return;
        }
    };
    loop {
        if let Err(e) = server.connect().await {
            eprintln!("pipe connect: {e}");
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            continue;
        }
        let pid = ipc::client_pid(&server).unwrap_or(0);
        let conn = server;
        // A failed instance must not stop the channel for good: retry until it works.
        server = loop {
            match agent_server(&owner_sid, false).await {
                Ok(s) => break s,
                Err(e) => {
                    eprintln!("pipe create: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        };
        let d2 = d.clone();
        tokio::spawn(async move {
            let process = if pid != 0 { ipc::process_chain(pid, 3) } else { String::new() };
            handle_agent_conn(d2, conn, process).await;
        });
    }
}

#[cfg(windows)]
pub async fn serve_ui(d: Arc<Daemon>, owner_sid: String, events: UiEvents) {
    let mut server = match ui_server(&owner_sid, true).await {
        Ok(s) => s,
        Err(e) => {
            d.set_pipe_alarm(Some(format!(
                "Канал интерфейса MCP Keyholder уже занят другим процессом ({e}). Приложение не сможет подключиться к службе."
            )));
            return;
        }
    };
    loop {
        if let Err(e) = server.connect().await {
            eprintln!("ui pipe connect: {e}");
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            continue;
        }
        let conn = server;
        server = loop {
            match ui_server(&owner_sid, false).await {
                Ok(s) => break s,
                Err(e) => {
                    eprintln!("ui pipe create: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        };
        let d2 = d.clone();
        let ev = events.clone();
        tokio::spawn(async move { handle_ui_conn(d2, conn, ev).await });
    }
}

#[cfg(unix)]
pub async fn serve_agent(d: Arc<Daemon>, _owner_sid: String) {
    use std::os::unix::fs::PermissionsExt;
    let path = kh_core::ipc::socket_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let _ = std::fs::remove_file(&path);
    let listener = match tokio::net::UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            d.set_pipe_alarm(Some(format!("Не удалось открыть сокет MCP Keyholder: {e}")));
            return;
        }
    };
    loop {
        if let Ok((stream, _)) = listener.accept().await {
            let d2 = d.clone();
            tokio::spawn(async move { handle_agent_conn(d2, stream, String::new()).await });
        }
    }
}

#[cfg(unix)]
pub async fn serve_ui(d: Arc<Daemon>, _owner_sid: String, events: UiEvents) {
    use std::os::unix::fs::PermissionsExt;
    let path = kh_core::ipc::ui_socket_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let _ = std::fs::remove_file(&path);
    let listener = match tokio::net::UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ui socket: {e}");
            return;
        }
    };
    loop {
        if let Ok((stream, _)) = listener.accept().await {
            let d2 = d.clone();
            let ev = events.clone();
            tokio::spawn(async move { handle_ui_conn(d2, stream, ev).await });
        }
    }
}

async fn read_line<R: AsyncRead + Unpin>(r: &mut BufReader<R>) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new();
    let n = r.take(MAX_LINE as u64 + 1).read_until(b'\n', &mut buf).await?;
    if n == 0 {
        return Ok(None);
    }
    if buf.len() > MAX_LINE {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "line too long"));
    }
    Ok(Some(String::from_utf8_lossy(&buf).trim_end().to_string()))
}

async fn write_loop<W: AsyncWrite + Unpin>(mut wr: W, mut rx: mpsc::UnboundedReceiver<ServerMsg>) {
    while let Some(msg) = rx.recv().await {
        let mut line = serde_json::to_vec(&msg).unwrap_or_default();
        line.push(b'\n');
        if wr.write_all(&line).await.is_err() {
            break;
        }
        let _ = wr.flush().await;
    }
}

async fn handle_agent_conn<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(d: Arc<Daemon>, stream: S, process: String) {
    let (rd, wr) = tokio::io::split(stream);
    let mut rd = BufReader::new(rd);
    let (tx, rx) = mpsc::unbounded_channel::<ServerMsg>();
    let writer = tokio::spawn(write_loop(wr, rx));

    // First message must be Hello, within 5 s.
    let hello = tokio::time::timeout(std::time::Duration::from_secs(5), read_line(&mut rd)).await;
    let Ok(Ok(Some(line))) = hello else {
        writer.abort();
        return;
    };
    let Ok(ClientMsg::Hello { protocol, token, purpose, .. }) = serde_json::from_str::<ClientMsg>(&line) else {
        let _ = tx.send(ServerMsg::Fatal { message: "ожидалось приветствие".into() });
        drop(tx);
        let _ = writer.await;
        return;
    };
    if protocol != PROTOCOL_VERSION {
        let _ = tx.send(ServerMsg::Fatal { message: format!("версия протокола {protocol} не поддерживается, нужна {PROTOCOL_VERSION}") });
        drop(tx);
        let _ = writer.await;
        return;
    }
    let purpose = match purpose.as_str() {
        "mcp" | "run" | "scan" | "status" => purpose,
        _ => "mcp".to_string(),
    };

    let session_id = uuid::Uuid::new_v4().to_string();
    d.broker.add_session(SessionInfo {
        id: session_id.clone(),
        purpose: purpose.clone(),
        client_id: None,
        client: "—".into(),
        claimed_client: String::new(),
        process,
        connected_at: now_ms(),
        blocked_until: 0,
        token: token.map(Zeroizing::new),
    });
    let _ = tx.send(ServerMsg::Welcome { session: session_id.clone(), client: None, app_version: env!("CARGO_PKG_VERSION").into() });
    if purpose == "mcp" {
        d.emit("sessions");
    }

    loop {
        let line = match read_line(&mut rd).await {
            Ok(Some(l)) => l,
            _ => break,
        };
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<ClientMsg>(&line) {
            Ok(ClientMsg::ClientInfo { name, version }) => {
                let claimed = kh_core::sanitize_untrusted(&format!("{name} {version}"), 80);
                d.broker.update_session(&session_id, |s| s.claimed_client = claimed);
            }
            Ok(ClientMsg::Request { id, method, params }) => {
                let d2 = d.clone();
                let sid = session_id.clone();
                let tx2 = tx.clone();
                tokio::spawn(async move {
                    let msg = match d2.handle_agent(&sid, &method, params).await {
                        Ok(result) => ServerMsg::Response { id, ok: true, result, error: None },
                        Err(e) => ServerMsg::Response { id, ok: false, result: serde_json::Value::Null, error: Some(e) },
                    };
                    let _ = tx2.send(msg);
                });
            }
            Ok(ClientMsg::Hello { .. }) | Err(_) => {
                let _ = tx.send(ServerMsg::Fatal { message: "неверное сообщение".into() });
                break;
            }
        }
    }

    d.broker.end_session(&session_id);
    if purpose == "mcp" {
        d.emit("sessions");
        if d.broker.queue_len() == 0 {
            d.close_approval();
        }
        d.emit("approvals");
    }
    drop(tx);
    let _ = writer.await;
}

/// Interface channel: the app's `call(method, params)`, plus change events.
async fn handle_ui_conn<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(d: Arc<Daemon>, stream: S, events: UiEvents) {
    let (rd, wr) = tokio::io::split(stream);
    let mut rd = BufReader::new(rd);
    let (tx, rx) = mpsc::unbounded_channel::<ServerMsg>();
    let writer = tokio::spawn(write_loop(wr, rx));
    let mut events = events.subscribe();

    let hello = tokio::time::timeout(std::time::Duration::from_secs(5), read_line(&mut rd)).await;
    let Ok(Ok(Some(line))) = hello else {
        writer.abort();
        return;
    };
    let Ok(ClientMsg::Hello { protocol, purpose, .. }) = serde_json::from_str::<ClientMsg>(&line) else {
        let _ = tx.send(ServerMsg::Fatal { message: "ожидалось приветствие".into() });
        drop(tx);
        let _ = writer.await;
        return;
    };
    if protocol != PROTOCOL_VERSION || purpose != "ui" {
        let _ = tx.send(ServerMsg::Fatal { message: "этот канал только для интерфейса MCP Keyholder".into() });
        drop(tx);
        let _ = writer.await;
        return;
    }
    let _ = tx.send(ServerMsg::Welcome {
        session: "ui".into(),
        client: Some("app".into()),
        app_version: env!("CARGO_PKG_VERSION").into(),
    });

    // Forward change events to the app while the connection lives.
    let ev_tx = tx.clone();
    let fwd = tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(what) => {
                    if ev_tx.send(ServerMsg::Event { what }).is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    loop {
        let line = match read_line(&mut rd).await {
            Ok(Some(l)) => l,
            _ => break,
        };
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<ClientMsg>(&line) {
            Ok(ClientMsg::Request { id, method, params }) => {
                let d2 = d.clone();
                let tx2 = tx.clone();
                tokio::spawn(async move {
                    // Interface calls touch the vault (KDF, SQLite): keep them off the async threads.
                    let r = tokio::task::spawn_blocking(move || d2.call(&method, params)).await;
                    let msg = match r {
                        Ok(Ok(result)) => ServerMsg::Response { id, ok: true, result, error: None },
                        Ok(Err(e)) => ServerMsg::Response { id, ok: false, result: serde_json::Value::Null, error: Some(e) },
                        Err(e) => ServerMsg::Response { id, ok: false, result: serde_json::Value::Null, error: Some(e.to_string()) },
                    };
                    let _ = tx2.send(msg);
                });
            }
            Ok(ClientMsg::ClientInfo { .. }) => {}
            Ok(ClientMsg::Hello { .. }) | Err(_) => {
                let _ = tx.send(ServerMsg::Fatal { message: "неверное сообщение".into() });
                break;
            }
        }
    }

    fwd.abort();
    drop(tx);
    let _ = writer.await;
}

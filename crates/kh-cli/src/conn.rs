//! Connection to the KeyHolder app over the local pipe / socket.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kh_core::protocol::{ClientMsg, ServerMsg, PROTOCOL_VERSION};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>>;

pub struct Conn {
    tx: mpsc::UnboundedSender<String>,
    pending: Pending,
    next: AtomicU64,
    alive: Arc<std::sync::atomic::AtomicBool>,
}

pub const DISCONNECTED: &str = "соединение с MCP Keyholder потеряно";

#[cfg(windows)]
async fn open_stream(autostart: bool) -> Result<tokio::net::windows::named_pipe::NamedPipeClient, String> {
    use kh_core::ipc;
    let mut started = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    loop {
        match ipc::connect().await {
            Ok(c) => {
                verify_server(&c)?;
                return Ok(c);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && autostart => {
                if !started {
                    started = true;
                    start_app();
                }
                if tokio::time::Instant::now() > deadline {
                    return Err("MCP Keyholder не запустился".into());
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            Err(e) => return Err(ipc::describe_connect_error(&e)),
        }
    }
}

/// The pipe must belong to KeyHolder itself: the app installed next to this `kh`, or the
/// KeyHolder service (whose binary sits next to `kh` in Program Files and whose process
/// runs under a service account).
#[cfg(windows)]
fn verify_server(c: &tokio::net::windows::named_pipe::NamedPipeClient) -> Result<(), String> {
    if std::env::var("KH_ALLOW_ANY_SERVER").as_deref() == Ok("1") {
        return Ok(());
    }
    let dir = std::env::current_exe().map_err(|e| e.to_string())?.with_file_name("");
    let pid = kh_core::ipc::server_pid(c).ok_or("не удалось определить процесс MCP Keyholder")?;
    let image = kh_core::ipc::process_image(pid).ok_or("не удалось определить путь процесса MCP Keyholder")?;
    let norm = |s: &str| s.replace('/', "\\").to_lowercase();
    let image_n = norm(&image);

    // 0. The installed KeyHolder service, as registered with the service control manager.
    //    This also keeps agents configured with an older `kh` working after the switch.
    if kh_core::ipc::service_pid("KeyHolder") == Some(pid) && image_n.ends_with("\\keyholder-service.exe") {
        return Ok(());
    }

    // 1. Otherwise the owner must be a KeyHolder binary from our own directory.
    let mut expected = Vec::new();
    for name in ["keyholder.exe", "keyholder-service.exe"] {
        let p = dir.join(name);
        expected.push((norm(&p.to_string_lossy()), name == "keyholder-service.exe"));
    }
    let Some((_, is_service)) = expected.into_iter().find(|(p, _)| image_n == *p) else {
        return Err(format!(
            "канал MCP Keyholder принадлежит чужому процессу ({image}), ожидался MCP Keyholder из {} — соединение отклонено",
            dir.display()
        ));
    };

    // 2. A service binary that is not the registered service is only accepted in `--console`
    //    development mode, running under this very user.
    if is_service {
        let me = kh_core::ipc::current_user_sid().unwrap_or_default();
        if kh_core::ipc::process_user_sid(pid).as_deref() != Some(me.as_str()) || me.is_empty() {
            return Err("процесс keyholder-service.exe не является службой MCP Keyholder — соединение отклонено".into());
        }
    }
    Ok(())
}

#[cfg(windows)]
fn start_app() {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    if let Ok(dir) = std::env::current_exe().map(|p| p.with_file_name("")) {
        // Service mode: the core is a service, and the SCM starts it for us.
        let service_exe = dir.join("keyholder-service.exe");
        let service_cfg = std::env::var_os("KH_SERVICE_CONFIG")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::env::var_os("ProgramData")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| std::path::PathBuf::from(r"C:\ProgramData"))
                    .join("KeyHolder")
                    .join("service.json")
            });
        // The approval windows belong to the app: start it too if the installer recorded where it is.
        if let Some(app_path) = std::fs::read(&service_cfg)
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v.get("appPath").and_then(|x| x.as_str()).map(std::path::PathBuf::from))
            .filter(|p| p.exists())
        {
            let _ = std::process::Command::new(app_path)
                .arg("--background")
                .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
        }
        if service_exe.exists() && service_cfg.exists() {
            let started = std::process::Command::new("sc.exe")
                .args(["start", "KeyHolder"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if started {
                return;
            }
        }
        let exe = dir.join("keyholder.exe");
        let _ = std::process::Command::new(exe)
            .arg("--background")
            .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
}

#[cfg(unix)]
async fn open_stream(_autostart: bool) -> Result<tokio::net::UnixStream, String> {
    kh_core::ipc::connect().await.map_err(|e| kh_core::ipc::describe_connect_error(&e))
}

impl Conn {
    pub async fn connect(purpose: &str, token: Option<String>, autostart: bool) -> Result<Arc<Conn>, String> {
        let stream = open_stream(autostart).await?;
        let (rd, mut wr) = tokio::io::split(stream);
        let mut rd = BufReader::new(rd);

        let hello = ClientMsg::Hello { protocol: PROTOCOL_VERSION, token, purpose: purpose.into(), pid: std::process::id() };
        let mut line = serde_json::to_string(&hello).map_err(|e| e.to_string())?;
        line.push('\n');
        wr.write_all(line.as_bytes()).await.map_err(|e| e.to_string())?;

        let mut first = String::new();
        tokio::time::timeout(Duration::from_secs(10), rd.read_line(&mut first))
            .await
            .map_err(|_| "MCP Keyholder не ответил".to_string())?
            .map_err(|e| e.to_string())?;
        match serde_json::from_str::<ServerMsg>(first.trim()) {
            Ok(ServerMsg::Welcome { .. }) => {}
            Ok(ServerMsg::Fatal { message }) => return Err(message),
            _ => return Err("неожиданный ответ MCP Keyholder".into()),
        }

        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            while let Some(mut l) = rx.recv().await {
                l.push('\n');
                if wr.write_all(l.as_bytes()).await.is_err() {
                    break;
                }
                let _ = wr.flush().await;
            }
        });

        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let (p2, a2) = (pending.clone(), alive.clone());
        tokio::spawn(async move {
            let mut buf = String::new();
            loop {
                buf.clear();
                match rd.read_line(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                match serde_json::from_str::<ServerMsg>(buf.trim()) {
                    Ok(ServerMsg::Response { id, ok, result, error }) => {
                        if let Some(tx) = p2.lock().unwrap_or_else(|e| e.into_inner()).remove(&id) {
                            let _ = tx.send(if ok { Ok(result) } else { Err(error.unwrap_or_default()) });
                        }
                    }
                    Ok(ServerMsg::Fatal { .. }) => break,
                    _ => {}
                }
            }
            a2.store(false, Ordering::Relaxed);
            for (_, tx) in p2.lock().unwrap_or_else(|e| e.into_inner()).drain() {
                let _ = tx.send(Err(DISCONNECTED.into()));
            }
        });

        Ok(Arc::new(Conn { tx, pending, next: AtomicU64::new(1), alive }))
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    pub fn send_client_info(&self, name: &str, version: &str) {
        let msg = ClientMsg::ClientInfo { name: name.into(), version: version.into() };
        if let Ok(s) = serde_json::to_string(&msg) {
            let _ = self.tx.send(s);
        }
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        if !self.is_alive() {
            return Err(DISCONNECTED.into());
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).insert(id, tx);
        let msg = ClientMsg::Request { id, method: method.into(), params };
        let s = serde_json::to_string(&msg).map_err(|e| e.to_string())?;
        if self.tx.send(s).is_err() {
            return Err(DISCONNECTED.into());
        }
        rx.await.unwrap_or_else(|_| Err(DISCONNECTED.into()))
    }
}

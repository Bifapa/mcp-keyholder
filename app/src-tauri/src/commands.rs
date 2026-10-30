//! Commands exposed to the webview.
//!
//! Almost everything is one `kh_call(method, params)` that reaches the core — in-process in
//! portable mode, over the interface channel when the core runs as the service. The few
//! commands that must run in the app process are here: clipboard, file reading for import,
//! QR rendering, the separate Windows desktop, and service installation.

use kh_core::import::{candidates, slug, Candidate};
use kh_core::Tier;
use serde_json::{json, Value};
use tauri::{AppHandle, Manager, WebviewWindow};

use crate::desktop::{self, Field, Prompt};
use crate::hello;
use crate::service;
use crate::state::AppState;

type Res<T> = Result<T, String>;

/// The window label decides what may be called: the approval popup can only decide
/// requests, everything else belongs to the main window.
fn allow(window: &WebviewWindow, method: &str) -> Res<()> {
    match window.label() {
        "main" => Ok(()),
        "approve" if matches!(method, "approval_current" | "approval_decide") => Ok(()),
        _ => Err("forbidden".into()),
    }
}

#[tauri::command]
pub async fn kh_call(app: AppHandle, window: WebviewWindow, method: String, params: Option<Value>) -> Res<Value> {
    allow(&window, &method)?;
    let st = app.state::<AppState>();
    st.call(&method, params.unwrap_or_else(|| json!({}))).await
}

/// Status plus app-side facts: which mode we run in, whether the service is installed,
/// whether the separate desktop is usable.
#[tauri::command]
pub async fn status(app: AppHandle, window: WebviewWindow) -> Res<Value> {
    allow(&window, "status")?;
    let st = app.state::<AppState>();
    let mut v = match st.call("status", json!({})).await {
        Ok(v) => v,
        Err(e) => json!({ "error": e, "initialized": false, "unlocked": false }),
    };
    if let Value::Object(ref mut o) = v {
        o.insert("serviceInstalled".into(), json!(st.service_installed));
        o.insert("desktopAvailable".into(), json!(desktop::available()));
        o.insert("portableAllowed".into(), json!(!st.service_installed));
    }
    Ok(v)
}

// ---------- clipboard ----------

#[tauri::command]
pub async fn copy_value(app: AppHandle, window: WebviewWindow, id: String) -> Res<()> {
    allow(&window, "copy_value")?;
    let st = app.state::<AppState>();
    // The value goes from the core to the clipboard without passing through the webview.
    let v = st.call("copy_value", json!({ "id": id })).await?;
    let value = v.get("value").and_then(|x| x.as_str()).unwrap_or_default().to_string();
    if value.is_empty() {
        return Err("key not found".into());
    }
    crate::clipboard::copy_secret(&value)
}

// ---------- import ----------

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportFile {
    path: String,
    file_name: String,
    stem: String,
    text: String,
    candidates: Vec<Candidate>,
    error: Option<String>,
}

/// Files chosen by the human are read here: the core never touches the filesystem of the
/// user's profile (in service mode it could not).
#[tauri::command]
pub fn import_read(window: WebviewWindow, paths: Vec<String>) -> Res<Vec<ImportFile>> {
    allow(&window, "import_read")?;
    Ok(paths
        .into_iter()
        .take(200)
        .map(|path| {
            let p = std::path::Path::new(&path);
            let file_name = p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
            let stem = slug(&p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default());
            let read = std::fs::metadata(p).and_then(|m| {
                if m.len() > 256 * 1024 {
                    Err(std::io::Error::new(std::io::ErrorKind::Other, "file is larger than 256 KB"))
                } else {
                    std::fs::read(p)
                }
            });
            match read {
                Ok(bytes) => {
                    let text = String::from_utf8_lossy(&bytes).trim_start_matches('\u{feff}').to_string();
                    ImportFile { candidates: candidates(&text), path, file_name, stem, text, error: None }
                }
                Err(e) => ImportFile { path, file_name, stem, text: String::new(), candidates: vec![], error: Some(e.to_string()) },
            }
        })
        .collect())
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    added: Vec<String>,
    errors: Vec<String>,
    deleted: usize,
}

#[tauri::command]
pub async fn import_commit(
    app: AppHandle,
    window: WebviewWindow,
    drafts: Vec<kh_core::NewSecret>,
    delete_paths: Vec<String>,
) -> Res<ImportResult> {
    allow(&window, "import_commit")?;
    let st = app.state::<AppState>();
    let v = st.call("import_commit", json!({ "drafts": drafts })).await?;
    let added: Vec<String> = v
        .get("added")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let errors: Vec<String> = v
        .get("errors")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    // Source files are removed only when every draft went in.
    let mut deleted = 0;
    if errors.is_empty() {
        for p in delete_paths {
            if std::fs::remove_file(&p).is_ok() {
                deleted += 1;
            }
        }
    }
    Ok(ImportResult { added, errors, deleted })
}

// ---------- setup ----------

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupView {
    qr_svg: String,
    recovery: Vec<String>,
}

#[tauri::command]
pub async fn setup_begin(app: AppHandle, window: WebviewWindow, password: String, word: String) -> Res<SetupView> {
    allow(&window, "setup_begin")?;
    let st = app.state::<AppState>();
    let v = st.call("setup_begin", json!({ "password": password, "word": word })).await?;
    let uri = v.get("otpauthUri").and_then(|x| x.as_str()).unwrap_or_default();
    let qr = qrcode::QrCode::new(uri.as_bytes()).map_err(|e| e.to_string())?;
    let svg = qr
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(240, 240)
        .quiet_zone(true)
        .build();
    let recovery: Vec<String> = v
        .get("recovery")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    Ok(SetupView { qr_svg: svg, recovery })
}

/// Renders any otpauth URI as an SVG QR code (setup, and authenticator reissue).
#[tauri::command]
pub fn qr_svg(window: WebviewWindow, uri: String) -> Res<String> {
    allow(&window, "status")?;
    let qr = qrcode::QrCode::new(uri.as_bytes()).map_err(|e| e.to_string())?;
    Ok(qr
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(240, 240)
        .quiet_zone(true)
        .build())
}

// ---------- separate desktop ----------
fn secure_desktop_on() -> bool {
    // Debug builds can turn it off so automated runs work; release builds always use it.
    if cfg!(debug_assertions) && std::env::var("KH_NO_SECURE_DESKTOP").as_deref() == Ok("1") {
        return false;
    }
    desktop::available()
}

async fn settings_on(app: &AppHandle) -> bool {
    let st = app.state::<AppState>();
    match st.call("get_settings", json!({})).await {
        Ok(v) => v.get("secureDesktop").and_then(|x| x.as_bool()).unwrap_or(true),
        Err(_) => true,
    }
}

/// The noise-word palette when the setting is on; None (plain word) when it is off or cannot be
/// read (vault locked, service unreachable).
async fn noise_word(app: &AppHandle) -> Option<Vec<u32>> {
    let st = app.state::<AppState>();
    let v = st.call("get_settings", json!({})).await.ok()?;
    if !v.get("noiseWord").and_then(|x| x.as_bool()).unwrap_or(false) {
        return None;
    }
    let colors: Vec<String> = v.get("noiseColors").and_then(|c| serde_json::from_value(c.clone()).ok()).unwrap_or_default();
    kh_core::parse_noise_colors(&colors).or_else(|| kh_core::parse_noise_colors(&kh_core::default_noise_colors()))
}

async fn antiphish(app: &AppHandle) -> String {
    let st = app.state::<AppState>();
    match st.call("approval_current", json!({})).await {
        Ok(v) => v.get("antiphish").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
        Err(_) => String::new(),
    }
}

fn level_field(level: Tier, has_pin: bool) -> Field {
    if level == Tier::Pin && has_pin {
        Field::Pin
    } else {
        Field::Otp
    }
}

async fn run_prompt(p: Prompt) -> Result<desktop::Answer, String> {
    tokio::task::spawn_blocking(move || desktop::prompt(p)).await.map_err(|e| e.to_string())?
}

/// Approving a `pin`/`otp` request: the code is typed on the separate desktop and goes
/// straight to the core. The webview only learns whether it worked.
#[tauri::command]
pub async fn approval_native(
    app: AppHandle,
    window: WebviewWindow,
    id: String,
    keep: Vec<String>,
    ttl_minutes: u32,
    block_session: bool,
) -> Res<()> {
    allow(&window, "approval_decide")?;
    if !secure_desktop_on() || !settings_on(&app).await {
        return Err("desktop_off".into());
    }
    let st = app.state::<AppState>();
    let cur = st.call("approval_current", json!({})).await?;
    let req = cur.get("request").cloned().unwrap_or(Value::Null);
    if req.is_null() {
        return Err("the request is no longer pending".into());
    }
    let has_pin = cur.get("hasPin").and_then(|x| x.as_bool()).unwrap_or(false);
    let level: Tier = req
        .get("keys")
        .and_then(|k| k.as_array())
        .map(|keys| {
            keys.iter()
                .filter(|k| k.get("name").and_then(|n| n.as_str()).map(|n| keep.iter().any(|x| x == n)).unwrap_or(false))
                .filter_map(|k| k.get("tier").and_then(|t| t.as_str()).and_then(Tier::parse))
                .max()
                .unwrap_or(Tier::Soft)
        })
        .unwrap_or(Tier::Soft);
    let names: Vec<String> = req
        .get("keys")
        .and_then(|k| k.as_array())
        .map(|keys| {
            keys.iter()
                .filter(|k| k.get("name").and_then(|n| n.as_str()).map(|n| keep.iter().any(|x| x == n)).unwrap_or(false))
                .map(|k| {
                    let n = k.get("name").and_then(|x| x.as_str()).unwrap_or("?");
                    let m = k.get("mode").and_then(|x| x.as_str()).unwrap_or("reveal");
                    format!("{n} · {m}")
                })
                .collect()
        })
        .unwrap_or_default();
    let mut shown: Vec<String> = names.iter().take(6).cloned().collect();
    if names.len() > shown.len() {
        shown.push(format!("and {} more", names.len() - shown.len()));
    }
    let mut facts = vec![
        ("Client".to_string(), req.get("client").and_then(|x| x.as_str()).unwrap_or("—").to_string()),
        ("Process".to_string(), req.get("process").and_then(|x| x.as_str()).unwrap_or("—").to_string()),
        ("Duration".to_string(), format!("{ttl_minutes} min")),
        ("Keys".to_string(), shown.join(", ")),
        ("Time".to_string(), now_text()),
    ];
    if let Some(claimed) = req.get("claimedClient").and_then(|x| x.as_str()).filter(|c| !c.is_empty()) {
        facts.push(("Introduced itself as".to_string(), format!("{claimed} (as the agent claims)")));
    }
    let reason = req.get("reason").and_then(|x| x.as_str()).unwrap_or_default().to_string();
    let p = Prompt {
        heading: "Access request".into(),
        facts,
        agent_note: Some(reason),
        antiphish: cur.get("antiphish").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
        field: level_field(level, has_pin),
        noise: noise_word(&app).await,
    };
    let a = run_prompt(p).await?;
    st.call(
        "approval_decide",
        json!({
            "id": id,
            "approve": true,
            "keep": keep,
            "ttl_minutes": ttl_minutes,
            "code": a.first,
            "block_session": block_session,
        }),
    )
    .await?;
    Ok(())
}

/// Local wall-clock time for the confirmation window, e.g. "2026-10-30 14:32".
#[cfg(windows)]
fn now_text() -> String {
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;
    let mut t = unsafe { std::mem::zeroed() };
    unsafe { GetLocalTime(&mut t) };
    format!("{}-{:02}-{:02} {:02}:{:02}", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute)
}

#[cfg(not(windows))]
fn now_text() -> String {
    String::new()
}

/// Step-up (master password + code) on the separate desktop.
#[tauri::command]
pub async fn stepup_native(app: AppHandle, window: WebviewWindow) -> Res<i64> {
    allow(&window, "stepup")?;
    if !secure_desktop_on() || !settings_on(&app).await {
        return Err("desktop_off".into());
    }
    let st = app.state::<AppState>();
    let p = Prompt {
        heading: "Step-up for 3 minutes".into(),
        facts: vec![
            ("Allows".into(), "showing values, changing policy, clients and settings".to_string()),
            ("Time".to_string(), now_text()),
        ],
        agent_note: None,
        antiphish: antiphish(&app).await,
        field: Field::PasswordOtp,
        noise: noise_word(&app).await,
    };
    let a = run_prompt(p).await?;
    let until = st.call("stepup", json!({ "password": a.first, "code": a.second })).await?;
    Ok(until.as_i64().unwrap_or(0))
}

/// Unlock after a lock (master password typed on the separate desktop).
#[tauri::command]
pub async fn unlock_native(app: AppHandle, window: WebviewWindow) -> Res<()> {
    allow(&window, "unlock")?;
    if !secure_desktop_on() || !settings_on(&app).await {
        return Err("desktop_off".into());
    }
    let st = app.state::<AppState>();
    let p = Prompt {
        heading: "Unlock MCP Keyholder".into(),
        facts: vec![("Time".to_string(), now_text())],
        agent_note: None,
        antiphish: antiphish(&app).await,
        field: Field::Password,
        noise: noise_word(&app).await,
    };
    let a = run_prompt(p).await?;
    st.call("unlock", json!({ "password": a.first })).await?;
    Ok(())
}

/// Service mode: open the interface with the method chosen in the settings.
#[tauri::command]
pub async fn login_native(app: AppHandle, window: WebviewWindow) -> Res<()> {
    allow(&window, "login")?;
    let st = app.state::<AppState>();
    let mode = st
        .call("status", json!({}))
        .await
        .ok()
        .and_then(|v| v.get("loginMode").and_then(|x| x.as_str()).map(str::to_string))
        .unwrap_or_else(|| "password".into());
    let credential = match mode.as_str() {
        "nothing" => String::new(),
        "pin" | "otp" => {
            let field = if mode == "pin" { Field::Pin } else { Field::Otp };
            let p = Prompt {
                heading: "Sign in to MCP Keyholder".into(),
                facts: vec![("Sign-in method".to_string(), if mode == "pin" { "PIN".into() } else { "Authenticator code".into() })],
                agent_note: None,
                antiphish: antiphish(&app).await,
                field,
                noise: noise_word(&app).await,
            };
            run_prompt(p).await?.first
        }
        _ => {
            let p = Prompt {
                heading: "Sign in to MCP Keyholder".into(),
                facts: Vec::new(),
                agent_note: None,
                antiphish: antiphish(&app).await,
                field: Field::Password,
                noise: noise_word(&app).await,
            };
            run_prompt(p).await?.first
        }
    };
    st.call("login", json!({ "credential": credential })).await?;
    Ok(())
}

// ---------- whole-vault file (.mcpkey) ----------

/// The chunk size the core hands out and takes (raw bytes, before base64).
const MCPKEY_CHUNK: usize = 1024 * 1024;

/// Only `.mcpkey` paths: the webview chooses the path, so it may not name any other file.
fn mcpkey_path(path: &str) -> Res<std::path::PathBuf> {
    let p = std::path::PathBuf::from(path);
    let ok = p.extension().and_then(|e| e.to_str()).is_some_and(|e| e.eq_ignore_ascii_case("mcpkey"));
    if !ok {
        return Err("the vault file must have the .mcpkey extension".into());
    }
    Ok(p)
}

/// Saves the whole vault, encrypted, as a `.mcpkey` file at `path` (from the save dialog).
#[tauri::command]
pub async fn export_vault_file(app: AppHandle, window: WebviewWindow, path: String) -> Res<u64> {
    allow(&window, "export_vault")?;
    let path = mcpkey_path(&path)?;
    let st = app.state::<AppState>();
    st.call("export_vault", json!({})).await?;
    let mut data = Vec::new();
    loop {
        let r = st.call("export_chunk", json!({ "offset": data.len() })).await?;
        let chunk = r.get("data").and_then(|x| x.as_str()).unwrap_or_default();
        data.extend(data_encoding::BASE64.decode(chunk.as_bytes()).map_err(|e| e.to_string())?);
        if r.get("done").and_then(|x| x.as_bool()).unwrap_or(true) {
            break;
        }
    }
    std::fs::write(&path, &data).map_err(|e| format!("could not write the file: {e}"))?;
    Ok(data.len() as u64)
}

/// Before asking for the file's password: replacing an existing vault needs it open and a
/// step-up, so the human is not asked for the password twice.
async fn import_allowed(st: &AppState) -> Res<()> {
    let s = st.call("status", json!({})).await?;
    let flag = |k: &str| s.get(k).and_then(|x| x.as_bool()).unwrap_or(false);
    if !flag("initialized") {
        return Ok(());
    }
    if !flag("unlocked") {
        return Err("unlock the vault first (or reset it on the sign-in screen)".into());
    }
    if s.get("elevatedUntil").and_then(|x| x.as_i64()).unwrap_or(0) <= kh_core::now_ms() {
        return Err("stepup_required".into());
    }
    Ok(())
}

async fn upload_mcpkey(st: &AppState, path: &str) -> Res<String> {
    let path = mcpkey_path(path)?;
    let data = std::fs::read(&path).map_err(|e| format!("could not read the file: {e}"))?;
    if !data.starts_with(kh_core::vault::EXPORT_MAGIC) {
        return Err("this is not an MCP Keyholder vault file (.mcpkey)".into());
    }
    for (i, chunk) in data.chunks(MCPKEY_CHUNK).enumerate() {
        let offset = i * MCPKEY_CHUNK;
        st.call("import_chunk", json!({ "offset": offset, "data": data_encoding::BASE64.encode(chunk) })).await?;
    }
    Ok(path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default())
}

/// Loads a `.mcpkey` file in place of the vault; its master password is typed on the
/// separate desktop.
#[tauri::command]
pub async fn import_vault_native(app: AppHandle, window: WebviewWindow, path: String) -> Res<Value> {
    allow(&window, "import_vault")?;
    if !secure_desktop_on() || !settings_on(&app).await {
        return Err("desktop_off".into());
    }
    let st = app.state::<AppState>();
    import_allowed(&st).await?;
    let name = upload_mcpkey(&st, &path).await?;
    let p = Prompt {
        heading: "Load a vault from a file".into(),
        facts: vec![("File".to_string(), name), ("Time".to_string(), now_text())],
        agent_note: None,
        antiphish: antiphish(&app).await,
        field: Field::Password,
        noise: noise_word(&app).await,
    };
    let a = run_prompt(p).await?;
    st.call("import_vault", json!({ "password": a.first })).await
}

/// The same with the password typed in the window (separate desktop off or unavailable).
#[tauri::command]
pub async fn import_vault_file(app: AppHandle, window: WebviewWindow, path: String, password: String) -> Res<Value> {
    allow(&window, "import_vault")?;
    let st = app.state::<AppState>();
    import_allowed(&st).await?;
    upload_mcpkey(&st, &path).await?;
    st.call("import_vault", json!({ "password": password })).await
}

/// Windows Hello availability, asked without showing any dialog. Portable mode only:
/// the service cannot check a dialog shown in another process.
#[tauri::command]
pub fn hello_available(app: AppHandle, window: WebviewWindow) -> Res<bool> {
    allow(&window, "status")?;
    if app.state::<AppState>().local().is_none() {
        return Ok(false);
    }
    Ok(hello::available())
}

/// Step-up with the master password and presence instead of the authenticator code.
#[tauri::command]
pub async fn stepup_hello(app: AppHandle, window: WebviewWindow, password: String) -> Res<i64> {
    allow(&window, "stepup")?;
    hello::stepup(&app, password).await
}

/// Approve a `pin`/`otp` request with presence instead of a code.
#[tauri::command]
pub async fn approval_hello(
    app: AppHandle,
    window: WebviewWindow,
    id: String,
    keep: Vec<String>,
    ttl_minutes: u32,
    block_session: bool,
) -> Res<()> {
    allow(&window, "approval_decide")?;
    hello::approve(&app, &id, keep, ttl_minutes, block_session).await
}

/// The approval popup is gone: deny whatever it was showing.
#[tauri::command]
pub async fn approval_closed(app: AppHandle, window: WebviewWindow) -> Res<()> {
    allow(&window, "approval_current")?;
    close_front(&app).await;
    Ok(())
}

pub async fn close_front(app: &AppHandle) {
    let st = app.state::<AppState>();
    if let Ok(v) = st.call("approval_current", json!({})).await {
        if let Some(id) = v.get("request").and_then(|r| r.get("id")).and_then(|x| x.as_str()) {
            let id = id.to_string();
            let _ = st.call("approval_decide", json!({ "id": id, "approve": false, "keep": [], "ttl_minutes": 0, "code": null, "block_session": false })).await;
        }
    }
}

// ---------- service mode ----------

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceStatus {
    installed: bool,
    /// Set when the service is installed but the app cannot reach it.
    error: Option<String>,
}

#[tauri::command]
pub fn service_status(app: AppHandle, window: WebviewWindow) -> Res<ServiceStatus> {
    allow(&window, "status")?;
    let st = app.state::<AppState>();
    Ok(ServiceStatus {
        installed: st.service_installed,
        error: st.service_client().and_then(|s| s.last_error()),
    })
}

/// Moves the vault into the service and restarts the app in service mode.
#[tauri::command]
pub async fn install_service(app: AppHandle, window: WebviewWindow) -> Res<()> {
    allow(&window, "status")?;
    let st = app.state::<AppState>();
    let source = st.data_dir.join("vault.db");
    if let Some(d) = st.local().cloned() {
        // Drop the keys and fold the WAL in, so the installer copies one complete file.
        tokio::task::spawn_blocking(move || d.prepare_migration()).await.map_err(|e| e.to_string())??;
    }
    tokio::task::spawn_blocking(move || service::install_elevated(&source)).await.map_err(|e| e.to_string())??;
    app.restart();
}

/// Removes the service, brings the vault back and restarts the app in portable mode.
#[tauri::command]
pub async fn uninstall_service(app: AppHandle, window: WebviewWindow) -> Res<()> {
    allow(&window, "status")?;
    let dir = app.state::<AppState>().data_dir.clone();
    tokio::task::spawn_blocking(move || service::uninstall_elevated(&dir)).await.map_err(|e| e.to_string())??;
    app.restart();
}

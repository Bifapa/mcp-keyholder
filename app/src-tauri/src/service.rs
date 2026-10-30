//! Service mode: detection of the installed service and elevated install/uninstall.
//!
//! The service keeps its data in `%ProgramData%\KeyHolder`, readable only by the service
//! account and SYSTEM. The installer writes `service.json` with the SID of the user who
//! installed it — that is the only account allowed to use the agent and interface channels.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const SERVICE_EXE: &str = "keyholder-service.exe";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceConfig {
    pub owner_sid: String,
    pub install_dir: String,
    pub data_dir: String,
    #[serde(default)]
    pub app_path: Option<String>,
}

pub fn program_data_dir() -> PathBuf {
    std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData")).join("KeyHolder")
}

pub fn config_path() -> PathBuf {
    program_data_dir().join("service.json")
}

/// `None` when KeyHolder runs in portable mode.
/// `KH_SERVICE_CONFIG` points at a config file directly (development and end-to-end tests).
pub fn installed() -> Option<ServiceConfig> {
    let path = match std::env::var_os("KH_SERVICE_CONFIG") {
        Some(p) => PathBuf::from(p),
        None => config_path(),
    };
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn service_exe() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let p = exe.with_file_name(SERVICE_EXE);
    if p.exists() {
        Ok(p)
    } else {
        Err(format!("Рядом с приложением нет {SERVICE_EXE}: переустановите MCP Keyholder скриптом scripts\\install.ps1"))
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn quote(s: &str) -> String {
    format!("\"{s}\"")
}

/// Runs `exe args` through UAC and waits for it. Returns the exit code.
#[cfg(windows)]
fn run_elevated(exe: &std::path::Path, args: &str) -> Result<u32, String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};

    let verb = wide("runas");
    let file = wide(&exe.to_string_lossy());
    let params = wide(args);
    unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = params.as_ptr();
        info.nShow = 0; // SW_HIDE: the installer has nothing to show
        if ShellExecuteExW(&mut info) == 0 || info.hProcess.is_null() {
            return Err("Установщик не запустился: нужны права администратора и подтверждение UAC.".into());
        }
        WaitForSingleObject(info.hProcess, INFINITE);
        let mut code = 1u32;
        GetExitCodeProcess(info.hProcess, &mut code);
        CloseHandle(info.hProcess);
        Ok(code)
    }
}

#[cfg(not(windows))]
fn run_elevated(_exe: &std::path::Path, _args: &str) -> Result<u32, String> {
    Err("режим службы есть только в Windows".into())
}

fn run_logged(exe: &std::path::Path, mut args: Vec<String>, what: &str) -> Result<(), String> {
    let log = std::env::temp_dir().join("keyholder-service-setup.log");
    let _ = std::fs::remove_file(&log);
    args.push("--log".into());
    args.push(quote(&log.to_string_lossy()));
    let code = run_elevated(exe, &args.join(" "))?;
    if code != 0 {
        let reason = std::fs::read_to_string(&log).unwrap_or_default();
        let _ = std::fs::remove_file(&log);
        return Err(if reason.trim().is_empty() {
            format!("{what} не удалось (код {code}).")
        } else {
            format!("{what} не удалось: {}", reason.trim())
        });
    }
    let _ = std::fs::remove_file(&log);
    Ok(())
}

/// Installs the service and moves the vault into `%ProgramData%`. Blocks until done.
pub fn install_elevated(portable_vault: &std::path::Path) -> Result<(), String> {
    let exe = service_exe()?;
    let sid = kh_core::ipc::current_user_sid().map_err(|e| format!("не удалось определить SID: {e}"))?;
    let mut args = vec!["install".to_string(), "--owner".into(), sid];
    if portable_vault.exists() {
        args.push("--source".into());
        args.push(quote(&portable_vault.to_string_lossy()));
    }
    if let Ok(me) = std::env::current_exe() {
        args.push("--app".into());
        args.push(quote(&me.to_string_lossy()));
    }
    run_logged(&exe, args, "Установка службы")
}

/// Removes the service and copies the vault back to the portable location. Blocks until done.
pub fn uninstall_elevated(portable_dir: &std::path::Path) -> Result<(), String> {
    let exe = service_exe()?;
    let args = vec!["uninstall".to_string(), "--restore".into(), quote(&portable_dir.to_string_lossy())];
    run_logged(&exe, args, "Удаление службы")
}

/// After the move the old portable file must never be opened again: keep it aside as a backup.
pub fn retire_portable(vault: &std::path::Path) {
    if !vault.exists() {
        return;
    }
    let stamp = kh_core::now_ms();
    let _ = std::fs::rename(vault, vault.with_extension(format!("db.migrated-{stamp}")));
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", vault.display()));
    }
}

/// In service mode the app starts with Windows (in the tray) so approval windows can appear.
#[cfg(windows)]
pub fn set_autostart(enabled: bool) {
    use windows_sys::Win32::System::Registry::{RegDeleteKeyValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ};
    let sub = wide(r"Software\Microsoft\Windows\CurrentVersion\Run");
    let name = wide("KeyHolder");
    unsafe {
        if enabled {
            let Ok(exe) = std::env::current_exe() else { return };
            let data = wide(&format!("\"{}\" --background", exe.display()));
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                sub.as_ptr(),
                name.as_ptr(),
                REG_SZ,
                data.as_ptr() as *const std::ffi::c_void,
                (data.len() * 2) as u32,
            );
        } else {
            RegDeleteKeyValueW(HKEY_CURRENT_USER, sub.as_ptr(), name.as_ptr());
        }
    }
}

#[cfg(not(windows))]
pub fn set_autostart(_enabled: bool) {}

/// The installer (and so every update) installs into the folder recorded under
/// `HKCU\Software\Bifastack\MCP Keyholder`. Recording the folder this copy runs from keeps
/// updates in place, so `kh.exe` — the path agents are configured with — never moves.
#[cfg(windows)]
pub fn remember_install_dir() {
    use windows_sys::Win32::System::Registry::{RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ};
    if cfg!(debug_assertions) {
        return;
    }
    let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.to_path_buf())) else { return };
    let sub = wide(r"Software\Bifastack\MCP Keyholder");
    let data = wide(&dir.display().to_string());
    unsafe {
        RegSetKeyValueW(
            HKEY_CURRENT_USER,
            sub.as_ptr(),
            std::ptr::null(),
            REG_SZ,
            data.as_ptr() as *const std::ffi::c_void,
            (data.len() * 2) as u32,
        );
    }
}

#[cfg(not(windows))]
pub fn remember_install_dir() {}

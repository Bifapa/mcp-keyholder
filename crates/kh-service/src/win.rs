//! Windows service plumbing: SCM dispatch, installation and the ACL that keeps the vault
//! away from the user's processes.

use std::ffi::{c_void, OsStr, OsString};
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, ACL, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};
use windows_sys::Win32::System::EventLog::{DeregisterEventSource, RegisterEventSourceW};

pub const SERVICE_NAME: &str = "KeyHolder";
pub const SERVICE_DISPLAY: &str = "MCP Keyholder";
pub const SERVICE_DESC: &str = "Key vault for AI agents: the core runs under a separate account";
pub const SERVICE_ACCOUNT: &str = "NT SERVICE\\KeyHolder";
pub const SERVICE_EXE: &str = "keyholder-service.exe";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceConfig {
    pub owner_sid: String,
    pub install_dir: String,
    pub data_dir: String,
    /// The KeyHolder app of the installing user (shows approval windows; `kh` may start it).
    #[serde(default)]
    pub app_path: Option<String>,
}

pub fn program_data_dir() -> PathBuf {
    std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData")).join(SERVICE_NAME)
}

pub fn program_files_dir() -> PathBuf {
    std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Program Files")).join(SERVICE_NAME)
}

pub fn config_path() -> PathBuf {
    program_data_dir().join("service.json")
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn current_sid() -> Result<String> {
    kh_core::ipc::current_user_sid().map_err(|e| anyhow!("could not determine the user SID: {e}"))
}

fn is_admin() -> bool {
    use windows_sys::Win32::Security::CheckTokenMembership;
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    unsafe {
        let mut sid: PSECURITY_DESCRIPTOR = null_mut();
        let admin = wide("S-1-5-32-544");
        if ConvertStringSidToSidW(admin.as_ptr(), &mut sid as *mut _ as *mut *mut c_void) == 0 {
            return false;
        }
        let mut is_member = 0i32;
        let ok = CheckTokenMembership(null_mut(), sid, &mut is_member);
        LocalFree(sid as *mut c_void);
        ok != 0 && is_member != 0
    }
}

/// Applies a protected DACL to `path` and everything inside it: the service account, SYSTEM
/// and elevated administrators (who are outside the threat model and need access to
/// install, uninstall and back up). Ordinary user processes get nothing.
pub fn lock_down(path: &Path) -> Result<()> {
    let sid = kh_core::ipc::service_account_sid(SERVICE_ACCOUNT)
        .map_err(|e| anyhow!("could not determine the service SID: {e}"))?;
    let sddl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})");
    apply_sddl(path, &sddl)?;
    // Files that already existed keep their old ACL: reapply to each of them.
    if path.is_dir() {
        for entry in std::fs::read_dir(path).with_context(|| format!("reading {}", path.display()))? {
            let p = entry?.path();
            apply_sddl(&p, &sddl)?;
            if p.is_dir() {
                lock_down(&p)?;
            }
        }
    }
    Ok(())
}

/// Gives the owner read access to one file (used for service.json, which the app reads).
pub fn allow_owner_read(path: &Path, owner_sid: &str) -> Result<()> {
    let sid = kh_core::ipc::service_account_sid(SERVICE_ACCOUNT)
        .map_err(|e| anyhow!("could not determine the service SID: {e}"))?;
    let sddl = format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{sid})(A;;FR;;;{owner_sid})");
    apply_sddl(path, &sddl)
}

fn apply_sddl(path: &Path, sddl: &str) -> Result<()> {
    unsafe {
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let s = wide(sddl);
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(s.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()) == 0 {
            bail!("could not parse the security descriptor");
        }
        let mut owner: PSECURITY_DESCRIPTOR = null_mut();
        let mut owner_defaulted = 0i32;
        let mut dacl: *mut ACL = null_mut();
        let mut dacl_present = 0i32;
        let mut dacl_defaulted = 0i32;
        GetSecurityDescriptorOwner(sd, &mut owner, &mut owner_defaulted);
        GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl, &mut dacl_defaulted);
        let w = wide(&path.to_string_lossy());
        // Only change the owner when the descriptor names one (setting a foreign owner needs
        // privileges an elevated token does not enable by default).
        let mut info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        if !owner.is_null() {
            info |= OWNER_SECURITY_INFORMATION;
        }
        let rc = SetNamedSecurityInfoW(
            w.as_ptr() as *mut u16,
            SE_FILE_OBJECT,
            info,
            owner as *mut c_void,
            null_mut(),
            dacl,
            null_mut(),
        );
        LocalFree(sd as *mut c_void);
        if rc != 0 {
            bail!("could not set permissions on {} (code {rc})", path.display());
        }
    }
    Ok(())
}

// ---------- SCM ----------

fn manager() -> Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| anyhow!("no access to the service control manager: {e}"))
}

pub fn status() -> Result<()> {
    let m = manager()?;
    match m.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(s) => {
            let st = s.query_status().map_err(|e| anyhow!("{e}"))?;
            println!("Service {SERVICE_NAME}: {:?}", st.current_state);
            if let Some(cfg) = read_config()? {
                println!("Data: {}", cfg.data_dir);
                println!("Binaries: {}", cfg.install_dir);
                println!("Channel owner: {}", cfg.owner_sid);
            }
        }
        Err(_) => println!("Service {SERVICE_NAME} is not installed"),
    }
    Ok(())
}

fn read_config() -> Result<Option<ServiceConfig>> {
    match std::fs::read(config_path()) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes).context("service.json is corrupted")?)),
        Err(_) => Ok(None),
    }
}

/// Runs the SCM dispatcher; the process becomes the service for as long as it lives.
pub fn dispatch() -> Result<()> {
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| anyhow!("the service failed to start: {e}"))
}

windows_service::define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_as_service() {
        report_error(&format!("{e:#}"));
        std::process::exit(1);
    }
}

fn run_as_service() -> Result<()> {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let tx = std::sync::Mutex::new(Some(tx));
    let status_handle = service_control_handler::register(SERVICE_NAME, move |event| {
        use windows_service::service::ServiceControl;
        match event {
            ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
                if let Some(tx) = tx.lock().ok().and_then(|mut g| g.take()) {
                    let _ = tx.send(());
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })
    .map_err(|e| anyhow!("registering the service control handler: {e}"))?;

    let starting = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: windows_service::service::ServiceControlAccept::empty(),
        exit_code: windows_service::service::ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    };
    status_handle.set_service_status(starting).ok();

    let cfg = read_config()?.ok_or_else(|| anyhow!("missing {}", config_path().display()))?;
    let install_dir = PathBuf::from(&cfg.install_dir);
    let kh_path = install_dir.join("kh.exe").to_string_lossy().to_string();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let running = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: windows_service::service::ServiceControlAccept::STOP,
        exit_code: windows_service::service::ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: Some(std::process::id()),
    };
    status_handle.set_service_status(running.clone()).ok();

    let result = rt.block_on(crate::app::serve(
        crate::app::Settings { data_dir: PathBuf::from(&cfg.data_dir), kh_path, owner_sid: cfg.owner_sid },
        rx,
    ));

    let stopped = ServiceStatus { current_state: ServiceState::Stopped, ..running };
    status_handle.set_service_status(stopped).ok();
    result
}

fn report_error(message: &str) {
    eprintln!("MCP Keyholder: {message}");
    unsafe {
        let source = RegisterEventSourceW(null_mut(), wide(SERVICE_NAME).as_ptr());
        if !source.is_null() {
            let text = wide(message);
            let ptrs = [text.as_ptr()];
            windows_sys::Win32::System::EventLog::ReportEventW(
                source,
                1, // EVENTLOG_ERROR_TYPE
                0,
                0,
                null_mut(),
                1,
                0,
                ptrs.as_ptr(),
                null_mut(),
            );
            DeregisterEventSource(source);
        }
    }
}

// ---------- install / uninstall ----------

pub fn install(source: Option<PathBuf>, owner: Option<String>, app: Option<String>) -> Result<()> {
    if !is_admin() {
        bail!("installing the service requires administrator rights");
    }
    {
        let m = manager()?;
        if m.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS).is_ok() {
            bail!("the MCP Keyholder service is already installed: uninstall it first");
        }
    }
    let owner_sid = match owner {
        Some(o) => o,
        None => current_sid()?,
    };
    if owner_sid.is_empty() {
        bail!("could not determine the user SID: run this from the MCP Keyholder app");
    }

    let data_dir = program_data_dir();
    let install_dir = program_files_dir();
    std::fs::create_dir_all(&data_dir).with_context(|| format!("creating {}", data_dir.display()))?;
    std::fs::create_dir_all(&install_dir).with_context(|| format!("creating {}", install_dir.display()))?;

    // 1. The vault moves in before the folder is locked down.
    if let Some(src) = source {
        let dst = data_dir.join("vault.db");
        if src.exists() && !dst.exists() {
            std::fs::copy(&src, &dst).with_context(|| format!("moving {}", src.display()))?;
            for suffix in ["-wal", "-shm"] {
                let from = PathBuf::from(format!("{}{suffix}", src.display()));
                if from.exists() {
                    let _ = std::fs::copy(&from, format!("{}{suffix}", dst.display()));
                }
            }
            println!("Vault moved to {}", dst.display());
        } else if dst.exists() {
            println!("A vault already exists in {}; leaving it as is", dst.display());
        }
    }

    // 2. Binaries into Program Files.
    let me = std::env::current_exe()?;
    let svc_exe = install_dir.join(SERVICE_EXE);
    if me != svc_exe {
        std::fs::copy(&me, &svc_exe).with_context(|| format!("copying to {}", svc_exe.display()))?;
    }
    let kh_src = me.with_file_name("kh.exe");
    if kh_src.exists() {
        std::fs::copy(&kh_src, install_dir.join("kh.exe"))?;
    } else {
        println!("Warning: kh.exe was not found next to this program; agents will have no way to connect");
    }

    // 3. Lock the data folder to the service account and SYSTEM.
    lock_down(&data_dir)?;
    std::fs::write(
        config_path(),
        serde_json::to_vec_pretty(&ServiceConfig {
            owner_sid: owner_sid.clone(),
            install_dir: install_dir.to_string_lossy().to_string(),
            data_dir: data_dir.to_string_lossy().to_string(),
            app_path: app,
        })?,
    )
    .with_context(|| "writing service.json".to_string())?;
    allow_owner_read(&config_path(), &owner_sid)?;

    // 4. The service itself.
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
        .map_err(|e| anyhow!("no access to the service control manager: {e}"))?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: svc_exe.clone(),
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: Some(OsString::from(SERVICE_ACCOUNT)),
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::START | ServiceAccess::QUERY_STATUS)
        .map_err(|e| anyhow!("could not create the service: {e}"))?;
    let _ = service.set_description(SERVICE_DESC);
    service.start::<&OsStr>(&[]).map_err(|e| anyhow!("the service failed to start: {e}"))?;
    println!("Service installed and started. Data: {}", data_dir.display());
    println!("Binaries: {}", install_dir.display());
    Ok(())
}

pub fn uninstall(restore: Option<PathBuf>) -> Result<()> {
    if !is_admin() {
        bail!("uninstalling the service requires administrator rights");
    }
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| anyhow!("no access to the service control manager: {e}"))?;
    let data_dir = program_data_dir();

    // 1. Stop the service so the vault file is closed.
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE)
        .ok();
    if let Some(service) = &service {
        let _ = service.stop();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match service.query_status() {
                Ok(s) if s.current_state == ServiceState::Stopped => break,
                _ if Instant::now() > deadline => bail!("the service did not stop within 20 seconds"),
                _ => std::thread::sleep(Duration::from_millis(200)),
            }
        }
    }

    // 2. Bring the vault back before anything is deleted (administrators can read the folder).
    if let Some(dir) = &restore {
        let from = data_dir.join("vault.db");
        if from.exists() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
            let to = dir.join("vault.db");
            if to.exists() {
                bail!("{} already contains vault.db: rename it and try again", dir.display());
            }
            std::fs::copy(&from, &to).with_context(|| format!("restoring the vault to {}", to.display()))?;
            for suffix in ["-wal", "-shm"] {
                let f = PathBuf::from(format!("{}{suffix}", from.display()));
                if f.exists() {
                    std::fs::copy(&f, format!("{}{suffix}", to.display())).with_context(|| "restoring the SQLite journal")?;
                }
            }
            println!("Vault restored to {}", dir.display());
        }
    }

    // 3. Now the service and its files can go.
    if let Some(service) = service {
        service.delete().map_err(|e| anyhow!("could not delete the service: {e}"))?;
        println!("Service removed");
    } else {
        println!("Service was not installed");
    }
    if data_dir.exists() {
        std::fs::remove_dir_all(&data_dir).with_context(|| format!("deleting {}", data_dir.display()))?;
    }
    let pf = program_files_dir();
    if pf.exists() {
        let _ = std::fs::remove_dir_all(&pf);
    }
    Ok(())
}

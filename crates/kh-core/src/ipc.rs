//! Local IPC endpoint: a per-user named pipe on Windows (DACL: current user + SYSTEM,
//! remote clients rejected, first-instance only), a 0700 unix socket elsewhere.

use std::io;

#[cfg(windows)]
pub use win::*;

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null_mut;

    use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    fn wide_to_string(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut len = 0;
        unsafe {
            while *p.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
        }
    }

    /// String SID of the current user, e.g. `S-1-5-21-...`.
    pub fn current_user_sid() -> io::Result<String> {
        unsafe {
            let mut token: HANDLE = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut len = 0u32;
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
            let mut buf = vec![0u8; len as usize];
            let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as *mut c_void, len, &mut len);
            CloseHandle(token);
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            let tu = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut s: *mut u16 = null_mut();
            if ConvertSidToStringSidW(tu.User.Sid, &mut s) == 0 {
                return Err(io::Error::last_os_error());
            }
            let out = wide_to_string(s);
            LocalFree(s as *mut c_void);
            Ok(out)
        }
    }

    pub fn pipe_name() -> String {
        let sid = current_user_sid().unwrap_or_else(|_| "unknown".into());
        agent_pipe_name(&sid)
    }

    /// Agent channel for the user with SID `sid` (the service and the app must agree on the name).
    pub fn agent_pipe_name(sid: &str) -> String {
        pipe_name_for("keyholder", sid)
    }

    /// Interface channel: used by the app when the core runs in the service.
    pub fn ui_pipe_name(sid: &str) -> String {
        pipe_name_for("keyholder-ui", sid)
    }

    fn pipe_name_for(prefix: &str, sid: &str) -> String {
        let h = crate::crypto::sha256(sid.as_bytes());
        format!(r"\\.\pipe\{prefix}-{}", data_encoding::HEXLOWER.encode(&h[..8]))
    }

    struct Sa(SECURITY_ATTRIBUTES);
    unsafe impl Send for Sa {}
    unsafe impl Sync for Sa {}

    /// Security descriptor with a protected DACL: full access for `sid`, for the account this
    /// process runs under (it creates every further pipe instance, which needs
    /// FILE_CREATE_PIPE_INSTANCE) and SYSTEM. Built once per SID, kept for the process lifetime.
    fn security_attributes(sid: &str) -> io::Result<Sa> {
        use std::collections::HashMap;
        use std::sync::{LazyLock, Mutex};
        static CACHE: LazyLock<Mutex<HashMap<String, usize>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
        let cache = &*CACHE;
        if let Some(p) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(sid) {
            return Ok(Sa(SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: *p as *mut c_void,
                bInheritHandle: 0,
            }));
        }
        unsafe {
            let me = current_user_sid().unwrap_or_default();
            let extra = if !me.is_empty() && me != sid { format!("(A;;GA;;;{me})") } else { String::new() };
            let sddl: Vec<u16> = format!("D:P(A;;GA;;;{sid}){extra}(A;;GA;;;SY)\0").encode_utf16().collect();
            let mut sd: *mut c_void = null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()) == 0 {
                return Err(io::Error::last_os_error());
            }
            cache.lock().unwrap_or_else(|e| e.into_inner()).insert(sid.to_string(), sd as usize);
            Ok(Sa(SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            }))
        }
    }

    /// Creates one server instance. `first` = fail if anyone already owns the name (squatting check).
    pub fn create_server(first: bool) -> io::Result<NamedPipeServer> {
        let sid = current_user_sid()?;
        create_server_for(&pipe_name(), &sid, first)
    }

    /// Creates one server instance named `name`, readable only by `sid` and SYSTEM.
    pub fn create_server_for(name: &str, sid: &str, first: bool) -> io::Result<NamedPipeServer> {
        let sa = security_attributes(sid)?;
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .max_instances(64)
                .create_with_security_attributes_raw(name, &sa.0 as *const SECURITY_ATTRIBUTES as *mut c_void)
        }
    }

    pub async fn connect() -> io::Result<NamedPipeClient> {
        connect_named(&pipe_name()).await
    }

    pub async fn connect_named(name: &str) -> io::Result<NamedPipeClient> {
        use tokio::net::windows::named_pipe::ClientOptions;
        for _ in 0..50 {
            match ClientOptions::new().open(name) {
                Ok(c) => return Ok(c),
                // All instances busy: wait a bit and retry.
                Err(e) if e.raw_os_error() == Some(231) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(io::ErrorKind::TimedOut, "the MCP Keyholder pipe is busy"))
    }

    /// Owner (user) SID of a process, e.g. `S-1-5-21-...` or `S-1-5-80-...` for a service account.
    pub fn process_user_sid(pid: u32) -> Option<String> {
        unsafe {
            use windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return None;
            }
            let mut token: HANDLE = null_mut();
            if OpenProcessToken(h, TOKEN_QUERY, &mut token) == 0 {
                CloseHandle(h);
                return None;
            }
            let mut len = 0u32;
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
            let mut buf = vec![0u8; len as usize];
            let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as *mut c_void, len, &mut len);
            CloseHandle(token);
            CloseHandle(h);
            if ok == 0 {
                return None;
            }
            let tu = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut s: *mut u16 = null_mut();
            if ConvertSidToStringSidW(tu.User.Sid, &mut s) == 0 {
                return None;
            }
            let out = wide_to_string(s);
            LocalFree(s as *mut c_void);
            Some(out)
        }
    }

    /// Resolves `NT SERVICE\Name` (or any account) to a string SID without needing the service to exist.
    pub fn service_account_sid(account: &str) -> io::Result<String> {
        use windows_sys::Win32::Security::LookupAccountNameW;
        let name: Vec<u16> = account.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid_len = 0u32;
        let mut dom_len = 0u32;
        unsafe {
            // First call sizes the buffers; the account may be unknown, so a derived SID is the fallback.
            LookupAccountNameW(null_mut(), name.as_ptr(), null_mut(), &mut sid_len, null_mut(), &mut dom_len, null_mut());
            if sid_len > 0 {
                let mut sid = vec![0u8; sid_len as usize];
                let mut dom = vec![0u16; dom_len.max(1) as usize];
                let mut use_: i32 = 0;
                if LookupAccountNameW(
                    null_mut(),
                    name.as_ptr(),
                    sid.as_mut_ptr() as *mut c_void,
                    &mut sid_len,
                    dom.as_mut_ptr(),
                    &mut dom_len,
                    &mut use_,
                ) != 0
                {
                    let mut s: *mut u16 = null_mut();
                    if ConvertSidToStringSidW(sid.as_ptr() as *mut c_void, &mut s) != 0 {
                        let out = wide_to_string(s);
                        LocalFree(s as *mut c_void);
                        return Ok(out);
                    }
                }
            }
            // Virtual account SID derivation: S-1-5-80-<5 sub-authorities of SHA-1(uppercase name)>.
            let (domain, base) = match account.rsplit_once('\\') {
                Some((d, b)) => (d, b),
                None => ("", account),
            };
            if !domain.is_empty() && !base.is_empty() {
                use sha1::{Digest as _, Sha1};
                let up = base.to_uppercase();
                let utf16: Vec<u8> = up.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
                let h = Sha1::digest(&utf16);
                let parts: Vec<String> = h.chunks(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]).to_string()).collect();
                return Ok(format!("S-1-5-80-{}", parts.join("-")));
            }
            Err(io::Error::last_os_error())
        }
    }

    /// PID of a running Windows service, from the service control manager (no admin rights needed).
    pub fn service_pid(name: &str) -> Option<u32> {
        use windows_sys::Win32::System::Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
            SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_STATUS_PROCESS,
        };
        let n: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
            if scm.is_null() {
                return None;
            }
            let svc = OpenServiceW(scm, n.as_ptr(), SERVICE_QUERY_STATUS);
            if svc.is_null() {
                CloseServiceHandle(scm);
                return None;
            }
            let mut st: SERVICE_STATUS_PROCESS = std::mem::zeroed();
            let mut need = 0u32;
            let ok = QueryServiceStatusEx(
                svc,
                SC_STATUS_PROCESS_INFO,
                &mut st as *mut SERVICE_STATUS_PROCESS as *mut u8,
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut need,
            );
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            (ok != 0 && st.dwProcessId != 0).then_some(st.dwProcessId)
        }
    }

    pub fn client_pid(server: &NamedPipeServer) -> Option<u32> {
        let mut pid = 0u32;
        let ok = unsafe { GetNamedPipeClientProcessId(server.as_raw_handle() as HANDLE, &mut pid) };
        (ok != 0).then_some(pid)
    }

    pub fn server_pid(client: &NamedPipeClient) -> Option<u32> {
        let mut pid = 0u32;
        let ok = unsafe { GetNamedPipeServerProcessId(client.as_raw_handle() as HANDLE, &mut pid) };
        (ok != 0).then_some(pid)
    }

    pub fn process_image(pid: u32) -> Option<String> {
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return None;
            }
            let mut buf = vec![0u16; 1024];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
            CloseHandle(h);
            (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
        }
    }

    /// (pid, parent pid, exe name) for every process.
    fn snapshot() -> Vec<(u32, u32, String)> {
        let mut out = Vec::new();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return out;
            }
            let mut e: PROCESSENTRY32W = std::mem::zeroed();
            e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            if Process32FirstW(snap, &mut e) != 0 {
                loop {
                    out.push((e.th32ProcessID, e.th32ParentProcessID, wide_to_string(e.szExeFile.as_ptr())));
                    if Process32NextW(snap, &mut e) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
        out
    }

    /// "kh.exe ← node.exe ← claude.exe": the process and up to `depth` ancestors.
    pub fn process_chain(pid: u32, depth: usize) -> String {
        let snap = snapshot();
        let mut names = Vec::new();
        let mut cur = pid;
        for _ in 0..=depth {
            let Some((_, ppid, name)) = snap.iter().find(|(p, ..)| *p == cur) else { break };
            names.push(name.clone());
            if *ppid == 0 || *ppid == cur {
                break;
            }
            cur = *ppid;
        }
        names.join(" ← ")
    }
}

#[cfg(unix)]
pub use unix::*;

#[cfg(unix)]
mod unix {
    use std::io;
    use std::path::PathBuf;

    pub fn socket_path() -> PathBuf {
        let base = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"));
        #[cfg(target_os = "macos")]
        let dir = base.join("Library/Application Support/KeyHolder");
        #[cfg(not(target_os = "macos"))]
        let dir = base.join(".local/share/keyholder");
        dir.join("kh.sock")
    }

    pub fn ui_socket_path() -> PathBuf {
        let mut p = socket_path();
        p.set_file_name("kh-ui.sock");
        p
    }

    pub async fn connect_ui() -> io::Result<tokio::net::UnixStream> {
        tokio::net::UnixStream::connect(ui_socket_path()).await
    }

    pub async fn connect() -> io::Result<tokio::net::UnixStream> {
        tokio::net::UnixStream::connect(socket_path()).await
    }

    pub fn process_chain(_pid: u32, _depth: usize) -> String {
        String::new()
    }
}

/// Human-readable name for an io error from `connect`.
pub fn describe_connect_error(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::NotFound => "MCP Keyholder is not running".to_string(),
        _ => format!("could not connect to MCP Keyholder: {e}"),
    }
}

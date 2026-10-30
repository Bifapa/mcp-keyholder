//! Locks the vault when the Windows session locks, when the machine goes to sleep, or when
//! the user logs off.
//!
//! A message-only window (never shown, never on screen) receives `WM_WTSSESSION_CHANGE` and
//! `WM_POWERBROADCAST`. In service mode the app is the only part that sees the user's session,
//! so it passes the lock on to the service over the interface channel.

use serde_json::json;
use tauri::{AppHandle, Manager};

use crate::state::AppState;

const CLASS: &str = "KeyHolderSessionWatcher";

/// Starts the watcher thread. Does nothing on platforms without these notifications.
pub fn spawn(app: AppHandle) {
    #[cfg(windows)]
    win::start(CLASS, Box::new(move || lock(&app)));
}

fn lock(app: &AppHandle) {
    if let Some(d) = app.state::<AppState>().local().cloned() {
        d.lock_ui();
        return;
    }
    if let Some(c) = app.state::<AppState>().service_client() {
        tauri::async_runtime::spawn(async move {
            let _ = c.call("lock_ui", json!({})).await;
        });
    }
}

#[cfg(windows)]
mod win {
    use std::ptr::null_mut;
    use std::sync::{mpsc, LazyLock, Mutex};

    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::RemoteDesktop::WTSRegisterSessionNotification;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
        TranslateMessage, MSG, WNDCLASSW,
    };

    pub const WM_WTSSESSION_CHANGE: u32 = 0x02B1;
    pub const WM_POWERBROADCAST: u32 = 0x0218;
    pub const WM_ENDSESSION: u32 = 0x0016;
    pub const WTS_SESSION_LOCK: usize = 0x7;
    pub const PBT_APMSUSPEND: usize = 0x4;
    const NOTIFY_FOR_THIS_SESSION: u32 = 0;
    const HWND_MESSAGE: isize = -3;

    /// What to do when the session locks, sleeps or ends. Set once per process.
    static ON_LOCK: LazyLock<Mutex<Option<Box<dyn Fn() + Send + Sync>>>> = LazyLock::new(|| Mutex::new(None));

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
        let fire = match msg {
            WM_WTSSESSION_CHANGE => w == WTS_SESSION_LOCK,
            WM_POWERBROADCAST => w == PBT_APMSUSPEND,
            WM_ENDSESSION => w != 0,
            _ => false,
        };
        if fire {
            if let Some(cb) = ON_LOCK.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
                cb();
            }
            return 0;
        }
        DefWindowProcW(hwnd, msg, w, l)
    }

    /// Creates the message-only window on its own thread and runs the message loop.
    /// The window handle is reported back so tests can drive it.
    pub fn start(class: &str, cb: Box<dyn Fn() + Send + Sync>) {
        start_with_handle(class, cb, None);
    }

    pub fn start_with_handle(class: &str, cb: Box<dyn Fn() + Send + Sync>, ready: Option<mpsc::Sender<usize>>) {
        *ON_LOCK.lock().unwrap_or_else(|e| e.into_inner()) = Some(cb);
        let class = class.to_string();
        let _ = std::thread::Builder::new()
            .name("kh-session-watch".into())
            .spawn(move || unsafe {
                let hinst = GetModuleHandleW(null_mut());
                let class_name = wide(&class);
                let wc = WNDCLASSW {
                    style: 0,
                    lpfnWndProc: Some(wndproc),
                    cbClsExtra: 0,
                    cbWndExtra: 0,
                    hInstance: hinst,
                    hIcon: null_mut(),
                    hCursor: null_mut(),
                    hbrBackground: null_mut(),
                    lpszMenuName: null_mut(),
                    lpszClassName: class_name.as_ptr(),
                };
                RegisterClassW(&wc);
                let title = wide("KeyHolder session watcher");
                let hwnd = CreateWindowExW(
                    0,
                    class_name.as_ptr(),
                    title.as_ptr(),
                    0,
                    0,
                    0,
                    0,
                    0,
                    HWND_MESSAGE as HWND,
                    null_mut(),
                    hinst,
                    null_mut(),
                );
                if hwnd.is_null() {
                    if let Some(tx) = ready {
                        let _ = tx.send(0);
                    }
                    return;
                }
                WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION);
                if let Some(tx) = ready {
                    let _ = tx.send(hwnd as usize);
                }
                let mut msg: MSG = std::mem::zeroed();
                while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            });
    }

    /// Posts the same message Windows posts when the session locks (used by tests).
    #[cfg(test)]
    pub fn post_session_lock(hwnd: usize) -> bool {
        use windows_sys::Win32::UI::WindowsAndMessaging::PostMessageW;
        unsafe { PostMessageW(hwnd as HWND, WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK, 0) != 0 }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::win;

    #[test]
    fn session_lock_reaches_the_handler() {
        let hits = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = std::sync::mpsc::channel::<usize>();
        let h = hits.clone();
        win::start_with_handle(
            "KeyHolderSessionWatcherTest",
            Box::new(move || {
                h.fetch_add(1, Ordering::SeqCst);
            }),
            Some(tx),
        );
        let hwnd = rx.recv_timeout(std::time::Duration::from_secs(5)).expect("watcher window created");
        assert_ne!(hwnd, 0, "the watcher window must exist");
        assert!(win::post_session_lock(hwnd), "lock message posted");
        for _ in 0..50 {
            if hits.load(Ordering::SeqCst) > 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1, "a session lock must lock the vault");
    }
}

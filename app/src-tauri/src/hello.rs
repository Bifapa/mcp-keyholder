//! Windows Hello: presence proof that an agent cannot fake and cannot replay.
//!
//! Used as an alternative to the authenticator code for `pin`/`otp` requests and for step-up.
//! The dialog belongs to Windows (TPM-backed credential), so neither the webview nor a fake
//! window can stand in for it.

use serde_json::json;
use tauri::{AppHandle, Manager};

use crate::state::AppState;

/// Is Windows Hello set up on this machine right now? Never shows a dialog.
#[cfg(windows)]
pub fn available() -> bool {
    #[cfg(windows)]
    use windows::Security::Credentials::UI::{UserConsentVerifier, UserConsentVerifierAvailability};

    let r = run(|| {
        let op = UserConsentVerifier::CheckAvailabilityAsync().map_err(|e| e.message())?;
        let a = wait(&op)?;
        Ok(a == UserConsentVerifierAvailability::Available)
    });
    matches!(r, Ok(true))
}

#[cfg(not(windows))]
pub fn available() -> bool {
    false
}

/// Shows the Windows Hello dialog and waits for the answer.
#[cfg(windows)]
pub fn verify(message: &str) -> Result<(), String> {
    use windows::core::HSTRING;
    use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};

    if !available() {
        return Err("Windows Hello не настроен на этом компьютере".into());
    }
    let msg = HSTRING::from(message);
    run(move || {
        let op = UserConsentVerifier::RequestVerificationAsync(&msg).map_err(|e| e.message())?;
        let r = wait(&op)?;
        if r == UserConsentVerificationResult::Verified {
            Ok(())
        } else if r == UserConsentVerificationResult::Canceled {
            Err("отменено".into())
        } else if r == UserConsentVerificationResult::RetriesExhausted {
            Err("слишком много попыток".into())
        } else {
            Err("Windows Hello не подтвердил присутствие".into())
        }
    })
}

#[cfg(not(windows))]
pub fn verify(_message: &str) -> Result<(), String> {
    Err("Windows Hello есть только в Windows".into())
}

/// WinRT needs its own thread with a COM apartment, and the dialog must not block a runtime worker.
#[cfg(windows)]
fn run<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("kh-hello".into())
        .spawn(move || {
            unsafe {
                use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
                let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
            }
            let _ = tx.send(f());
        })
        .map_err(|e| format!("не удалось запустить проверку присутствия: {e}"))?;
    rx.recv_timeout(std::time::Duration::from_secs(120))
        .map_err(|_| "Windows Hello не ответил".to_string())?
}

/// Waits for a WinRT operation by polling its status (no executor needed).
#[cfg(windows)]
fn wait<T: windows::core::RuntimeType>(
    op: &windows_future::IAsyncOperation<T>,
) -> Result<T, String> {
    use windows_future::AsyncStatus;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(110);
    loop {
        match op.Status().map_err(|e| e.message())? {
            AsyncStatus::Started => {
                if std::time::Instant::now() > deadline {
                    return Err("Windows Hello не ответил".into());
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            _ => return op.GetResults().map_err(|e| e.message()),
        }
    }
}

/// Step-up with the master password and presence instead of the authenticator code.
/// The core runs the Windows Hello dialog itself (see `TauriEvents::verify_presence`).
pub async fn stepup(app: &AppHandle, password: String) -> Result<i64, String> {
    let st = app.state::<AppState>();
    let until = st.call("stepup", json!({ "password": password, "hello": true })).await?;
    Ok(until.as_i64().unwrap_or(0))
}

/// Approve a `pin`/`otp` request with presence instead of a code (the core shows the dialog).
pub async fn approve(app: &AppHandle, id: &str, keep: Vec<String>, ttl_minutes: u32, block_session: bool) -> Result<(), String> {
    let st = app.state::<AppState>();
    st.call(
        "approval_decide",
        json!({
            "id": id,
            "approve": true,
            "keep": keep,
            "ttl_minutes": ttl_minutes,
            "code": null,
            "block_session": block_session,
            "hello": true,
        }),
    )
    .await?;
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    /// Availability must be answerable without showing any dialog.
    #[test]
    fn availability_is_reported_without_a_dialog() {
        let a = super::available();
        println!("Windows Hello доступен: {a}");
        // No assertion on the value: a machine without a PIN or face simply answers "no".
    }
}

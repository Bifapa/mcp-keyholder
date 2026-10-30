//! Keeping key material out of reach of the paging file and crash dumps.

/// Locks the pages that hold `data` into physical memory (`VirtualLock`).
///
/// Best effort: a locked page is a process-wide property, so the same page may serve other
/// allocations. Failure (working-set quota) is not fatal — the value is still `zeroize`d.
#[cfg(windows)]
pub fn lock_pages(data: &[u8]) -> bool {
    use windows_sys::Win32::System::Memory::VirtualLock;
    if data.is_empty() {
        return true;
    }
    unsafe { VirtualLock(data.as_ptr() as *mut std::ffi::c_void, data.len()) != 0 }
}

#[cfg(not(windows))]
pub fn lock_pages(_data: &[u8]) -> bool {
    false
}

/// Asks Windows Error Reporting to skip this application, so a crash cannot produce a dump
/// that contains decrypted keys.
#[cfg(windows)]
pub fn exclude_from_wer(exe_name: &str) {
    use windows_sys::Win32::System::ErrorReporting::WerAddExcludedApplication;
    let name: Vec<u16> = exe_name.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        WerAddExcludedApplication(name.as_ptr(), 0);
    }
}

#[cfg(not(windows))]
pub fn exclude_from_wer(_exe_name: &str) {}

//! Copies a secret to the clipboard, excluded from clipboard history, cloud clipboard
//! and clipboard monitors, and clears it after 30 s if it is still ours.

#[cfg(windows)]
pub fn copy_secret(text: &str) -> Result<(), String> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard, RegisterClipboardFormatW,
        SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
    use zeroize::Zeroize;

    const CF_UNICODETEXT: u32 = 13;

    unsafe fn put(format: u32, bytes: &[u8]) -> bool {
        let h = GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1));
        if h.is_null() {
            return false;
        }
        let p = GlobalLock(h) as *mut u8;
        if p.is_null() {
            return false;
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
        GlobalUnlock(h);
        !SetClipboardData(format, h as HANDLE).is_null()
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe {
        let mut opened = false;
        for _ in 0..10 {
            if OpenClipboard(null_mut()) != 0 {
                opened = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(30));
        }
        if !opened {
            return Err("the clipboard is in use by another program".into());
        }
        EmptyClipboard();
        let mut w: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let mut bytes: Vec<u8> = w.iter().flat_map(|c| c.to_le_bytes()).collect();
        let ok = put(CF_UNICODETEXT, &bytes);
        bytes.zeroize();
        w.zeroize();
        for (name, data) in [
            ("ExcludeClipboardContentFromMonitorProcessing", &[0u8; 1][..]),
            ("CanIncludeInClipboardHistory", &0u32.to_le_bytes()[..]),
            ("CanUploadToCloudClipboard", &0u32.to_le_bytes()[..]),
        ] {
            let fmt = RegisterClipboardFormatW(wide(name).as_ptr());
            if fmt != 0 {
                put(fmt, data);
            }
        }
        CloseClipboard();
        if !ok {
            return Err("could not write to the clipboard".into());
        }
        let seq = GetClipboardSequenceNumber();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(30));
            if GetClipboardSequenceNumber() == seq && OpenClipboard(null_mut()) != 0 {
                EmptyClipboard();
                CloseClipboard();
            }
        });
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn copy_secret(_text: &str) -> Result<(), String> {
    Err("copying is only available on Windows for now".into())
}

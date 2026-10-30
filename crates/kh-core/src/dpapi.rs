//! DPAPI: keeps the vault's data keys for the account the core runs under.
//!
//! Used only in service mode: the Windows service runs as `NT SERVICE\KeyHolder`, so a
//! blob protected here can be unwrapped by the service (and by nobody else) without a
//! master password. The master password still guards the vault file itself and is still
//! required to change protection, restore a backup and leave full lock.

use zeroize::Zeroizing;

use crate::Result;

#[cfg(windows)]
pub fn protect(data: &[u8]) -> Result<Vec<u8>> {
    use std::ffi::c_void;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    unsafe {
        let mut input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: null_mut() };
        let ok = CryptProtectData(&mut input, null_mut(), null_mut(), null_mut(), null_mut(), CRYPTPROTECT_UI_FORBIDDEN, &mut out);
        if ok == 0 {
            return Err(crate::Error::Crypto);
        }
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData as *mut c_void);
        Ok(v)
    }
}

#[cfg(windows)]
pub fn unprotect(blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use std::ffi::c_void;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    unsafe {
        let mut input = CRYPT_INTEGER_BLOB { cbData: blob.len() as u32, pbData: blob.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: null_mut() };
        let ok = CryptUnprotectData(
            &mut input,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        );
        if ok == 0 {
            return Err(crate::Error::Crypto);
        }
        let v = Zeroizing::new(std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec());
        LocalFree(out.pbData as *mut c_void);
        Ok(v)
    }
}

#[cfg(not(windows))]
pub fn protect(_data: &[u8]) -> Result<Vec<u8>> {
    Err(crate::Error::Invalid("DPAPI есть только на Windows".into()))
}

#[cfg(not(windows))]
pub fn unprotect(_blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    Err(crate::Error::Invalid("DPAPI есть только на Windows".into()))
}

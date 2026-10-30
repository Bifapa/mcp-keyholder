//! RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30 s) with the "one code, one approval" rule:
//! a code is accepted only if its time step is strictly greater than the last accepted step.

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::crypto::ct_eq;

pub const STEP_SECS: i64 = 30;
pub const DIGITS: u32 = 6;

pub fn new_seed() -> [u8; 20] {
    crate::crypto::random_bytes::<20>()
}

pub fn seed_base32(seed: &[u8]) -> String {
    BASE32_NOPAD.encode(seed)
}

pub fn otpauth_uri(seed: &[u8], account: &str) -> String {
    format!(
        "otpauth://totp/MCP%20Keyholder:{}?secret={}&issuer=MCP%20Keyholder&algorithm=SHA1&digits={}&period={}",
        account,
        seed_base32(seed),
        DIGITS,
        STEP_SECS
    )
}

pub fn step_at(unix_secs: i64) -> i64 {
    unix_secs.div_euclid(STEP_SECS)
}

pub fn code_at_step(seed: &[u8], step: i64) -> String {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(seed).expect("any key length");
    mac.update(&(step as u64).to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[19] & 0x0f) as usize;
    let bin = ((u32::from(h[off]) & 0x7f) << 24)
        | (u32::from(h[off + 1]) << 16)
        | (u32::from(h[off + 2]) << 8)
        | u32::from(h[off + 3]);
    format!("{:0width$}", bin % 10u32.pow(DIGITS), width = DIGITS as usize)
}

/// Returns the matched step if `code` is valid for the current or previous step
/// and that step is newer than `last_step`.
pub fn verify(seed: &[u8], code: &str, now_secs: i64, last_step: i64) -> Option<i64> {
    let code: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    if code.len() != DIGITS as usize {
        return None;
    }
    let now = step_at(now_secs);
    let mut hit = None;
    // Check both candidates without early exit to keep timing uniform.
    for step in [now - 1, now] {
        let ok = ct_eq(code_at_step(seed, step).as_bytes(), code.as_bytes());
        if ok && step > last_step {
            hit = Some(step);
        }
    }
    hit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_vector() {
        // RFC 6238 appendix B, SHA1 seed "12345678901234567890", T = 59 s -> 94287082 (8 digits).
        let seed = b"12345678901234567890";
        assert_eq!(code_at_step(seed, step_at(59)), "287082");
        assert_eq!(code_at_step(seed, step_at(1111111109)), "081804");
    }

    #[test]
    fn one_code_one_approval() {
        let seed = new_seed();
        let now = 1_800_000_000;
        let code = code_at_step(&seed, step_at(now));
        let s = verify(&seed, &code, now, 0).expect("fresh code accepted");
        assert!(verify(&seed, &code, now, s).is_none(), "replay rejected");
        assert!(verify(&seed, "000000x", now, 0).is_none());
    }
}

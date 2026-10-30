//! Primitives: Argon2id KDF, XChaCha20-Poly1305 sealing, HKDF, HMAC-SHA256.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{Error, Result};

pub type Key32 = Zeroizing<[u8; 32]>;
type HmacSha256 = Hmac<Sha256>;

pub const NONCE_LEN: usize = 24;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // 256 MiB, 3 passes, 4 lanes: roughly 0.5–1.5 s on a desktop.
        KdfParams { m_kib: 256 * 1024, t: 3, p: 4 }
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

pub fn random_key() -> Key32 {
    Zeroizing::new(random_bytes::<32>())
}

pub fn derive_kek(password: &str, salt: &[u8], p: KdfParams) -> Result<Key32> {
    let params = Params::new(p.m_kib, p.t, p.p, Some(32)).map_err(|_| Error::Crypto)?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    a2.hash_password_into(password.as_bytes(), salt, out.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(out)
}

/// Seal with a fresh random nonce. Returns (nonce, ciphertext||tag).
pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = random_bytes::<NONCE_LEN>();
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::Crypto)?;
    Ok((nonce.to_vec(), ct))
}

pub fn open(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != NONCE_LEN {
        return Err(Error::Crypto);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Crypto)
}

/// Wrap a 32-byte key: nonce || ciphertext.
pub fn wrap_key(kek: &[u8; 32], key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>> {
    let (n, ct) = seal(kek, key, aad)?;
    Ok([n, ct].concat())
}

pub fn unwrap_key(kek: &[u8; 32], blob: &[u8], aad: &[u8]) -> Result<Key32> {
    if blob.len() < NONCE_LEN {
        return Err(Error::Crypto);
    }
    let pt = open(kek, &blob[..NONCE_LEN], &blob[NONCE_LEN..], aad)?;
    if pt.len() != 32 {
        return Err(Error::Crypto);
    }
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&pt);
    Ok(k)
}

pub fn hkdf(ikm: &[u8; 32], info: &str) -> Key32 {
    let hk = Hkdf::<Sha256>::new(Some(b"keyholder/v1"), ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info.as_bytes(), out.as_mut()).expect("32 bytes is a valid HKDF length");
    out
}

pub fn hmac(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

pub fn hmac_verify(key: &[u8; 32], data: &[u8], tag: &[u8]) -> bool {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("any key length");
    m.update(data);
    m.verify_slice(tag).is_ok()
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_and_aad_binding() {
        let k = random_key();
        let (n, ct) = seal(&k, b"hello", b"aad-1").unwrap();
        assert_eq!(&open(&k, &n, &ct, b"aad-1").unwrap()[..], b"hello");
        assert!(open(&k, &n, &ct, b"aad-2").is_err());
    }

    #[test]
    fn wrap_unwrap() {
        let kek = random_key();
        let k = random_key();
        let blob = wrap_key(&kek, &k, b"w").unwrap();
        assert_eq!(unwrap_key(&kek, &blob, b"w").unwrap()[..], k[..]);
        assert!(unwrap_key(&random_key(), &blob, b"w").is_err());
    }
}

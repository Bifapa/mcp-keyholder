//! KeyHolder core.
//!
//! Everything that touches secret material lives here: key derivation, sealing,
//! the SQLite-backed vault, signed policy, TOTP, the audit chain and leak scanning.
//! The desktop app and the `kh` CLI only talk to this crate (or to the app over IPC).

pub mod crypto;
pub mod dpapi;
pub mod import;
pub mod ipc;
pub mod mem;
pub mod model;
pub mod protocol;
pub mod scan;
pub mod totp;
pub mod vault;

pub use model::*;
pub use vault::Vault;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("vault is locked")]
    Locked,
    #[error("vault is not set up yet")]
    NotInitialized,
    #[error("vault is already set up")]
    AlreadyInitialized,
    #[error("wrong master password")]
    BadPassword,
    #[error("wrong code")]
    BadCode,
    #[error("code entry is paused: too many wrong codes")]
    CodeLockout,
    #[error("integrity check failed: {0}")]
    Integrity(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("{0}")]
    Invalid(String),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("encryption error")]
    Crypto,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

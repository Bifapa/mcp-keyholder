//! SQLite-backed vault.
//!
//! Key hierarchy (see CONCEPT.md §11.5):
//!   master password --Argon2id--> KEK
//!   KEK wraps K_everyday (auto/soft keys) and K_guarded (otp/sealed keys, TOTP seed)
//!   K_guarded --HKDF--> K_policy (policy/settings/client MACs), K_log (audit MACs)
//! Every value is sealed with XChaCha20-Poly1305; the AAD binds vault id, key id,
//! version, partition and the policy hash, so ciphertexts cannot be moved between
//! records and policy cannot be edited in the database without detection.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use data_encoding::{BASE32_NOPAD, HEXLOWER};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, Key32, KdfParams};
use crate::model::*;
use crate::{now_ms, scan, totp, Error, Result};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL,
  grp TEXT NOT NULL,
  tags TEXT NOT NULL,
  tier TEXT NOT NULL,
  mode TEXT NOT NULL,
  env_name TEXT NOT NULL,
  status TEXT NOT NULL,
  version INTEGER NOT NULL,
  nonce BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  policy_mac BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_used_at INTEGER,
  use_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS clients (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  token_hash BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER,
  revoked INTEGER NOT NULL DEFAULT 0,
  blocked INTEGER NOT NULL DEFAULT 0,
  mac BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS leaks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  secret_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  client TEXT NOT NULL,
  session TEXT NOT NULL,
  comment TEXT NOT NULL,
  at INTEGER NOT NULL,
  resolved_at INTEGER
);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  client TEXT NOT NULL,
  session TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  outcome TEXT NOT NULL,
  detail TEXT NOT NULL,
  prev_hash BLOB NOT NULL,
  hash BLOB NOT NULL,
  mac BLOB NOT NULL
);
"#;

/// Failed OTP attempts allowed per window before codes are refused for a while.
const OTP_FAIL_LIMIT: usize = 5;
const OTP_FAIL_WINDOW_MS: i64 = 15 * 60 * 1000;

struct Unlocked {
    everyday: Key32,
    guarded: Key32,
    policy: Key32,
    log: Key32,
    totp_seed: Zeroizing<Vec<u8>>,
}

/// One audit record before it is chained.
#[derive(Debug, Clone, Default)]
pub struct LogInput {
    pub client: String,
    pub session: String,
    pub action: String,
    pub target: String,
    pub outcome: String,
    pub detail: String,
}

impl LogInput {
    pub fn new(action: &str, target: &str, outcome: &str) -> Self {
        LogInput {
            client: "user".into(),
            session: String::new(),
            action: action.into(),
            target: target.into(),
            outcome: outcome.into(),
            detail: String::new(),
        }
    }
    pub fn by(mut self, client: &str, session: &str) -> Self {
        self.client = client.into();
        self.session = session.into();
        self
    }
    pub fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = d.into();
        self
    }
}

/// Argon2id parameters for the PIN hash: lighter than the master key, still slow per guess.
const PIN_KDF: KdfParams = KdfParams { m_kib: 64 * 1024, t: 3, p: 1 };

#[derive(Serialize, Deserialize)]
struct PinRecord {
    salt: String,
    hash: String,
}

#[derive(Serialize, Deserialize)]
struct LogHead {
    count: i64,
    hash: String,
}

/// Material for first-run setup, kept in memory until the user confirms a TOTP code.
pub struct PendingSetup {
    password: Zeroizing<String>,
    antiphish: Zeroizing<String>,
    seed: Zeroizing<Vec<u8>>,
    recovery: Vec<String>,
}

impl PendingSetup {
    pub fn new(password: &str, antiphish_word: &str) -> Result<Self> {
        if password.chars().count() < 10 {
            return Err(Error::Invalid("the master password must be at least 10 characters long".into()));
        }
        let word = antiphish_word.trim();
        if word.chars().count() < 3 || word.chars().count() > 8 {
            return Err(Error::Invalid("anti-phishing word: 3 to 8 characters".into()));
        }
        let recovery = (0..10)
            .map(|_| {
                let raw = BASE32_NOPAD.encode(&crypto::random_bytes::<8>());
                format!("{}-{}-{}", &raw[0..4], &raw[4..8], &raw[8..12])
            })
            .collect();
        Ok(PendingSetup {
            password: Zeroizing::new(password.to_string()),
            antiphish: Zeroizing::new(word.to_string()),
            seed: Zeroizing::new(totp::new_seed().to_vec()),
            recovery,
        })
    }
    pub fn otpauth_uri(&self) -> String {
        totp::otpauth_uri(&self.seed, "vault")
    }
    pub fn seed_base32(&self) -> String {
        totp::seed_base32(&self.seed)
    }
    pub fn recovery_codes(&self) -> &[String] {
        &self.recovery
    }
}

pub struct Vault {
    conn: Connection,
    path: PathBuf,
    vault_id: Vec<u8>,
    keys: Option<Unlocked>,
    /// Last accepted TOTP step; kept in memory so resetting it in the DB does not enable replay.
    last_step: i64,
    otp_failures: VecDeque<i64>,
    otp_lock_until: i64,
    otp_lockouts: u32,
    pending_log: Vec<(i64, LogInput)>,
    /// New TOTP seed awaiting confirmation during a reissue; never in the database.
    pending_totp: Option<Zeroizing<Vec<u8>>>,
    /// The pending reissue was started with a recovery code (lost authenticator).
    pending_recovery: bool,
}

fn hex(b: &[u8]) -> String {
    HEXLOWER.encode(b)
}

/// `.mcpkey`: magic, header length (u32 LE), header JSON, nonce, ciphertext of the database.
/// The header is bound as AAD, so it cannot be swapped either.
pub const EXPORT_MAGIC: &[u8; 8] = b"MCPKEY01";
const EXPORT_INFO: &str = "mcpkey-export";

#[derive(Serialize, Deserialize)]
struct ExportHeader {
    format: u32,
    vault_id: String,
    kdf: KdfParams,
    salt: String,
    wrap_guarded: String,
    created_at: i64,
}

/// Opens a `.mcpkey` file with its master password and returns the vault database inside.
pub fn read_export(data: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let not_ours = || Error::Invalid("this is not an MCP Keyholder vault file (.mcpkey)".into());
    if data.len() < 12 || &data[..8] != EXPORT_MAGIC {
        return Err(not_ours());
    }
    let hlen = u32::from_le_bytes(data[8..12].try_into().expect("4 bytes")) as usize;
    if data.len() < 12 + hlen + crypto::NONCE_LEN {
        return Err(not_ours());
    }
    let header_raw = &data[12..12 + hlen];
    let h: ExportHeader = serde_json::from_slice(header_raw).map_err(|_| not_ours())?;
    if h.format != 1 {
        return Err(Error::Invalid("the file was made by a newer version of MCP Keyholder".into()));
    }
    // The parameters come from the file: refuse ones that would exhaust memory or time.
    if h.kdf.m_kib > 4 * 1024 * 1024 || h.kdf.t > 50 || h.kdf.p > 64 {
        return Err(not_ours());
    }
    let decode = |s: &str| HEXLOWER.decode(s.as_bytes()).map_err(|_| not_ours());
    let (vault_id, salt, wrap) = (decode(&h.vault_id)?, decode(&h.salt)?, decode(&h.wrap_guarded)?);
    let kek = crypto::derive_kek(password, &salt, h.kdf)?;
    let wrap_aad = format!("kh1|wrap|guarded|{}", hex(&vault_id)).into_bytes();
    let guarded = crypto::unwrap_key(&kek, &wrap, &wrap_aad).map_err(|_| Error::BadPassword)?;
    let key = crypto::hkdf(&guarded, EXPORT_INFO);
    let body = &data[12 + hlen..];
    let aad = [&EXPORT_MAGIC[..], header_raw].concat();
    crypto::open(&key, &body[..crypto::NONCE_LEN], &body[crypto::NONCE_LEN..], &aad)
        .map_err(|_| Error::Integrity("the .mcpkey file is damaged".into()))
}

fn remove_db_files(path: &Path) {
    let _ = std::fs::remove_file(path);
    for suffix in ["-wal", "-shm", "-journal"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

impl Vault {
    pub fn open(path: &Path) -> Result<Vault> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON;")?;
        conn.execute_batch(SCHEMA)?;
        let mut v = Vault {
            conn,
            path: path.to_path_buf(),
            vault_id: Vec::new(),
            keys: None,
            last_step: 0,
            otp_failures: VecDeque::new(),
            otp_lock_until: 0,
            otp_lockouts: 0,
            pending_log: Vec::new(),
            pending_totp: None,
            pending_recovery: false,
        };
        if let Some(id) = v.meta_get("vault_id")? {
            v.vault_id = id;
        }
        Ok(v)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Lost master password: the current file is put aside (still encrypted, so nothing is
    /// lost if the password turns up later) and an empty vault takes its place.
    /// Returns the path of the kept file.
    pub fn reset(&mut self) -> Result<PathBuf> {
        let path = self.path.clone();
        self.keys = None;
        // Close the database before renaming it (Windows will not rename an open file).
        self.conn = Connection::open_in_memory()?;
        let backup = path.with_extension(format!("db.reset-{}", now_ms()));
        std::fs::rename(&path, &backup)?;
        for suffix in ["-wal", "-shm"] {
            let f = PathBuf::from(format!("{}{suffix}", path.display()));
            if f.exists() {
                let _ = std::fs::rename(&f, format!("{}{suffix}", backup.display()));
            }
        }
        *self = Vault::open(&path)?;
        let name = backup.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        // Chained into the new log once the new vault is set up.
        self.pending_log.push((now_ms(), LogInput::new("reset", "vault", "ok").detail(format!("previous vault kept as {name}"))));
        Ok(backup)
    }

    /// Folds the WAL into the main file so a plain file copy is complete (used before moving
    /// the vault into the service).
    pub fn checkpoint(&self) -> Result<()> {
        self.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    // ---------- export / import (.mcpkey) ----------

    /// The whole vault as a `.mcpkey` file. The database copy is encrypted once more, so key
    /// names, clients and the log are not readable either; the header carries the salt and the
    /// wrapped K_guarded, so the master password alone opens the file on any machine.
    /// Machine-bound material (the DPAPI wrap of the service) is left out.
    pub fn export_file(&mut self) -> Result<Vec<u8>> {
        let key = crypto::hkdf(&self.keys()?.guarded, EXPORT_INFO);
        let header = ExportHeader {
            format: 1,
            vault_id: hex(&self.vault_id),
            kdf: serde_json::from_slice(&self.meta_get("kdf")?.ok_or(Error::NotInitialized)?)
                .map_err(|_| Error::Integrity("KDF parameters are damaged".into()))?,
            salt: hex(&self.meta_get("salt")?.ok_or(Error::NotInitialized)?),
            wrap_guarded: hex(&self.meta_get("wrap_guarded")?.ok_or(Error::NotInitialized)?),
            created_at: now_ms(),
        };
        let db = self.snapshot()?;
        let header = serde_json::to_vec(&header).expect("serialize");
        let aad = [&EXPORT_MAGIC[..], &header].concat();
        let (nonce, ct) = crypto::seal(&key, &db, &aad)?;
        let mut out = Vec::with_capacity(12 + header.len() + nonce.len() + ct.len());
        out.extend_from_slice(EXPORT_MAGIC);
        out.extend_from_slice(&(header.len() as u32).to_le_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        let count: i64 = self.conn.query_row("SELECT COUNT(*) FROM secrets", [], |r| r.get(0))?;
        self.log(LogInput::new("export", "vault", "ok").detail(format!("exported to a .mcpkey file, keys: {count}")))?;
        Ok(out)
    }

    /// A consistent copy of the database without the DPAPI wrap.
    fn snapshot(&self) -> Result<Zeroizing<Vec<u8>>> {
        let tmp = self.path.with_extension(format!("db.export-{}", now_ms()));
        let r = (|| -> Result<Zeroizing<Vec<u8>>> {
            self.conn.execute("VACUUM INTO ?1", params![tmp.to_string_lossy()])?;
            {
                let c = Connection::open(&tmp)?;
                c.execute_batch(
                    "PRAGMA journal_mode=DELETE; PRAGMA secure_delete=ON;
                     DELETE FROM meta WHERE k IN ('wrap_dpapi', 'wrap_dpapi.mac'); VACUUM;",
                )?;
            }
            Ok(Zeroizing::new(std::fs::read(&tmp)?))
        })();
        remove_db_files(&tmp);
        r
    }

    /// Replaces this vault with the one carried by a `.mcpkey` file and opens it with
    /// `password` (the master password the file was exported with). The current file is
    /// kept aside like on reset; returns its path (None when there was no vault yet).
    pub fn import_file(&mut self, data: &[u8], password: &str) -> Result<Option<PathBuf>> {
        let db = read_export(data, password)?;
        let path = self.path.clone();
        let tmp = path.with_extension(format!("db.import-{}", now_ms()));
        std::fs::write(&tmp, &db[..])?;
        // The new file must open with this password before the current one is touched.
        let check = (|| -> Result<()> {
            let v = Vault::open(&tmp)?;
            v.verify_password(password)?;
            v.checkpoint()
        })();
        if let Err(e) = check {
            remove_db_files(&tmp);
            return Err(e);
        }
        let had_vault = self.is_initialized();
        self.keys = None;
        // Close the database before renaming it (Windows will not rename an open file).
        self.conn = Connection::open_in_memory()?;
        let backup = path.with_extension(format!("db.before-import-{}", now_ms()));
        if had_vault {
            std::fs::rename(&path, &backup)?;
            for suffix in ["-wal", "-shm"] {
                let f = PathBuf::from(format!("{}{suffix}", path.display()));
                if f.exists() {
                    let _ = std::fs::rename(&f, format!("{}{suffix}", backup.display()));
                }
            }
        } else {
            remove_db_files(&path);
        }
        for suffix in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", tmp.display()));
        }
        std::fs::rename(&tmp, &path)?;
        *self = Vault::open(&path)?;
        let detail = if had_vault {
            let name = backup.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            format!("vault loaded from a .mcpkey file; previous one kept as {name}")
        } else {
            "vault loaded from a .mcpkey file".to_string()
        };
        self.pending_log.push((now_ms(), LogInput::new("import_vault", "vault", "ok").detail(detail)));
        self.unlock(password)?;
        Ok(had_vault.then_some(backup))
    }

    pub fn is_initialized(&self) -> bool {
        !self.vault_id.is_empty()
    }

    pub fn is_unlocked(&self) -> bool {
        self.keys.is_some()
    }

    fn keys(&self) -> Result<&Unlocked> {
        self.keys.as_ref().ok_or(Error::Locked)
    }

    // ---------- meta helpers ----------

    fn meta_get(&self, k: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row("SELECT v FROM meta WHERE k = ?1", params![k], |r| r.get::<_, Vec<u8>>(0))
            .optional()?)
    }

    fn meta_set(&self, k: &str, v: &[u8]) -> Result<()> {
        self.conn
            .execute("INSERT INTO meta(k, v) VALUES(?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v", params![k, v])?;
        Ok(())
    }

    fn aad(&self, what: &str) -> Vec<u8> {
        format!("kh1|{}|{}", what, hex(&self.vault_id)).into_bytes()
    }

    /// Store a value together with a MAC under K_policy.
    fn meta_set_signed(&self, k: &str, v: &[u8]) -> Result<()> {
        let mac = crypto::hmac(&self.keys()?.policy, &[k.as_bytes(), b"|", v].concat());
        self.meta_set(k, v)?;
        self.meta_set(&format!("{k}.mac"), &mac)
    }

    fn meta_get_signed(&self, k: &str) -> Result<Option<Vec<u8>>> {
        let Some(v) = self.meta_get(k)? else { return Ok(None) };
        let mac = self.meta_get(&format!("{k}.mac"))?.unwrap_or_default();
        if !crypto::hmac_verify(&self.keys()?.policy, &[k.as_bytes(), b"|", &v].concat(), &mac) {
            return Err(Error::Integrity(format!("signature of \"{k}\" does not match")));
        }
        Ok(Some(v))
    }

    // ---------- setup / unlock ----------

    pub fn finish_setup(&mut self, pending: &PendingSetup, code: &str) -> Result<()> {
        if self.is_initialized() {
            return Err(Error::AlreadyInitialized);
        }
        let now_s = now_ms() / 1000;
        let step = totp::verify(&pending.seed, code, now_s, 0).ok_or(Error::BadCode)?;

        let vault_id = crypto::random_bytes::<16>().to_vec();
        let salt = crypto::random_bytes::<16>();
        let kdf = KdfParams::default();
        let kek = crypto::derive_kek(&pending.password, &salt, kdf)?;
        let everyday = crypto::random_key();
        let guarded = crypto::random_key();

        self.vault_id = vault_id.clone();
        self.conn.execute_batch("BEGIN")?;
        let r = self.write_setup(pending, &kek, everyday, guarded, &salt, kdf, &vault_id, step);
        if r.is_err() {
            let _ = self.conn.execute_batch("ROLLBACK");
            self.vault_id.clear();
            self.keys = None;
            return r;
        }
        self.conn.execute_batch("COMMIT")?;
        for (ts, entry) in std::mem::take(&mut self.pending_log) {
            self.append_log(ts, entry)?;
        }
        self.log(LogInput::new("setup", "vault", "ok").detail("vault set up"))?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn write_setup(
        &mut self,
        pending: &PendingSetup,
        kek: &[u8; 32],
        everyday: Key32,
        guarded: Key32,
        salt: &[u8],
        kdf: KdfParams,
        vault_id: &[u8],
        step: i64,
    ) -> Result<()> {
        self.meta_set("format", b"1")?;
        self.meta_set("vault_id", vault_id)?;
        self.meta_set("kdf", &serde_json::to_vec(&kdf).expect("serialize"))?;
        self.meta_set("salt", salt)?;
        self.meta_set("wrap_everyday", &crypto::wrap_key(kek, &everyday, &self.aad("wrap|everyday"))?)?;
        self.meta_set("wrap_guarded", &crypto::wrap_key(kek, &guarded, &self.aad("wrap|guarded"))?)?;
        let (n, ct) = crypto::seal(&guarded, &pending.seed, &self.aad("totp"))?;
        self.meta_set("totp", &[n, ct].concat())?;
        let (n, ct) = crypto::seal(&guarded, pending.antiphish.as_bytes(), &self.aad("antiphish"))?;
        self.meta_set("antiphish", &[n, ct].concat())?;

        self.install_keys(everyday, guarded, Zeroizing::new(pending.seed.to_vec()));
        let rec: Vec<String> = pending
            .recovery
            .iter()
            .map(|c| hex(&crypto::sha256(&[vault_id, c.as_bytes()].concat())))
            .collect();
        self.meta_set_signed("recovery", &serde_json::to_vec(&rec).expect("serialize"))?;
        self.meta_set_signed("settings", &serde_json::to_vec(&Settings::default()).expect("serialize"))?;
        self.last_step = step;
        self.persist_last_step()
    }

    fn install_keys(&mut self, everyday: Key32, guarded: Key32, totp_seed: Zeroizing<Vec<u8>>) {
        let policy = crypto::hkdf(&guarded, "policy");
        let log = crypto::hkdf(&guarded, "log");
        self.keys = Some(Unlocked { everyday, guarded, policy, log, totp_seed });
        // Keep the key pages out of the paging file while the vault is open. Locked after the
        // move into `self.keys`: that is where they live from now on (locking the locals above
        // would only pin a stack frame).
        if let Some(k) = self.keys.as_ref() {
            crate::mem::lock_pages(&k.everyday[..]);
            crate::mem::lock_pages(&k.guarded[..]);
            crate::mem::lock_pages(&k.policy[..]);
            crate::mem::lock_pages(&k.log[..]);
            crate::mem::lock_pages(&k.totp_seed);
        }
    }

    fn derive_and_unwrap(&self, password: &str) -> Result<(Key32, Key32)> {
        if !self.is_initialized() {
            return Err(Error::NotInitialized);
        }
        let kdf: KdfParams = serde_json::from_slice(&self.meta_get("kdf")?.ok_or(Error::NotInitialized)?)
            .map_err(|_| Error::Integrity("KDF parameters are damaged".into()))?;
        let salt = self.meta_get("salt")?.ok_or(Error::NotInitialized)?;
        let kek = crypto::derive_kek(password, &salt, kdf)?;
        let we = self.meta_get("wrap_everyday")?.ok_or(Error::NotInitialized)?;
        let wg = self.meta_get("wrap_guarded")?.ok_or(Error::NotInitialized)?;
        let everyday = crypto::unwrap_key(&kek, &we, &self.aad("wrap|everyday")).map_err(|_| Error::BadPassword)?;
        let guarded = crypto::unwrap_key(&kek, &wg, &self.aad("wrap|guarded")).map_err(|_| Error::BadPassword)?;
        Ok((everyday, guarded))
    }

    pub fn unlock(&mut self, password: &str) -> Result<()> {
        let (everyday, guarded) = self.derive_and_unwrap(password)?;
        let blob = self.meta_get("totp")?.ok_or(Error::NotInitialized)?;
        if blob.len() < crypto::NONCE_LEN {
            return Err(Error::Integrity("TOTP secret is damaged".into()));
        }
        let seed = crypto::open(&guarded, &blob[..crypto::NONCE_LEN], &blob[crypto::NONCE_LEN..], &self.aad("totp"))
            .map_err(|_| Error::Integrity("TOTP secret is damaged".into()))?;
        self.install_keys(everyday, guarded, seed);
        // Take the newest of the in-memory and stored step; a stored value with a bad MAC is ignored.
        if let Ok(Some(v)) = self.meta_get_signed("totp_last_step") {
            if let Ok(s) = String::from_utf8_lossy(&v).parse::<i64>() {
                self.last_step = self.last_step.max(s);
            }
        }
        let pending = std::mem::take(&mut self.pending_log);
        for (ts, entry) in pending {
            self.append_log(ts, entry)?;
        }
        self.log(LogInput::new("unlock", "vault", "ok"))?;
        Ok(())
    }

    pub fn lock(&mut self) {
        if self.keys.is_some() {
            let _ = self.log(LogInput::new("lock", "vault", "ok"));
        }
        self.keys = None; // Zeroizing drops wipe the key material.
        self.pending_totp = None;
        self.pending_recovery = false;
    }

    /// Checks the master password without changing state (used for step-up).
    pub fn verify_password(&self, password: &str) -> Result<()> {
        self.derive_and_unwrap(password).map(|_| ())
    }

    // ---------- TOTP ----------

    pub fn otp_locked_until(&self) -> Option<i64> {
        (self.otp_lock_until > now_ms()).then_some(self.otp_lock_until)
    }

    /// Verifies a TOTP code and consumes its time step. Global failure limit applies.
    pub fn check_otp(&mut self, code: &str) -> Result<()> {
        let now = now_ms();
        if self.otp_lock_until > now {
            return Err(Error::CodeLockout);
        }
        let seed = self.keys()?.totp_seed.clone();
        match totp::verify(&seed, code, now / 1000, self.last_step) {
            Some(step) => {
                self.last_step = step;
                self.persist_last_step()?;
                Ok(())
            }
            None => {
                self.code_failed(now);
                Err(Error::BadCode)
            }
        }
    }

    /// Counts a wrong OTP or PIN. Too many within the window closes code entry for a while (exponential).
    fn code_failed(&mut self, now: i64) {
        self.otp_failures.push_back(now);
        while self.otp_failures.front().is_some_and(|t| now - t > OTP_FAIL_WINDOW_MS) {
            self.otp_failures.pop_front();
        }
        if self.otp_failures.len() >= OTP_FAIL_LIMIT {
            self.otp_lockouts += 1;
            let mult = 1i64 << self.otp_lockouts.min(4).saturating_sub(1);
            self.otp_lock_until = now + OTP_FAIL_WINDOW_MS * mult;
            self.otp_failures.clear();
            let _ = self.log(LogInput::new("otp_lockout", "vault", "locked").detail("too many wrong codes"));
        }
    }

    // ---------- PIN ----------

    pub fn has_pin(&self) -> bool {
        matches!(self.meta_get("pin"), Ok(Some(_)))
    }

    /// Sets or replaces the PIN (4–6 digits). Stored as an Argon2id hash under a policy MAC.
    pub fn set_pin(&mut self, pin: &str) -> Result<()> {
        if !(4..=6).contains(&pin.len()) || !pin.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::Invalid("PIN must be 4 to 6 digits".into()));
        }
        self.keys()?;
        let salt = crypto::random_bytes::<16>();
        let hash = crypto::derive_kek(pin, &salt, PIN_KDF)?;
        let rec = PinRecord { salt: hex(&salt), hash: hex(hash.as_ref()) };
        self.meta_set_signed("pin", &serde_json::to_vec(&rec).expect("serialize"))?;
        self.log(LogInput::new("set_pin", "vault", "ok").detail("PIN set"))
    }

    /// Verifies the PIN. Shares the failure limit with OTP codes.
    pub fn check_pin(&mut self, pin: &str) -> Result<()> {
        let now = now_ms();
        if self.otp_lock_until > now {
            return Err(Error::CodeLockout);
        }
        let rec: PinRecord = match self.meta_get_signed("pin")? {
            Some(v) => serde_json::from_slice(&v).map_err(|_| Error::Integrity("PIN is damaged".into()))?,
            None => return Err(Error::Invalid("PIN is not set".into())),
        };
        let salt = HEXLOWER.decode(rec.salt.as_bytes()).map_err(|_| Error::Integrity("PIN is damaged".into()))?;
        let hash = crypto::derive_kek(pin, &salt, PIN_KDF)?;
        if crypto::ct_eq(hex(hash.as_ref()).as_bytes(), rec.hash.as_bytes()) {
            Ok(())
        } else {
            self.code_failed(now);
            Err(Error::BadCode)
        }
    }

    fn persist_last_step(&self) -> Result<()> {
        self.meta_set_signed("totp_last_step", self.last_step.to_string().as_bytes())
    }

    pub fn antiphish_word(&self) -> Result<String> {
        let k = self.keys()?;
        let blob = self.meta_get("antiphish")?.ok_or(Error::NotInitialized)?;
        let pt = crypto::open(&k.guarded, &blob[..crypto::NONCE_LEN], &blob[crypto::NONCE_LEN..], &self.aad("antiphish"))?;
        Ok(String::from_utf8_lossy(&pt).to_string())
    }

    // ---------- settings ----------

    pub fn settings(&self) -> Result<Settings> {
        match self.meta_get_signed("settings")? {
            Some(v) => serde_json::from_slice(&v).map_err(|_| Error::Integrity("settings are damaged".into())),
            None => Ok(Settings::default()),
        }
    }

    pub fn set_settings(&mut self, s: &Settings) -> Result<()> {
        if s.autolock_minutes == 0 || s.autolock_minutes > 24 * 60 {
            return Err(Error::Invalid("auto-lock: 1 minute to 24 hours".into()));
        }
        if s.max_ttl_minutes == 0 || s.default_ttl_minutes == 0 || s.default_ttl_minutes > s.max_ttl_minutes {
            return Err(Error::Invalid("the default duration must not exceed the maximum".into()));
        }
        if s.login_mode == LoginMode::Pin && !self.has_pin() {
            return Err(Error::Invalid("set a PIN first".into()));
        }
        if parse_noise_colors(&s.noise_colors).is_none() {
            return Err(Error::Invalid("noise colours: 2 to 6 colours as #rrggbb".into()));
        }
        self.meta_set_signed("settings", &serde_json::to_vec(s).expect("serialize"))?;
        // Readable while locked: startup has to know whether to restore the keys.
        self.meta_set("full_lock", if s.full_lock { b"1" } else { b"0" })?;
        self.log(LogInput::new("settings", "vault", "ok").detail(format!(
            "auto-lock {} min, duration {}/{} min",
            s.autolock_minutes, s.default_ttl_minutes, s.max_ttl_minutes
        )))
    }

    // ---------- secrets ----------

    fn policy_mac(&self, id: &str, version: i64, p: &Policy) -> Result<Vec<u8>> {
        Ok(crypto::hmac(&self.keys()?.policy, p.canonical(id, version).as_bytes()))
    }

    fn value_aad(&self, id: &str, version: i64, p: &Policy) -> Vec<u8> {
        format!(
            "kh1|value|{}|{}|{}|{}|{}",
            hex(&self.vault_id),
            id,
            version,
            p.tier.partition().as_str(),
            hex(&crypto::sha256(p.canonical(id, version).as_bytes()))
        )
        .into_bytes()
    }

    fn partition_key(&self, p: &Policy) -> Result<&[u8; 32]> {
        let k = self.keys()?;
        Ok(match p.tier.partition() {
            Partition::Everyday => &k.everyday,
            Partition::Guarded => &k.guarded,
        })
    }

    fn validate_policy(p: &Policy) -> Result<()> {
        // Agents ask for keys by name, so theirs stay plain Latin; sealed keys never reach an
        // agent and may be named in any language.
        let sealed = p.tier == Tier::Sealed;
        for (what, v) in [("name", &p.name), ("group", &p.group)] {
            if sealed {
                if !valid_sealed_name(v) {
                    return Err(Error::Invalid(format!("{what} \"{v}\": any lowercase letters, digits, space and . _ / - (up to 64 characters)")));
                }
            } else if !valid_key_name(v) {
                return Err(Error::Invalid(if valid_sealed_name(v) {
                    format!(
                        "{what} \"{v}\": non-Latin letters and spaces are only allowed for sealed keys — agents find keys by their Latin name"
                    )
                } else {
                    format!("{what} \"{v}\": only lowercase Latin letters, digits and . _ / - (up to 64 characters)")
                }));
            }
        }
        if !valid_env_name(&p.env_name) {
            return Err(Error::Invalid(format!("variable name \"{}\": only A-Z, 0-9 and _", p.env_name)));
        }
        if !p.mode.available() {
            return Err(Error::Invalid(format!("mode \"{}\" is coming in a later version", p.mode.as_str())));
        }
        Ok(())
    }

    pub fn add_secret(&mut self, s: NewSecret) -> Result<SecretMeta> {
        self.keys()?;
        if s.value.is_empty() {
            return Err(Error::Invalid("the value is empty".into()));
        }
        if s.value.len() > 64 * 1024 {
            return Err(Error::Invalid("the value is longer than 64 KB".into()));
        }
        let p = Policy {
            name: s.name.trim().to_string(),
            group: if s.group.trim().is_empty() { "default".into() } else { s.group.trim().to_string() },
            tier: s.tier,
            mode: s.mode,
            env_name: s
                .env_name
                .filter(|e| !e.trim().is_empty())
                .map(|e| e.trim().to_string())
                .unwrap_or_else(|| default_env_name(s.name.trim())),
            status: KeyStatus::Active,
        };
        Self::validate_policy(&p)?;
        if self.find_id(&p.name)?.is_some() {
            return Err(Error::Invalid(format!("key \"{}\" already exists", p.name)));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let version = 1;
        let (nonce, ct) = crypto::seal(self.partition_key(&p)?, s.value.as_bytes(), &self.value_aad(&id, version, &p))?;
        let mac = self.policy_mac(&id, version, &p)?;
        let now = now_ms();
        let tags = serde_json::to_string(&clean_tags(&s.tags)).expect("serialize");
        self.conn.execute(
            "INSERT INTO secrets(id, name, description, grp, tags, tier, mode, env_name, status, version, nonce, ciphertext, policy_mac, created_at, updated_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', ?9, ?10, ?11, ?12, ?13, ?13)",
            params![id, p.name, s.description.trim(), p.group, tags, p.tier.as_str(), p.mode.as_str(), p.env_name, version, nonce, ct, mac, now],
        )?;
        self.log(LogInput::new("add_key", &p.name, "ok").detail(format!("{} · {}", p.tier.as_str(), p.mode.as_str())))?;
        self.get_meta(&id)
    }

    pub fn find_id(&self, name: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT id FROM secrets WHERE name = ?1", params![name], |r| r.get(0))
            .optional()?)
    }

    fn row_policy(r: &rusqlite::Row) -> rusqlite::Result<(Policy, i64)> {
        let tier: String = r.get("tier")?;
        let mode: String = r.get("mode")?;
        let status: String = r.get("status")?;
        Ok((
            Policy {
                name: r.get("name")?,
                group: r.get("grp")?,
                tier: Tier::parse(&tier).unwrap_or(Tier::Sealed),
                mode: Mode::parse(&mode).unwrap_or(Mode::Proxy),
                env_name: r.get("env_name")?,
                status: if status == "active" { KeyStatus::Active } else { KeyStatus::Disabled },
            },
            r.get("version")?,
        ))
    }

    pub fn list_secrets(&self) -> Result<Vec<SecretMeta>> {
        let k = self.keys()?;
        let leaks = self.open_leaks()?;
        let mut stmt = self.conn.prepare("SELECT * FROM secrets ORDER BY name")?;
        let rows = stmt.query_map([], |r| {
            let (p, version) = Self::row_policy(r)?;
            let id: String = r.get("id")?;
            let mac: Vec<u8> = r.get("policy_mac")?;
            let tags: String = r.get("tags")?;
            Ok((id, p, version, mac, tags, r.get::<_, String>("description")?, r.get::<_, i64>("created_at")?,
                r.get::<_, i64>("updated_at")?, r.get::<_, Option<i64>>("last_used_at")?, r.get::<_, i64>("use_count")?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, p, version, mac, tags, description, created_at, updated_at, last_used_at, use_count) = row?;
            let ok = crypto::hmac_verify(&k.policy, p.canonical(&id, version).as_bytes(), &mac);
            let mine: Vec<&(String, LeakInfo)> = leaks.iter().filter(|(sid, _)| *sid == id).collect();
            out.push(SecretMeta {
                leak: mine.iter().find(|(_, l)| l.kind != LeakKind::Exposed).map(|(_, l)| l.clone()),
                exposed: mine.iter().any(|(_, l)| l.kind == LeakKind::Exposed),
                id,
                name: p.name,
                description,
                group: p.group,
                tags: serde_json::from_str(&tags).unwrap_or_default(),
                tier: p.tier,
                mode: p.mode,
                env_name: p.env_name,
                status: p.status,
                created_at,
                updated_at,
                last_used_at,
                use_count,
                quarantined: !ok,
            });
        }
        Ok(out)
    }

    pub fn get_meta(&self, id: &str) -> Result<SecretMeta> {
        self.list_secrets()?
            .into_iter()
            .find(|m| m.id == id)
            .ok_or_else(|| Error::NotFound(id.to_string()))
    }

    pub fn get_meta_by_name(&self, name: &str) -> Result<SecretMeta> {
        let id = self.find_id(name)?.ok_or_else(|| Error::NotFound(name.to_string()))?;
        self.get_meta(&id)
    }

    /// Loads policy + verifies its MAC. Fails closed.
    fn load_policy(&self, id: &str) -> Result<(Policy, i64, Vec<u8>, Vec<u8>)> {
        let k = self.keys()?;
        let (p, version, nonce, ct, mac) = self
            .conn
            .query_row("SELECT * FROM secrets WHERE id = ?1", params![id], |r| {
                let (p, v) = Self::row_policy(r)?;
                Ok((p, v, r.get::<_, Vec<u8>>("nonce")?, r.get::<_, Vec<u8>>("ciphertext")?, r.get::<_, Vec<u8>>("policy_mac")?))
            })
            .optional()?
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        if !crypto::hmac_verify(&k.policy, p.canonical(id, version).as_bytes(), &mac) {
            return Err(Error::Integrity(format!("the policy of key \"{}\" was changed outside MCP Keyholder", p.name)));
        }
        Ok((p, version, nonce, ct))
    }

    /// Decrypts a value. Callers enforce grants; this only enforces integrity.
    pub fn read_value(&self, id: &str) -> Result<Zeroizing<String>> {
        let (p, version, nonce, ct) = self.load_policy(id)?;
        let pt = crypto::open(self.partition_key(&p)?, &nonce, &ct, &self.value_aad(id, version, &p))
            .map_err(|_| Error::Integrity(format!("the ciphertext of key \"{}\" fails verification", p.name)))?;
        Ok(Zeroizing::new(String::from_utf8_lossy(&pt).to_string()))
    }

    pub fn policy_of(&self, id: &str) -> Result<Policy> {
        Ok(self.load_policy(id)?.0)
    }

    /// True if going from `old` to `new` makes the key easier to obtain or misidentify.
    pub fn is_weakening(old: &Policy, new: &Policy) -> bool {
        new.tier < old.tier
            || (new.mode.exposes_value() && !old.mode.exposes_value())
            || (old.tier >= Tier::Pin && new.name != old.name)
    }

    /// Applies a metadata patch. Re-encrypts when the policy changes. Returns (meta, was_weakening).
    pub fn update_meta(&mut self, id: &str, patch: &MetaPatch, allow_weakening: bool) -> Result<SecretMeta> {
        let (old, version, nonce, ct) = self.load_policy(id)?;
        let mut new = old.clone();
        if let Some(n) = &patch.name {
            new.name = n.trim().to_string();
        }
        if let Some(g) = &patch.group {
            new.group = g.trim().to_string();
        }
        if let Some(t) = patch.tier {
            new.tier = t;
        }
        if let Some(m) = patch.mode {
            new.mode = m;
        }
        if let Some(e) = &patch.env_name {
            new.env_name = e.trim().to_string();
        }
        if let Some(s) = patch.status {
            new.status = s;
        }
        Self::validate_policy(&new)?;
        if Self::is_weakening(&old, &new) && !allow_weakening {
            return Err(Error::Invalid("stepup_required".into()));
        }
        if new.name != old.name && self.find_id(&new.name)?.is_some() {
            return Err(Error::Invalid(format!("key \"{}\" already exists", new.name)));
        }
        let now = now_ms();
        if new != old {
            let pt = crypto::open(self.partition_key(&old)?, &nonce, &ct, &self.value_aad(id, version, &old))
                .map_err(|_| Error::Integrity(format!("the ciphertext of key \"{}\" fails verification", old.name)))?;
            let nv = version + 1;
            let (n2, c2) = crypto::seal(self.partition_key(&new)?, &pt, &self.value_aad(id, nv, &new))?;
            let mac = self.policy_mac(id, nv, &new)?;
            self.conn.execute(
                "UPDATE secrets SET name=?2, grp=?3, tier=?4, mode=?5, env_name=?6, status=?7, version=?8, nonce=?9, ciphertext=?10, policy_mac=?11, updated_at=?12 WHERE id=?1",
                params![id, new.name, new.group, new.tier.as_str(), new.mode.as_str(), new.env_name,
                        if new.status == KeyStatus::Active { "active" } else { "disabled" }, nv, n2, c2, mac, now],
            )?;
            let mut changes = Vec::new();
            if old.tier != new.tier {
                changes.push(format!("level {} → {}", old.tier.as_str(), new.tier.as_str()));
            }
            if old.mode != new.mode {
                changes.push(format!("mode {} → {}", old.mode.as_str(), new.mode.as_str()));
            }
            if old.name != new.name {
                changes.push(format!("name {} → {}", old.name, new.name));
            }
            if old.status != new.status {
                changes.push(if new.status == KeyStatus::Active { "enabled".into() } else { "disabled".into() });
            }
            if old.group != new.group {
                changes.push(format!("group {} → {}", old.group, new.group));
            }
            if old.env_name != new.env_name {
                changes.push(format!("variable {} → {}", old.env_name, new.env_name));
            }
            self.log(LogInput::new("edit_key", &new.name, "ok").detail(changes.join(", ")))?;
        }
        if let Some(d) = &patch.description {
            self.conn.execute("UPDATE secrets SET description=?2, updated_at=?3 WHERE id=?1", params![id, d.trim(), now])?;
        }
        if let Some(t) = &patch.tags {
            let tags = serde_json::to_string(&clean_tags(t)).expect("serialize");
            self.conn.execute("UPDATE secrets SET tags=?2, updated_at=?3 WHERE id=?1", params![id, tags, now])?;
        }
        self.get_meta(id)
    }

    /// Replaces the value (rotation). Clears leak/exposure marks.
    pub fn replace_value(&mut self, id: &str, value: &str) -> Result<SecretMeta> {
        if value.is_empty() || value.len() > 64 * 1024 {
            return Err(Error::Invalid("the value is empty or longer than 64 KB".into()));
        }
        let (p, version, _, _) = self.load_policy(id)?;
        let nv = version + 1;
        let (n, c) = crypto::seal(self.partition_key(&p)?, value.as_bytes(), &self.value_aad(id, nv, &p))?;
        let mac = self.policy_mac(id, nv, &p)?;
        self.conn.execute(
            "UPDATE secrets SET version=?2, nonce=?3, ciphertext=?4, policy_mac=?5, updated_at=?6 WHERE id=?1",
            params![id, nv, n, c, mac, now_ms()],
        )?;
        self.conn.execute("UPDATE leaks SET resolved_at=?2 WHERE secret_id=?1 AND resolved_at IS NULL", params![id, now_ms()])?;
        self.log(LogInput::new("rotate_key", &p.name, "ok").detail("value replaced, leak marks cleared"))?;
        self.get_meta(id)
    }

    pub fn delete_secret(&mut self, id: &str) -> Result<()> {
        let name: String = self
            .conn
            .query_row("SELECT name FROM secrets WHERE id=?1", params![id], |r| r.get(0))
            .optional()?
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        self.keys()?;
        self.conn.execute("DELETE FROM secrets WHERE id=?1", params![id])?;
        self.conn.execute("DELETE FROM leaks WHERE secret_id=?1", params![id])?;
        self.log(LogInput::new("delete_key", &name, "ok"))
    }

    pub fn touch_use(&self, id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE secrets SET last_used_at=?2, use_count=use_count+1 WHERE id=?1",
            params![id, now_ms()],
        )?;
        Ok(())
    }

    pub fn groups(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT DISTINCT grp FROM secrets ORDER BY grp")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    // ---------- leaks ----------

    fn open_leaks(&self) -> Result<Vec<(String, LeakInfo)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, secret_id, kind, client, comment, at FROM leaks WHERE resolved_at IS NULL ORDER BY at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            let kind: String = r.get(2)?;
            Ok((
                r.get::<_, String>(1)?,
                LeakInfo {
                    id: r.get(0)?,
                    kind: LeakKind::parse(&kind).unwrap_or(LeakKind::Reported),
                    client: r.get(3)?,
                    comment: r.get(4)?,
                    at: r.get(5)?,
                },
            ))
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn add_leak(&mut self, id: &str, kind: LeakKind, client: &str, session: &str, comment: &str) -> Result<()> {
        let p = self.policy_of(id)?;
        let comment = sanitize_untrusted(comment, 500);
        if kind == LeakKind::Exposed {
            let already: bool = self.conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM leaks WHERE secret_id=?1 AND kind='exposed' AND resolved_at IS NULL)",
                params![id],
                |r| r.get(0),
            )?;
            if already {
                return Ok(());
            }
        }
        self.conn.execute(
            "INSERT INTO leaks(secret_id, kind, client, session, comment, at) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, kind.as_str(), client, session, comment, now_ms()],
        )?;
        let action = match kind {
            LeakKind::Reported => "report_leak",
            LeakKind::Found => "leak_found",
            LeakKind::Exposed => "exposed",
        };
        self.log(LogInput::new(action, &p.name, if kind == LeakKind::Exposed { "exposed" } else { "leaked" })
            .by(client, session)
            .detail(comment))
    }

    /// Clears leak marks without rotating (requires step-up at the caller).
    pub fn dismiss_leaks(&mut self, id: &str) -> Result<()> {
        let p = self.policy_of(id)?;
        self.conn.execute("UPDATE leaks SET resolved_at=?2 WHERE secret_id=?1 AND resolved_at IS NULL", params![id, now_ms()])?;
        self.log(LogInput::new("dismiss_leak", &p.name, "ok").detail("leak mark cleared without replacing the value"))
    }

    /// Finds full stored values (and their common encodings) inside `text`.
    /// Returns (id, name) of every key found. Short / low-entropy values are excluded.
    pub fn scan_text(&self, text: &str) -> Result<Vec<(String, String)>> {
        let metas = self.list_secrets()?;
        let mut values = Vec::new();
        for m in metas.iter().filter(|m| !m.quarantined) {
            if let Ok(v) = self.read_value(&m.id) {
                values.push((m.id.clone(), m.name.clone(), v));
            }
        }
        let refs: Vec<(&str, &str, &str)> = values.iter().map(|(i, n, v)| (i.as_str(), n.as_str(), v.as_str())).collect();
        Ok(scan::find(&refs, text).into_iter().map(|(i, n)| (i.to_string(), n.to_string())).collect())
    }

    // ---------- clients ----------

    fn client_mac(&self, id: &str, name: &str, token_hash: &[u8], revoked: bool, blocked: bool) -> Result<Vec<u8>> {
        let s = format!("kh1|client|{}|{}|{}|{}|{}", id, name, hex(token_hash), revoked as u8, blocked as u8);
        Ok(crypto::hmac(&self.keys()?.policy, s.as_bytes()))
    }

    pub fn create_client(&mut self, name: &str) -> Result<(Client, String)> {
        let name = name.trim();
        if !valid_key_name(name) {
            return Err(Error::Invalid("client name: only lowercase Latin letters, digits and . _ / -".into()));
        }
        let token = format!("kh_{}", BASE32_NOPAD.encode(&crypto::random_bytes::<32>()).to_lowercase());
        let th = crypto::sha256(token.as_bytes());
        let id = uuid::Uuid::new_v4().to_string();
        let mac = self.client_mac(&id, name, &th, false, false)?;
        self.conn
            .execute(
                "INSERT INTO clients(id, name, token_hash, created_at, mac) VALUES(?1, ?2, ?3, ?4, ?5)",
                params![id, name, th, now_ms(), mac],
            )
            .map_err(|_| Error::Invalid(format!("client \"{name}\" already exists")))?;
        self.log(LogInput::new("add_client", name, "ok"))?;
        let c = self.list_clients()?.into_iter().find(|c| c.id == id).ok_or_else(|| Error::NotFound(id))?;
        Ok((c, token))
    }

    pub fn list_clients(&self) -> Result<Vec<Client>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, token_hash, created_at, last_seen_at, revoked, blocked, mac FROM clients ORDER BY name",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, Option<i64>>(4)?,
                r.get::<_, i64>(5)? != 0,
                r.get::<_, i64>(6)? != 0,
                r.get::<_, Vec<u8>>(7)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, name, th, created_at, last_seen_at, revoked, blocked, mac) = row?;
            let ok = crypto::ct_eq(&self.client_mac(&id, &name, &th, revoked, blocked)?, &mac);
            out.push(Client { id, name, created_at, last_seen_at, revoked: revoked || !ok, blocked: blocked || !ok });
        }
        Ok(out)
    }

    /// Authenticates a client token. Tampered rows are treated as revoked.
    pub fn auth_client(&self, token: &str) -> Result<Option<Client>> {
        let th = crypto::sha256(token.as_bytes());
        let id: Option<String> = self
            .conn
            .query_row("SELECT id FROM clients WHERE token_hash=?1", params![th], |r| r.get(0))
            .optional()?;
        let Some(id) = id else { return Ok(None) };
        let c = self.list_clients()?.into_iter().find(|c| c.id == id);
        Ok(c.filter(|c| !c.revoked))
    }

    pub fn touch_client(&self, id: &str) -> Result<()> {
        self.conn.execute("UPDATE clients SET last_seen_at=?2 WHERE id=?1", params![id, now_ms()])?;
        Ok(())
    }

    fn set_client_flags(&mut self, id: &str, revoked: Option<bool>, blocked: Option<bool>) -> Result<Client> {
        let (name, th, r0, b0): (String, Vec<u8>, bool, bool) = self
            .conn
            .query_row("SELECT name, token_hash, revoked, blocked FROM clients WHERE id=?1", params![id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? != 0, r.get::<_, i64>(3)? != 0))
            })
            .optional()?
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        let r = revoked.unwrap_or(r0);
        let b = blocked.unwrap_or(b0);
        let mac = self.client_mac(id, &name, &th, r, b)?;
        self.conn.execute(
            "UPDATE clients SET revoked=?2, blocked=?3, mac=?4 WHERE id=?1",
            params![id, r as i64, b as i64, mac],
        )?;
        self.list_clients()?.into_iter().find(|c| c.id == id).ok_or_else(|| Error::NotFound(id.to_string()))
    }

    pub fn revoke_client(&mut self, id: &str) -> Result<Client> {
        let c = self.set_client_flags(id, Some(true), None)?;
        self.log(LogInput::new("revoke_client", &c.name, "ok"))?;
        Ok(c)
    }

    pub fn set_client_blocked(&mut self, id: &str, blocked: bool, why: &str) -> Result<Client> {
        let c = self.set_client_flags(id, None, Some(blocked))?;
        self.log(LogInput::new(if blocked { "block_client" } else { "unblock_client" }, &c.name, "ok").detail(why))?;
        Ok(c)
    }

    // ---------- audit log ----------

    /// Appends to the audit chain. While locked, entries are buffered and chained on unlock.
    pub fn log(&mut self, e: LogInput) -> Result<()> {
        let ts = now_ms();
        if self.keys.is_none() {
            if self.pending_log.len() < 10_000 {
                self.pending_log.push((ts, e));
            }
            return Ok(());
        }
        self.append_log(ts, e)
    }

    fn entry_canonical(seq: i64, ts: i64, e: &LogInput) -> Vec<u8> {
        serde_json::to_vec(&(seq, ts, &e.client, &e.session, &e.action, &e.target, &e.outcome, &e.detail))
            .expect("serialize")
    }

    fn append_log(&mut self, ts: i64, mut e: LogInput) -> Result<()> {
        e.detail = sanitize_untrusted(&e.detail, 1000);
        e.client = sanitize_untrusted(&e.client, 100);
        e.target = sanitize_untrusted(&e.target, 200);
        let k = self.keys()?;
        let (prev_seq, prev_hash): (i64, Vec<u8>) = self
            .conn
            .query_row("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?
            .unwrap_or((0, vec![0u8; 32]));
        let seq = prev_seq + 1;
        let hash = crypto::sha256(&[&prev_hash[..], &Self::entry_canonical(seq, ts, &e)].concat());
        let mac = crypto::hmac(&k.log, &hash);
        self.conn.execute(
            "INSERT INTO audit(seq, ts, client, session, action, target, outcome, detail, prev_hash, hash, mac)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![seq, ts, e.client, e.session, e.action, e.target, e.outcome, e.detail, prev_hash, hash, mac],
        )?;
        let head = LogHead { count: seq, hash: hex(&hash) };
        self.meta_set_signed("log_head", &serde_json::to_vec(&head).expect("serialize"))
    }

    pub fn list_log(&self, limit: i64, before_seq: Option<i64>) -> Result<Vec<LogEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, ts, client, session, action, target, outcome, detail FROM audit
             WHERE (?1 IS NULL OR seq < ?1) ORDER BY seq DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![before_seq, limit], |r| {
            Ok(LogEntry {
                seq: r.get(0)?,
                ts: r.get(1)?,
                client: r.get(2)?,
                session: r.get(3)?,
                action: r.get(4)?,
                target: r.get(5)?,
                outcome: r.get(6)?,
                detail: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn verify_chain(&self) -> Result<ChainStatus> {
        let k = self.keys()?;
        let mut stmt = self.conn.prepare(
            "SELECT seq, ts, client, session, action, target, outcome, detail, prev_hash, hash, mac FROM audit ORDER BY seq",
        )?;
        let mut rows = stmt.query([])?;
        let mut prev = vec![0u8; 32];
        let mut expected_seq = 1;
        let mut count = 0;
        let bad = |seq: i64, msg: &str, count: i64| ChainStatus {
            ok: false,
            entries: count,
            first_bad_seq: Some(seq),
            message: msg.to_string(),
        };
        while let Some(r) = rows.next()? {
            let seq: i64 = r.get(0)?;
            let e = LogInput {
                client: r.get(2)?,
                session: r.get(3)?,
                action: r.get(4)?,
                target: r.get(5)?,
                outcome: r.get(6)?,
                detail: r.get(7)?,
            };
            let ts: i64 = r.get(1)?;
            let prev_hash: Vec<u8> = r.get(8)?;
            let hash: Vec<u8> = r.get(9)?;
            let mac: Vec<u8> = r.get(10)?;
            if seq != expected_seq {
                return Ok(bad(expected_seq, "entries are missing", count));
            }
            if !crypto::ct_eq(&prev_hash, &prev) {
                return Ok(bad(seq, "the chain is broken", count));
            }
            let h = crypto::sha256(&[&prev[..], &Self::entry_canonical(seq, ts, &e)].concat());
            if !crypto::ct_eq(&h, &hash) || !crypto::hmac_verify(&k.log, &hash, &mac) {
                return Ok(bad(seq, "an entry was changed", count));
            }
            prev = hash;
            expected_seq += 1;
            count += 1;
        }
        match self.meta_get_signed("log_head") {
            Ok(Some(v)) => {
                let head: LogHead = serde_json::from_slice(&v).map_err(|_| Error::Integrity("log head is damaged".into()))?;
                if head.count != count || head.hash != hex(&prev) {
                    return Ok(bad(count + 1, "the latest entries were removed", count));
                }
            }
            Ok(None) if count == 0 => {}
            Ok(None) => return Ok(bad(1, "the log head signature is missing", count)),
            Err(_) => return Ok(bad(count, "the log head signature does not match", count)),
        }
        Ok(ChainStatus { ok: true, entries: count, first_bad_seq: None, message: "the chain is intact".into() })
    }

    // ---------- permission presets ----------

    pub fn presets(&self) -> Result<Vec<Preset>> {
        match self.meta_get_signed("presets")? {
            Some(v) => serde_json::from_slice(&v).map_err(|_| Error::Integrity("presets are damaged".into())),
            None => Ok(Vec::new()),
        }
    }

    fn store_presets(&self, list: &[Preset]) -> Result<()> {
        self.meta_set_signed("presets", &serde_json::to_vec(list).expect("serialize"))
    }

    pub fn save_preset(&mut self, name: &str, keys: &[String], ttl_minutes: u32) -> Result<Vec<Preset>> {
        self.keys()?;
        let name = sanitize_untrusted(name, 32);
        if name.is_empty() {
            return Err(Error::Invalid("preset name: 1 to 32 characters".into()));
        }
        if keys.is_empty() || keys.len() > 32 {
            return Err(Error::Invalid("a preset holds 1 to 32 keys".into()));
        }
        let metas = self.list_secrets()?;
        let known: Vec<String> = keys.iter().filter(|k| metas.iter().any(|m| &m.name == *k)).cloned().collect();
        if known.is_empty() {
            return Err(Error::Invalid("none of these keys are in the vault".into()));
        }
        let preset = Preset { name: name.clone(), keys: known, ttl_minutes: ttl_minutes.clamp(1, 24 * 60), created_at: now_ms() };
        let mut list = self.presets()?;
        match list.iter_mut().find(|p| p.name == name) {
            Some(p) => *p = preset,
            None => list.push(preset),
        }
        self.store_presets(&list)?;
        self.log(LogInput::new("save_preset", &name, "ok").detail(format!("{} keys", list.iter().find(|p| p.name == name).map(|p| p.keys.len()).unwrap_or(0))))?;
        Ok(list)
    }

    pub fn delete_preset(&mut self, name: &str) -> Result<Vec<Preset>> {
        self.keys()?;
        let mut list = self.presets()?;
        let before = list.len();
        list.retain(|p| p.name != name);
        if list.len() == before {
            return Err(Error::NotFound(format!("preset \"{name}\"")));
        }
        self.store_presets(&list)?;
        self.log(LogInput::new("delete_preset", name, "ok"))?;
        Ok(list)
    }

    // ---------- master password / anti-phishing word ----------

    /// Re-wraps the two data keys under a new master password. Values are not touched.
    pub fn change_password(&mut self, new_password: &str) -> Result<()> {
        if new_password.chars().count() < 10 {
            return Err(Error::Invalid("the master password must be at least 10 characters long".into()));
        }
        {
            let k = self.keys()?;
            let salt = crypto::random_bytes::<16>();
            let kdf = KdfParams::default();
            let kek = crypto::derive_kek(new_password, &salt, kdf)?;
            let we = crypto::wrap_key(&kek, &k.everyday, &self.aad("wrap|everyday"))?;
            let wg = crypto::wrap_key(&kek, &k.guarded, &self.aad("wrap|guarded"))?;
            // All four values or none: a half-written set would open with neither password.
            self.conn.execute_batch("BEGIN IMMEDIATE")?;
            let r = (|| -> Result<()> {
                self.meta_set("kdf", &serde_json::to_vec(&kdf).expect("serialize"))?;
                self.meta_set("salt", &salt)?;
                self.meta_set("wrap_everyday", &we)?;
                self.meta_set("wrap_guarded", &wg)?;
                Ok(())
            })();
            match r {
                Ok(()) => self.conn.execute_batch("COMMIT")?,
                Err(e) => {
                    let _ = self.conn.execute_batch("ROLLBACK");
                    return Err(e);
                }
            }
        }
        self.log(LogInput::new("change_password", "vault", "ok").detail("master password changed"))?;
        Ok(())
    }

    pub fn set_antiphish(&mut self, word: &str) -> Result<()> {
        let w = word.trim();
        if w.chars().count() < 3 || w.chars().count() > 8 {
            return Err(Error::Invalid("anti-phishing word: 3 to 8 characters".into()));
        }
        let blob = {
            let k = self.keys()?;
            let (n, ct) = crypto::seal(&k.guarded, w.as_bytes(), &self.aad("antiphish"))?;
            [n, ct].concat()
        };
        self.meta_set("antiphish", &blob)?;
        self.log(LogInput::new("change_antiphish", "vault", "ok").detail("anti-phishing word changed"))?;
        Ok(())
    }

    // ---------- authenticator reissue / recovery codes ----------

    /// New seed, kept in memory until `finish_totp_reissue` proves the human enrolled it.
    pub fn begin_totp_reissue(&mut self) -> Result<String> {
        self.keys()?;
        if self.pending_totp.is_some() {
            return Err(Error::Invalid("authenticator reissue is already in progress".into()));
        }
        let seed = totp::new_seed().to_vec();
        let uri = totp::otpauth_uri(&seed, "vault");
        self.pending_totp = Some(Zeroizing::new(seed));
        Ok(uri)
    }

    /// Commits the new seed after a code from it checks out; returns the fresh recovery codes.
    pub fn finish_totp_reissue(&mut self, code: &str) -> Result<Vec<String>> {
        let seed = self.pending_totp.clone().ok_or_else(|| Error::Invalid("authenticator reissue has not been started".into()))?;
        let step = totp::verify(&seed, code, now_ms() / 1000, 0).ok_or(Error::BadCode)?;
        {
            let k = self.keys()?;
            let (n, ct) = crypto::seal(&k.guarded, &seed, &self.aad("totp"))?;
            self.meta_set("totp", &[n, ct].concat())?;
        }
        if let Some(u) = self.keys.as_mut() {
            u.totp_seed = seed;
        }
        self.last_step = step;
        self.persist_last_step()?;
        self.pending_totp = None;
        self.pending_recovery = false;
        // New codes replace all old ones, including the one used to start a recovery.
        let codes = self.regenerate_recovery()?;
        self.log(LogInput::new("reissue_totp", "vault", "ok").detail("authenticator reissued"))?;
        Ok(codes)
    }

    fn regenerate_recovery(&mut self) -> Result<Vec<String>> {
        let codes: Vec<String> = (0..10)
            .map(|_| {
                let raw = BASE32_NOPAD.encode(&crypto::random_bytes::<8>());
                format!("{}-{}-{}", &raw[0..4], &raw[4..8], &raw[8..12])
            })
            .collect();
        let rec: Vec<String> =
            codes.iter().map(|c| hex(&crypto::sha256(&[&self.vault_id[..], c.as_bytes()].concat()))).collect();
        self.meta_set_signed("recovery", &serde_json::to_vec(&rec).expect("serialize"))?;
        Ok(codes)
    }

    fn recovery_hashes(&self) -> Result<Vec<String>> {
        match self.meta_get_signed("recovery")? {
            Some(v) => serde_json::from_slice(&v).map_err(|_| Error::Integrity("recovery codes are damaged".into())),
            None => Ok(Vec::new()),
        }
    }

    /// Consumes one recovery code (lost phone). The code stops working immediately.
    pub fn use_recovery_code(&mut self, code: &str) -> Result<()> {
        self.keys()?;
        let rec = self.recovery_hashes()?;
        if rec.is_empty() {
            return Err(Error::Invalid("recovery codes are not set".into()));
        }
        let c = code.trim().to_uppercase();
        let hash = hex(&crypto::sha256(&[&self.vault_id[..], c.as_bytes()].concat()));
        let Some(pos) = rec.iter().position(|h| crypto::ct_eq(h.as_bytes(), hash.as_bytes())) else {
            return Err(Error::BadCode);
        };
        let mut rest = rec;
        rest.remove(pos);
        self.meta_set_signed("recovery", &serde_json::to_vec(&rest).expect("serialize"))?;
        self.log(LogInput::new("recovery_code", "vault", "ok").detail(format!("recovery code used, {} left", rest.len())))?;
        Ok(())
    }

    /// Lost authenticator: master password (checked by the caller) + recovery code, then enrol
    /// a new one. The code is not consumed here: finishing the reissue replaces every code.
    pub fn start_recovery_reissue(&mut self, recovery: &str) -> Result<String> {
        self.keys()?;
        let rec = self.recovery_hashes()?;
        let c = recovery.trim().to_uppercase();
        let hash = hex(&crypto::sha256(&[&self.vault_id[..], c.as_bytes()].concat()));
        if !rec.iter().any(|h| crypto::ct_eq(h.as_bytes(), hash.as_bytes())) {
            self.code_failed(now_ms());
            return Err(Error::BadCode);
        }
        self.pending_totp = None;
        let uri = self.begin_totp_reissue()?;
        self.pending_recovery = true;
        self.log(LogInput::new("recovery_code", "vault", "ok").detail("authenticator recovery started"))?;
        Ok(uri)
    }

    /// True while a reissue started from a recovery code waits for its first code.
    pub fn reissue_via_recovery(&self) -> bool {
        self.pending_totp.is_some() && self.pending_recovery
    }

    /// Abandons a started reissue (the current authenticator keeps working).
    pub fn cancel_totp_reissue(&mut self) {
        self.pending_totp = None;
        self.pending_recovery = false;
    }

    // ---------- audit anchor ----------

    /// Appends the chain head to a file outside the database, so a rolled-back or
    /// truncated vault can be spotted later.
    pub fn write_anchor(&self) -> Result<()> {
        let path = self.settings()?.anchor_path;
        if path.trim().is_empty() {
            return Err(Error::Invalid("no path set for the log anchor".into()));
        }
        let head: LogHead = match self.meta_get_signed("log_head")? {
            Some(v) => serde_json::from_slice(&v).map_err(|_| Error::Integrity("log head is damaged".into()))?,
            None => LogHead { count: 0, hash: hex(&[0u8; 32]) },
        };
        let line = format!("kh1|{}|{}|{}\n", head.count, head.hash, now_ms());
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path.trim())?;
        f.write_all(line.as_bytes())?;
        Ok(())
    }

    // ---------- service mode: keys without a master password ----------

    /// Readable while locked: auto-lock must also forget the keys.
    pub fn startup_full_lock(&self) -> bool {
        matches!(self.meta_get("full_lock"), Ok(Some(v)) if v == b"1")
    }

    pub fn has_dpapi(&self) -> bool {
        matches!(self.meta_get("wrap_dpapi"), Ok(Some(_)))
    }

    /// Keeps both data keys under DPAPI for this account, so the service starts without a password.
    pub fn enable_dpapi(&mut self) -> Result<()> {
        let blob = {
            let k = self.keys()?;
            let plain = Zeroizing::new([&k.everyday[..], &k.guarded[..]].concat());
            crate::dpapi::protect(&plain)?
        };
        self.meta_set("wrap_dpapi", &blob)?;
        self.log(LogInput::new("dpapi", "vault", "ok").detail("keys available to the service without the master password"))?;
        Ok(())
    }

    pub fn disable_dpapi(&mut self) -> Result<()> {
        self.keys()?;
        for k in ["wrap_dpapi", "wrap_dpapi.mac"] {
            self.conn.execute("DELETE FROM meta WHERE k = ?1", params![k])?;
        }
        self.log(LogInput::new("dpapi", "vault", "ok").detail("service keys are no longer stored"))?;
        Ok(())
    }

    /// Opens the vault without the human. Returns `false` when the vault has no service-wrapped keys.
    pub fn unlock_dpapi(&mut self) -> Result<bool> {
        let Some(blob) = self.meta_get("wrap_dpapi")? else { return Ok(false) };
        let plain = crate::dpapi::unprotect(&blob).map_err(|_| Error::Crypto)?;
        if plain.len() != 64 {
            return Err(Error::Integrity("service keys are damaged".into()));
        }
        let mut everyday = Zeroizing::new([0u8; 32]);
        everyday.copy_from_slice(&plain[..32]);
        let mut guarded = Zeroizing::new([0u8; 32]);
        guarded.copy_from_slice(&plain[32..]);
        // Trust the keys only once they open the TOTP secret.
        let blob = self.meta_get("totp")?.ok_or(Error::NotInitialized)?;
        if blob.len() < crypto::NONCE_LEN {
            return Err(Error::Integrity("TOTP secret is damaged".into()));
        }
        let seed = crypto::open(&guarded, &blob[..crypto::NONCE_LEN], &blob[crypto::NONCE_LEN..], &self.aad("totp"))
            .map_err(|_| Error::Crypto)?;
        self.install_keys(everyday, guarded, seed);
        if let Ok(Some(v)) = self.meta_get_signed("totp_last_step") {
            if let Ok(s) = String::from_utf8_lossy(&v).parse::<i64>() {
                self.last_step = self.last_step.max(s);
            }
        }
        let pending = std::mem::take(&mut self.pending_log);
        for (ts, entry) in pending {
            self.append_log(ts, entry)?;
        }
        self.log(LogInput::new("unlock", "vault", "ok").detail("service restored the keys (DPAPI)"))?;
        Ok(true)
    }
}

fn clean_tags(tags: &[String]) -> Vec<String> {
    let mut t: Vec<String> = tags
        .iter()
        .map(|s| sanitize_untrusted(s, 32).to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    t.sort();
    t.dedup();
    t.truncate(16);
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let mut v = Vault::open(&dir.path().join("vault.db")).unwrap();
        let p = PendingSetup::new("correct horse battery", "owl").unwrap();
        let code = totp::code_at_step(&p.seed, totp::step_at(now_ms() / 1000));
        v.finish_setup(&p, &code).unwrap();
        (dir, v)
    }

    fn new_key(name: &str, tier: Tier) -> NewSecret {
        NewSecret {
            name: name.into(),
            value: format!("value-of-{name}-0123456789abcdef"),
            description: "d".into(),
            group: "g".into(),
            tags: vec![],
            tier,
            mode: Mode::Reveal,
            env_name: None,
        }
    }

    #[test]
    fn roundtrip_lock_unlock() {
        let (_d, mut v) = setup();
        let m = v.add_secret(new_key("a/b", Tier::Otp)).unwrap();
        assert_eq!(&*v.read_value(&m.id).unwrap(), "value-of-a/b-0123456789abcdef");
        v.lock();
        assert!(matches!(v.read_value(&m.id), Err(Error::Locked)));
        assert!(matches!(v.unlock("wrong password!"), Err(Error::BadPassword)));
        v.unlock("correct horse battery").unwrap();
        assert_eq!(&*v.read_value(&m.id).unwrap(), "value-of-a/b-0123456789abcdef");
        assert!(v.verify_chain().unwrap().ok);
    }

    #[test]
    fn tampered_policy_is_quarantined() {
        let (_d, v) = setup();
        let mut v = v;
        let m = v.add_secret(new_key("gh/token", Tier::Otp)).unwrap();
        v.conn.execute("UPDATE secrets SET tier='auto' WHERE id=?1", params![m.id]).unwrap();
        assert!(v.get_meta(&m.id).unwrap().quarantined);
        assert!(matches!(v.read_value(&m.id), Err(Error::Integrity(_))));
    }

    #[test]
    fn swapped_ciphertext_fails() {
        let (_d, mut v) = setup();
        let a = v.add_secret(new_key("guarded/one", Tier::Otp)).unwrap();
        let b = v.add_secret(new_key("open/two", Tier::Auto)).unwrap();
        let (n, c): (Vec<u8>, Vec<u8>) = v
            .conn
            .query_row("SELECT nonce, ciphertext FROM secrets WHERE id=?1", params![a.id], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        v.conn.execute("UPDATE secrets SET nonce=?2, ciphertext=?3 WHERE id=?1", params![b.id, n, c]).unwrap();
        assert!(v.read_value(&b.id).is_err());
    }

    #[test]
    fn weakening_needs_stepup_and_reencrypts() {
        let (_d, mut v) = setup();
        let m = v.add_secret(new_key("x/y", Tier::Otp)).unwrap();
        let patch = MetaPatch { tier: Some(Tier::Auto), ..Default::default() };
        assert!(v.update_meta(&m.id, &patch, false).is_err());
        let m2 = v.update_meta(&m.id, &patch, true).unwrap();
        assert_eq!(m2.tier, Tier::Auto);
        assert_eq!(&*v.read_value(&m.id).unwrap(), "value-of-x/y-0123456789abcdef");
        // Strengthening is free.
        v.update_meta(&m.id, &MetaPatch { tier: Some(Tier::Sealed), ..Default::default() }, false).unwrap();
    }

    #[test]
    fn audit_tamper_detected() {
        let (_d, mut v) = setup();
        v.add_secret(new_key("k/1", Tier::Auto)).unwrap();
        v.log(LogInput::new("x", "y", "ok")).unwrap();
        assert!(v.verify_chain().unwrap().ok);
        v.conn.execute("UPDATE audit SET outcome='denied' WHERE seq=2", []).unwrap();
        assert!(!v.verify_chain().unwrap().ok);
    }

    #[test]
    fn audit_truncation_detected() {
        let (_d, mut v) = setup();
        v.log(LogInput::new("a", "b", "ok")).unwrap();
        v.log(LogInput::new("c", "d", "ok")).unwrap();
        v.conn.execute("DELETE FROM audit WHERE seq=(SELECT MAX(seq) FROM audit)", []).unwrap();
        assert!(!v.verify_chain().unwrap().ok);
    }

    #[test]
    fn otp_replay_and_lockout() {
        let (_d, mut v) = setup();
        // The setup code consumed the current step; the same step cannot approve again.
        let seed = v.keys().unwrap().totp_seed.clone();
        let code = totp::code_at_step(&seed, totp::step_at(now_ms() / 1000));
        assert!(matches!(v.check_otp(&code), Err(Error::BadCode)));
        for _ in 0..5 {
            let _ = v.check_otp("000000");
        }
        assert!(v.otp_locked_until().is_some());
    }

    #[test]
    fn pin_set_check_and_tamper() {
        let (_d, mut v) = setup();
        assert!(!v.has_pin());
        assert!(v.set_pin("12a4").is_err());
        v.set_pin("482913").unwrap();
        assert!(v.has_pin());
        v.check_pin("482913").unwrap();
        assert!(matches!(v.check_pin("000000"), Err(Error::BadCode)));
        // Replacing the stored hash outside KeyHolder breaks its signature.
        v.conn.execute("UPDATE meta SET v = x'7b7d' WHERE k = 'pin'", []).unwrap();
        assert!(matches!(v.check_pin("482913"), Err(Error::Integrity(_))));
    }

    fn seed_from_uri(uri: &str) -> Vec<u8> {
        let secret = uri.split("secret=").nth(1).unwrap().split('&').next().unwrap();
        BASE32_NOPAD.decode(secret.as_bytes()).unwrap()
    }

    #[test]
    fn presets_roundtrip_and_tamper() {
        let (_d, mut v) = setup();
        v.add_secret(new_key("git/one", Tier::Otp)).unwrap();
        let list = v.save_preset("release", &["git/one".into(), "nope/missing".into()], 120).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].keys, vec!["git/one".to_string()], "unknown keys are dropped");
        assert_eq!(v.presets().unwrap()[0].ttl_minutes, 120);
        v.conn.execute("UPDATE meta SET v = x'5b5d' WHERE k = 'presets'", []).unwrap();
        assert!(matches!(v.presets(), Err(Error::Integrity(_))));
    }

    #[test]
    fn change_password_and_antiphish() {
        let (_d, mut v) = setup();
        let m = v.add_secret(new_key("svc/key", Tier::Otp)).unwrap();
        assert!(v.change_password("short").is_err());
        v.change_password("a brand new password").unwrap();
        v.set_antiphish("лиса").unwrap();
        v.lock();
        assert!(matches!(v.unlock("correct horse battery"), Err(Error::BadPassword)));
        v.unlock("a brand new password").unwrap();
        assert_eq!(&*v.read_value(&m.id).unwrap(), "value-of-svc/key-0123456789abcdef");
        assert_eq!(v.antiphish_word().unwrap(), "лиса");
    }

    #[test]
    fn totp_reissue_then_recovery() {
        let (_d, mut v) = setup();
        let uri = v.begin_totp_reissue().unwrap();
        let seed = seed_from_uri(&uri);
        assert!(matches!(v.finish_totp_reissue("000000"), Err(Error::BadCode)));
        let code = totp::code_at_step(&seed, totp::step_at(now_ms() / 1000));
        let recovery = v.finish_totp_reissue(&code).unwrap();
        assert_eq!(recovery.len(), 10);
        assert!(!v.reissue_via_recovery());

        // Lost phone: a wrong recovery code is refused, a right one starts a reissue without
        // consuming anything yet; cancelling or locking abandons it.
        assert!(matches!(v.start_recovery_reissue("AAAA-BBBB-CCCC"), Err(Error::BadCode)));
        v.start_recovery_reissue(&recovery[0]).unwrap();
        assert!(v.reissue_via_recovery());
        v.cancel_totp_reissue();
        assert!(!v.reissue_via_recovery());
        v.start_recovery_reissue(&recovery[0]).unwrap();
        v.lock();
        assert!(!v.reissue_via_recovery());
    }

    #[test]
    fn anchor_appends_chain_head() {
        let (d, mut v) = setup();
        assert!(v.write_anchor().is_err(), "no path configured");
        let path = d.path().join("anchor.txt");
        let mut s = v.settings().unwrap();
        s.anchor_path = path.to_string_lossy().to_string();
        v.set_settings(&s).unwrap();
        v.write_anchor().unwrap();
        v.write_anchor().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.starts_with("kh1|"));
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_unlock_without_password() {
        let (_d, mut v) = setup();
        let m = v.add_secret(new_key("dp/key", Tier::Otp)).unwrap();
        assert!(!v.has_dpapi());
        assert!(!v.unlock_dpapi().unwrap(), "nothing to unwrap before enable_dpapi");
        v.enable_dpapi().unwrap();
        v.lock();
        assert!(v.unlock_dpapi().unwrap());
        assert_eq!(&*v.read_value(&m.id).unwrap(), "value-of-dp/key-0123456789abcdef");
    }

    #[test]
    fn reset_keeps_old_file_and_starts_empty() {
        let (d, mut v) = setup();
        v.add_secret(new_key("old/key", Tier::Otp)).unwrap();
        v.lock();
        let backup = v.reset().unwrap();
        assert!(backup.exists());
        assert!(!v.is_initialized());
        // The kept file still opens with the old password.
        let mut old = Vault::open(&backup).unwrap();
        old.unlock("correct horse battery").unwrap();
        assert_eq!(old.list_secrets().unwrap().len(), 1);
        // A new vault can be created in place, and its log starts with the reset.
        let p = PendingSetup::new("another long password", "hedgehog").unwrap();
        let code = totp::code_at_step(&p.seed, totp::step_at(now_ms() / 1000));
        v.finish_setup(&p, &code).unwrap();
        let log = v.list_log(10, None).unwrap();
        assert!(log.iter().any(|e| e.action == "reset"));
        assert!(v.verify_chain().unwrap().ok);
        drop(d);
    }

    #[test]
    fn non_latin_names_only_for_sealed_keys() {
        let (_d, mut v) = setup();
        let mut note = new_key("личное/почта", Tier::Sealed);
        note.group = "личное".into();
        let m = v.add_secret(note).unwrap();
        assert_eq!(v.get_meta_by_name("личное/почта").unwrap().id, m.id);
        // A key agents can ask for keeps a Latin name.
        let err = v.add_secret(new_key("почта", Tier::Soft)).unwrap_err().to_string();
        assert!(err.contains("only allowed for sealed keys"), "{err}");
        // Opening the note to agents needs a Latin name and group first.
        let to_soft = MetaPatch { tier: Some(Tier::Soft), ..Default::default() };
        assert!(v.update_meta(&m.id, &to_soft, true).is_err());
        let renamed = MetaPatch {
            name: Some("personal/mail".into()),
            group: Some("personal".into()),
            tier: Some(Tier::Soft),
            ..Default::default()
        };
        assert_eq!(v.update_meta(&m.id, &renamed, true).unwrap().name, "personal/mail");
    }

    #[test]
    fn mcpkey_export_moves_the_whole_vault() {
        let (_d, mut v) = setup();
        let m = v.add_secret(new_key("gh/token", Tier::Otp)).unwrap();
        let (_c, token) = v.create_client("claude-code").unwrap();
        #[cfg(windows)]
        v.enable_dpapi().unwrap();
        let file = v.export_file().unwrap();
        assert_eq!(&file[..8], EXPORT_MAGIC);
        // Names are not readable in the file.
        assert!(!file.windows(8).any(|w| w == b"gh/token"));

        // Wrong password, foreign bytes and a flipped bit are all refused.
        assert!(matches!(read_export(&file, "wrong password!!"), Err(Error::BadPassword)));
        assert!(read_export(b"not a vault at all", "correct horse battery").is_err());
        let mut bad = file.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(matches!(read_export(&bad, "correct horse battery"), Err(Error::Integrity(_))));

        // Another machine: an empty vault takes the file and opens with the same password.
        let other = tempfile::tempdir().unwrap();
        let mut w = Vault::open(&other.path().join("vault.db")).unwrap();
        assert!(w.import_file(&file, "wrong password!!").is_err());
        assert!(!w.is_initialized(), "a failed import leaves the vault untouched");
        assert_eq!(w.import_file(&file, "correct horse battery").unwrap(), None);
        assert!(w.is_unlocked());
        assert_eq!(&*w.read_value(&m.id).unwrap(), "value-of-gh/token-0123456789abcdef");
        assert!(w.auth_client(&token).unwrap().is_some(), "agent tokens keep working");
        assert!(!w.has_dpapi(), "machine-bound wrap is not carried over");
        assert!(w.verify_chain().unwrap().ok);
        assert!(w.list_log(5, None).unwrap().iter().any(|e| e.action == "import_vault"));

        // Importing over an existing vault keeps the old one aside.
        let (_e, mut x) = setup();
        x.add_secret(new_key("old/key", Tier::Soft)).unwrap();
        let backup = x.import_file(&file, "correct horse battery").unwrap().unwrap();
        assert!(backup.exists());
        assert_eq!(x.list_secrets().unwrap().len(), 1);
        assert_eq!(x.list_secrets().unwrap()[0].name, "gh/token");
    }

    #[test]
    fn clients_and_tamper() {
        let (_d, mut v) = setup();
        let (c, token) = v.create_client("claude-code").unwrap();
        assert_eq!(v.auth_client(&token).unwrap().unwrap().id, c.id);
        assert!(v.auth_client("kh_nope").unwrap().is_none());
        v.conn.execute("UPDATE clients SET blocked=0, revoked=0, name='other' WHERE id=?1", params![c.id]).unwrap();
        assert!(v.auth_client(&token).unwrap().is_none(), "tampered row treated as revoked");
    }

    #[test]
    fn scan_finds_full_values_only() {
        let (_d, mut v) = setup();
        let m = v.add_secret(new_key("svc/token", Tier::Otp)).unwrap();
        let val = v.read_value(&m.id).unwrap().to_string();
        let hits = v.scan_text(&format!("log line: token={val} end")).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(v.scan_text(&val[..val.len() / 2]).unwrap().is_empty());
    }
}

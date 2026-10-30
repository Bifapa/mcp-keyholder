use serde::{Deserialize, Serialize};

/// How much human confirmation a key needs before it can enter a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Auto,
    Soft,
    /// Fixed 4–6 digit PIN known only to the user.
    Pin,
    Otp,
    Sealed,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Auto => "auto",
            Tier::Soft => "soft",
            Tier::Pin => "pin",
            Tier::Otp => "otp",
            Tier::Sealed => "sealed",
        }
    }
    pub fn parse(s: &str) -> Option<Tier> {
        Some(match s {
            "auto" => Tier::Auto,
            "soft" => Tier::Soft,
            "pin" => Tier::Pin,
            "otp" => Tier::Otp,
            "sealed" => Tier::Sealed,
            _ => return None,
        })
    }
    /// Which encryption partition holds keys of this tier.
    pub fn partition(self) -> Partition {
        match self {
            Tier::Auto | Tier::Soft => Partition::Everyday,
            Tier::Pin | Tier::Otp | Tier::Sealed => Partition::Guarded,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Partition {
    Everyday,
    Guarded,
}

impl Partition {
    pub fn as_str(self) -> &'static str {
        match self {
            Partition::Everyday => "everyday",
            Partition::Guarded => "guarded",
        }
    }
}

/// In what form an agent receives the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Value returned over MCP.
    Reveal,
    /// Value placed in the environment of a `kh run` child process.
    Env,
    /// Placeholder + substituting proxy (planned for v0.2).
    Proxy,
    /// Signing only (planned).
    Sign,
    /// Pre-defined command only (planned).
    Recipe,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Reveal => "reveal",
            Mode::Env => "env",
            Mode::Proxy => "proxy",
            Mode::Sign => "sign",
            Mode::Recipe => "recipe",
        }
    }
    pub fn parse(s: &str) -> Option<Mode> {
        Some(match s {
            "reveal" => Mode::Reveal,
            "env" => Mode::Env,
            "proxy" => Mode::Proxy,
            "sign" => Mode::Sign,
            "recipe" => Mode::Recipe,
            _ => return None,
        })
    }
    /// Modes in which the value leaves the core.
    pub fn exposes_value(self) -> bool {
        matches!(self, Mode::Reveal | Mode::Env)
    }
    /// Implemented in this version.
    pub fn available(self) -> bool {
        matches!(self, Mode::Reveal | Mode::Env)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    Active,
    Disabled,
}

/// The security-relevant part of a key. Covered by the policy MAC and bound into
/// the ciphertext AAD, so editing any of it outside the core is detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub group: String,
    pub tier: Tier,
    pub mode: Mode,
    pub env_name: String,
    pub status: KeyStatus,
}

impl Policy {
    pub fn canonical(&self, id: &str, version: i64) -> String {
        format!(
            "kh1|policy|{}|{}|{}|{}|{}|{}|{}|{}",
            id,
            version,
            self.name,
            self.group,
            self.tier.as_str(),
            self.mode.as_str(),
            self.env_name,
            match self.status {
                KeyStatus::Active => "active",
                KeyStatus::Disabled => "disabled",
            }
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretMeta {
    pub id: String,
    pub name: String,
    pub description: String,
    pub group: String,
    pub tags: Vec<String>,
    pub tier: Tier,
    pub mode: Mode,
    pub env_name: String,
    pub status: KeyStatus,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_used_at: Option<i64>,
    pub use_count: i64,
    /// Unresolved "leaked" report/finding, newest first.
    pub leak: Option<LeakInfo>,
    /// Value has left the core in reveal/env mode since the last rotation.
    pub exposed: bool,
    /// Policy MAC or ciphertext failed verification; the key is quarantined.
    pub quarantined: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeakInfo {
    pub id: i64,
    pub kind: LeakKind,
    pub client: String,
    pub comment: String,
    pub at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LeakKind {
    /// Agent called report_leak.
    Reported,
    /// check_leak / kh scan found the value in text.
    Found,
    /// Value was handed out in reveal/env mode.
    Exposed,
}

impl LeakKind {
    pub fn as_str(self) -> &'static str {
        match self {
            LeakKind::Reported => "reported",
            LeakKind::Found => "found",
            LeakKind::Exposed => "exposed",
        }
    }
    pub fn parse(s: &str) -> Option<LeakKind> {
        Some(match s {
            "reported" => LeakKind::Reported,
            "found" => LeakKind::Found,
            "exposed" => LeakKind::Exposed,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewSecret {
    pub name: String,
    pub value: String,
    pub description: String,
    pub group: String,
    pub tags: Vec<String>,
    pub tier: Tier,
    pub mode: Mode,
    pub env_name: Option<String>,
}

/// A metadata edit. `None` leaves the field unchanged.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetaPatch {
    pub name: Option<String>,
    pub description: Option<String>,
    pub group: Option<String>,
    pub tags: Option<Vec<String>>,
    pub tier: Option<Tier>,
    pub mode: Option<Mode>,
    pub env_name: Option<String>,
    pub status: Option<KeyStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Client {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
    pub revoked: bool,
    pub blocked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub seq: i64,
    pub ts: i64,
    pub client: String,
    pub session: String,
    pub action: String,
    pub target: String,
    pub outcome: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainStatus {
    pub ok: bool,
    pub entries: i64,
    pub first_bad_seq: Option<i64>,
    pub message: String,
}

/// A saved permission preset: the keys an agent may ask for in one request and how long.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Preset {
    pub name: String,
    pub keys: Vec<String>,
    pub ttl_minutes: u32,
    pub created_at: i64,
}

/// How the interface is unlocked once the vault itself is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LoginMode {
    /// Master password (portable mode, and the service's default).
    #[default]
    Password,
    /// No gate at all: the window opens straight away.
    Nothing,
    /// 4–6 digit PIN.
    Pin,
    /// Code from the authenticator.
    Otp,
}

impl LoginMode {
    pub fn as_str(self) -> &'static str {
        match self {
            LoginMode::Password => "password",
            LoginMode::Nothing => "nothing",
            LoginMode::Pin => "pin",
            LoginMode::Otp => "otp",
        }
    }
    pub fn parse(s: &str) -> Option<LoginMode> {
        Some(match s {
            "password" => LoginMode::Password,
            "nothing" => LoginMode::Nothing,
            "pin" => LoginMode::Pin,
            "otp" => LoginMode::Otp,
            _ => return None,
        })
    }
    /// Only the service keeps its keys without a password, so short login methods need it.
    pub fn available_in(self, service: bool) -> bool {
        service || self == LoginMode::Password
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub autolock_minutes: u32,
    pub default_ttl_minutes: u32,
    pub max_ttl_minutes: u32,
    pub disable_on_leak_report: bool,
    /// Service mode only: how the interface is unlocked.
    #[serde(default)]
    pub login_mode: LoginMode,
    /// Service mode only: forget the keys (not just the interface) on auto-lock.
    #[serde(default)]
    pub full_lock: bool,
    /// Confirm `pin`/`otp` requests and passwords on a separate Windows desktop.
    #[serde(default = "yes")]
    pub secure_desktop: bool,
    /// Where to append the audit chain head, outside the database (empty = off).
    #[serde(default)]
    pub anchor_path: String,
    /// Show the anti-phishing word as moving noise, so a still screen capture shows no word.
    /// Off by default; offered in Settings with a demo.
    #[serde(default)]
    pub noise_word: bool,
    /// Colours of the noise word: 2 to 6 "#rrggbb" values, each cell takes one at random.
    #[serde(default = "default_noise_colors")]
    pub noise_colors: Vec<String>,
}

fn yes() -> bool {
    true
}

/// Four greys from near black to white.
pub fn default_noise_colors() -> Vec<String> {
    ["#1e1e1e", "#696969", "#b4b4b4", "#ffffff"].iter().map(|c| c.to_string()).collect()
}

/// The noise colours as 0x00RRGGBB, or None unless there are 2 to 6 valid "#rrggbb" values.
pub fn parse_noise_colors(colors: &[String]) -> Option<Vec<u32>> {
    if !(2..=6).contains(&colors.len()) {
        return None;
    }
    colors
        .iter()
        .map(|c| {
            let hex = c.strip_prefix('#')?;
            if hex.len() != 6 {
                return None;
            }
            u32::from_str_radix(hex, 16).ok()
        })
        .collect()
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            autolock_minutes: 60,
            default_ttl_minutes: 60,
            max_ttl_minutes: 240,
            disable_on_leak_report: false,
            login_mode: LoginMode::Password,
            full_lock: false,
            secure_desktop: true,
            anchor_path: String::new(),
            noise_word: false,
            noise_colors: default_noise_colors(),
        }
    }
}

/// Key names: lowercase ASCII, digits and `._/-`, 1..=64 chars.
pub fn valid_key_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'/' | b'-'))
        && !name.starts_with('/')
        && !name.ends_with('/')
}

/// Names of sealed keys — the human's own records, never listed to agents — may use any
/// lowercase letters (non-Latin too), digits, single inner spaces and `. _ / -`, up to 64 chars.
pub fn valid_sealed_name(name: &str) -> bool {
    let n = name.chars().count();
    n > 0
        && n <= 64
        && name.trim() == name
        && !name.contains("  ")
        && name
            .chars()
            .all(|c| (c.is_alphabetic() && !c.is_uppercase()) || c.is_ascii_digit() || matches!(c, ' ' | '.' | '_' | '/' | '-'))
        && !name.starts_with('/')
        && !name.ends_with('/')
}

/// Environment variable names: `[A-Z_][A-Z0-9_]*`, up to 64 chars.
pub fn valid_env_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_uppercase() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
}

/// `github/pipod-updates` -> `GITHUB_PIPOD_UPDATES`.
pub fn default_env_name(key_name: &str) -> String {
    let mut s: String = key_name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' })
        .collect();
    if s.as_bytes().first().map_or(true, |c| c.is_ascii_digit()) {
        s.insert(0, '_');
    }
    s.truncate(64);
    s
}

/// Remove control and bidi-override characters and cap the length of text that came from an agent.
pub fn sanitize_untrusted(s: &str, max_chars: usize) -> String {
    s.chars()
        .filter(|c| {
            !(c.is_control() && *c != ' ')
                && !matches!(*c,
                    '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
        })
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(valid_key_name("github/pipod-updates"));
        assert!(!valid_key_name("GitHub"));
        assert!(!valid_key_name("a b"));
        assert!(!valid_key_name("ключ"));
        assert!(valid_sealed_name("личное/почта"));
        assert!(valid_sealed_name("почта яндекс"));
        assert!(valid_sealed_name("github/pipod-updates"));
        assert!(!valid_sealed_name("Почта"), "lowercase only, like every other name");
        assert!(!valid_sealed_name(" почта"));
        assert!(!valid_sealed_name("почта  яндекс"));
        assert!(!valid_sealed_name("поч\u{202e}та"), "no bidi overrides");
        assert!(!valid_sealed_name("/почта"));
        assert_eq!(parse_noise_colors(&default_noise_colors()), Some(vec![0x1e1e1e, 0x696969, 0xb4b4b4, 0xffffff]));
        assert!(parse_noise_colors(&["#000000".into()]).is_none(), "at least two colours");
        assert!(parse_noise_colors(&vec!["#000000".to_string(); 7]).is_none(), "at most six");
        assert!(parse_noise_colors(&["#000000".into(), "red".into()]).is_none());
        assert_eq!(default_env_name("личное/почта"), "____________");
        assert_eq!(default_env_name("github/pipod-updates"), "GITHUB_PIPOD_UPDATES");
        assert!(valid_env_name("GH_TOKEN"));
        assert!(!valid_env_name("1X"));
    }

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_untrusted("ok\u{202E}evil\n<b>", 100), "okevil<b>");
        assert_eq!(sanitize_untrusted("abcdef", 3), "abc");
    }
}

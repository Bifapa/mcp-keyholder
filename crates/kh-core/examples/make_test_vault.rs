//! Dev helper for end-to-end tests: creates a throwaway vault with known password,
//! a few sample keys and a client. Prints the TOTP seed and the client token.
//! Usage: cargo run -p kh-core --example make_test_vault -- <dir>

use data_encoding::BASE32_NOPAD;
use kh_core::vault::PendingSetup;
use kh_core::{now_ms, totp, Mode, NewSecret, Tier, Vault};

fn main() {
    let dir = std::env::args().nth(1).expect("usage: make_test_vault <dir>");
    let mut v = Vault::open(&std::path::Path::new(&dir).join("vault.db")).unwrap();
    let p = PendingSetup::new("test-password-123", "test").unwrap();
    let seed = BASE32_NOPAD.decode(p.seed_base32().as_bytes()).unwrap();
    // Use the previous step so the next real code (current step) is still accepted.
    let code = totp::code_at_step(&seed, totp::step_at(now_ms() / 1000) - 1);
    v.finish_setup(&p, &code).unwrap();
    let key = |name: &str, tier: Tier, mode: Mode, value: &str, desc: &str| NewSecret {
        name: name.into(),
        value: value.into(),
        description: desc.into(),
        group: name.split('/').next().unwrap().into(),
        tags: vec![],
        tier,
        mode,
        env_name: None,
    };
    v.add_secret(key("demo/open", Tier::Auto, Mode::Reveal, "open-Value-1234567890abcdefXYZ", "auto + reveal")).unwrap();
    v.add_secret(key("demo/auto-env", Tier::Auto, Mode::Env, "auto-Env-Value-0f1e2d3c4b5a6978", "auto + env")).unwrap();
    v.add_secret(key("demo/soft", Tier::Soft, Mode::Reveal, "soft-Value-0987654321zyxwvuABC", "soft + reveal")).unwrap();
    v.add_secret(key("demo/otp-env", Tier::Otp, Mode::Env, "otp-Env-Value-55aa66bb77cc88dd", "otp + env")).unwrap();
    v.add_secret(key("demo/sealed", Tier::Sealed, Mode::Reveal, "sealed-Value-never-leaves-0001", "sealed")).unwrap();
    let (_, token) = v.create_client("e2e-test").unwrap();
    println!("SEED={}", p.seed_base32());
    println!("TOKEN={token}");
}

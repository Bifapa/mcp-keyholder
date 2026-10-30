//! Locking the vault when the human stops using it.

use std::sync::Arc;
use std::time::Duration;

use std::sync::atomic::Ordering;

use kh_core::now_ms;

use crate::{Daemon, Runtime};

/// Checks inactivity every few seconds and locks after `autolock_minutes`.
/// Any interaction — UI or agent — must call `Daemon::touch()`.
pub async fn run(d: Arc<Daemon>) {
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let unlocked = {
            let v = d.vault();
            v.is_unlocked()
        };
        if !unlocked {
            continue;
        }
        let Some(settings) = d.vault().settings().ok() else { continue };
        let limit = settings.autolock_minutes as i64 * 60_000;
        let now = now_ms();
        let idle_any = now - d.last_activity.load(Ordering::Relaxed);
        let idle_ui = now - d.ui_activity.load(Ordering::Relaxed);
        if d.runtime == Runtime::Service {
            // The service keeps serving agents: only the human's own inactivity closes the
            // interface. Full lock forgets the keys once nobody (human or agent) uses them.
            if settings.full_lock && idle_any >= limit {
                d.lock_vault("полная блокировка после бездействия");
            } else if idle_ui >= limit && d.ui_unlocked() && settings.login_mode != kh_core::LoginMode::Nothing {
                d.elevated_until.store(0, Ordering::Relaxed);
                d.set_ui_unlocked(false);
            }
        } else if idle_any >= limit {
            d.lock_vault("автоблокировка по бездействию");
        }
    }
}

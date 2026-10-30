//! Interface commands, reachable only through the app: `call(method, params)`.
//!
//! In portable mode the app runs them in-process; in service mode it sends the same call
//! over the interface channel. Nothing here is reachable by an agent.

use std::sync::atomic::Ordering;

use data_encoding::BASE64;
use kh_core::vault::{LogInput, PendingSetup};
use kh_core::{now_ms, ChainStatus, LoginMode, MetaPatch, NewSecret, Policy, Settings, Tier};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::broker::{Grant, Outcome, SessionInfo};
use crate::{err_str, CallResult, Daemon, Runtime, STEPUP_MS};

/// `.mcpkey` chunks stay well under the channel's line limit once in base64.
const TRANSFER_CHUNK: usize = 1024 * 1024;
const TRANSFER_MAX: usize = 512 * 1024 * 1024;

fn req<T: for<'de> Deserialize<'de>>(params: Value) -> Result<T, String> {
    serde_json::from_value(params).map_err(|e| format!("неверные параметры: {e}"))
}

impl Daemon {
    /// The single entry point for the UI. Everything the app can do to the core goes through here.
    pub fn call(&self, method: &str, params: Value) -> CallResult {
        // Background refreshes (status, lists, the approval window polling) are not activity;
        // otherwise an open app would keep the vault unlocked forever.
        if !is_passive(method) {
            self.touch_ui();
        }
        // In service mode the interface itself can be locked while agents keep working.
        if self.runtime == Runtime::Service
            && !self.ui_unlocked()
            && !matches!(method, "status" | "login" | "setup_begin" | "setup_secret_text" | "setup_finish" | "unlock" | "reset_vault")
        {
            return Err("ui_locked".into());
        }
        match method {
            "status" => Ok(self.status()),

            // ---------- setup / unlock ----------
            "setup_begin" => self.setup_begin(params),
            "setup_secret_text" => self.setup_secret_text(),
            "setup_finish" => self.setup_finish(params),
            "unlock" => self.unlock(params),
            "unlock_full" => self.unlock_full(params),
            "reset_vault" => self.reset_vault(params),
            "lock" => {
                self.lock_vault("хранилище заблокировано");
                Ok(Value::Null)
            }
            "lock_ui" => {
                self.lock_ui();
                Ok(Value::Null)
            }
            "login" => self.login(params),
            "stepup" => self.stepup(params),
            "end_stepup" => {
                self.elevated_until.store(0, Ordering::Relaxed);
                Ok(Value::Null)
            }
            "set_pin" => self.set_pin(params),

            // ---------- keys ----------
            "list_keys" => self.list_keys(),
            "add_key" => self.add_key(params),
            "update_keys" => self.update_keys(params),
            "replace_value" => self.replace_value(params),
            "delete_keys" => self.delete_keys(params),
            "reveal_value" => self.reveal_value(params),
            "copy_value" => self.copy_value(params),
            "dismiss_leak" => self.dismiss_leak(params),

            // ---------- grants / sessions ----------
            "list_grants" => self.list_grants(),
            "revoke_grant" => self.revoke_grant(params),
            "deny_request" => self.deny_request(params),
            "show_approval" => {
                if self.broker.queue_len() > 0 {
                    self.show_approval();
                }
                Ok(Value::Null)
            }
            "unblock_session" => self.unblock_session(params),
            "list_presets" => self.list_presets(),
            "save_preset" => self.save_preset(params),
            "delete_preset" => self.delete_preset(params),

            // ---------- clients ----------
            "list_clients" => self.list_clients(),
            "add_client" => self.add_client(params),
            "revoke_client" => self.revoke_client(params),
            "unblock_client" => self.unblock_client(params),

            // ---------- log ----------
            "list_log" => self.list_log(params),
            "verify_log" => self.verify_log(),

            // ---------- import ----------
            "read_import" => Ok(json!({ "candidates": [] })),
            "import_commit" => self.import_commit(params),

            // ---------- settings ----------
            "get_settings" => self.get_settings(),
            "set_settings" => self.set_settings(params),
            "set_login_mode" => self.set_login_mode(params),
            "change_password" => self.change_password(params),
            "change_antiphish" => self.change_antiphish(params),
            "reissue_totp_begin" => self.reissue_totp_begin(params),
            "reissue_totp_finish" => self.reissue_totp_finish(params),
            "reissue_totp_cancel" => {
                self.vault().cancel_totp_reissue();
                Ok(Value::Null)
            }
            "recovery_used" => self.recovery_used(params),
            "anchor_now" => self.anchor_now(),

            // ---------- whole-vault file (.mcpkey) ----------
            "export_vault" => self.export_vault(),
            "export_chunk" => self.export_chunk(params),
            "import_chunk" => self.import_chunk(params),
            "import_vault" => self.import_vault(params),

            // ---------- approval window ----------
            "approval_current" => self.approval_current(),
            "approval_decide" => self.approval_decide(params),
            _ => Err(format!("неизвестный метод интерфейса {method}")),
        }
    }

    // ---------- setup / unlock ----------

    fn setup_begin(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            password: String,
            word: String,
        }
        let p: P = req(params)?;
        if self.vault().is_initialized() {
            return Err("хранилище уже создано".into());
        }
        let pending = PendingSetup::new(&p.password, &p.word).map_err(err_str)?;
        let out = json!({
            "otpauthUri": pending.otpauth_uri(),
            "seedBase32": pending.seed_base32(),
            "recovery": pending.recovery_codes(),
        });
        *self.pending_setup.lock().unwrap_or_else(|e| e.into_inner()) = Some(pending);
        Ok(out)
    }

    fn setup_secret_text(&self) -> CallResult {
        let g = self.pending_setup.lock().unwrap_or_else(|e| e.into_inner());
        g.as_ref().map(|p| json!(p.seed_base32())).ok_or_else(|| "настройка не начата".into())
    }

    fn setup_finish(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            code: String,
        }
        let p: P = req(params)?;
        let r = {
            let mut slot = self.pending_setup.lock().unwrap_or_else(|e| e.into_inner());
            let pending = slot.as_ref().ok_or("настройка не начата")?;
            let r = self.vault().finish_setup(pending, &p.code);
            if r.is_ok() {
                *slot = None;
            }
            r
        };
        r.map_err(err_str)?;
        self.unlock_notify.notify_waiters();
        self.emit("unlock");
        Ok(Value::Null)
    }

    fn unlock(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            password: String,
        }
        let p: P = req(params)?;
        self.vault().unlock(&p.password).map_err(err_str)?;
        self.after_unlock();
        Ok(Value::Null)
    }

    /// Lost master password: start over with an empty vault. The old file is kept aside
    /// (encrypted), so a reset is never a data loss — only a fresh start.
    fn reset_vault(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            confirm: String,
        }
        let p: P = req(params)?;
        if p.confirm.trim() != "СБРОСИТЬ" {
            return Err("введите СБРОСИТЬ, чтобы подтвердить".into());
        }
        self.elevated_until.store(0, Ordering::Relaxed);
        self.broker.clear_all("хранилище сброшено");
        self.close_approval();
        *self.pending_setup.lock().unwrap_or_else(|e| e.into_inner()) = None;
        let backup = self.vault().reset().map_err(err_str)?;
        self.ui_unlocked.store(true, Ordering::Relaxed);
        self.emit("lock");
        Ok(json!({ "backup": backup.display().to_string() }))
    }

    /// After a full lock (keys forgotten): the master password brings them back.
    fn unlock_full(&self, params: Value) -> CallResult {
        self.unlock(params)
    }

    fn after_unlock(&self) {
        if self.runtime == Runtime::Service {
            // The service must be able to restart without the human; full lock opts out.
            let wrapped = {
                let v = self.vault();
                v.is_unlocked() && !v.has_dpapi() && !v.startup_full_lock()
            };
            if wrapped {
                let _ = self.vault().enable_dpapi();
            }
        }
        self.ui_unlocked.store(true, Ordering::Relaxed);
        self.touch_ui();
        self.unlock_notify.notify_waiters();
        self.emit("unlock");
    }

    fn login(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            credential: Option<String>,
        }
        let p: P = req(params)?;
        let mode = self.vault().settings().map(|s| s.login_mode).unwrap_or_default();
        if self.runtime != Runtime::Service {
            return Err("вход по PIN и OTP есть только в режиме службы".into());
        }
        let cred = p.credential.unwrap_or_default();
        let r = {
            let mut v = self.vault();
            if !v.is_unlocked() {
                return Err("vault_locked".into());
            }
            match mode {
                LoginMode::Nothing => Ok(()),
                LoginMode::Password => v.verify_password(&cred),
                LoginMode::Pin => v.check_pin(&cred),
                LoginMode::Otp => v.check_otp(&cred),
            }
        };
        r.map_err(err_str)?;
        self.ui_unlocked.store(true, Ordering::Relaxed);
        self.touch_ui();
        self.emit("unlock");
        Ok(json!({ "ok": true }))
    }

    /// Master password plus either the authenticator code or Windows Hello. The Hello
    /// dialog is run by the core itself (through the UI process), never taken on trust.
    fn stepup(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            password: Option<String>,
            code: Option<String>,
            #[serde(default)]
            hello: bool,
        }
        let p: P = req(params)?;
        let password = p.password.filter(|x| !x.is_empty()).ok_or("нужен мастер-пароль")?;
        {
            let mut v = self.vault();
            if let Err(e) = v.verify_password(&password) {
                let _ = v.log(LogInput::new("stepup", "vault", "denied").detail("неверный пароль"));
                return Err(e.to_string());
            }
        }
        if p.hello {
            if let Err(e) = self.verify_presence("MCP Keyholder: повышение прав на 3 минуты") {
                let _ = self.vault().log(LogInput::new("stepup", "vault", "denied").detail("Windows Hello не подтверждён"));
                return Err(e);
            }
        } else {
            let code = p.code.unwrap_or_default();
            let mut v = self.vault();
            if let Err(e) = v.check_otp(&code) {
                let _ = v.log(LogInput::new("stepup", "vault", "denied").detail("неверный код"));
                return Err(e.to_string());
            }
        }
        let until = now_ms() + STEPUP_MS;
        self.elevated_until.store(until, Ordering::Relaxed);
        let _ = self.vault().log(LogInput::new("stepup", "vault", "ok").detail(if p.hello {
            "повышение прав на 3 минуты (Windows Hello)"
        } else {
            "повышение прав на 3 минуты"
        }));
        Ok(json!(until))
    }

    fn set_pin(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            pin: String,
        }
        let p: P = req(params)?;
        self.require_elevated()?;
        self.vault().set_pin(&p.pin).map_err(err_str)?;
        self.emit("vault");
        Ok(Value::Null)
    }

    // ---------- keys ----------

    fn list_keys(&self) -> CallResult {
        let v = self.vault();
        Ok(json!({
            "keys": v.list_secrets().map_err(err_str)?,
            "groups": v.groups().map_err(err_str)?,
        }))
    }

    fn add_key(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            key: NewSecret,
        }
        let p: P = req(params)?;
        let m = self.vault().add_secret(p.key).map_err(err_str)?;
        self.emit("vault");
        Ok(serde_json::to_value(m).unwrap_or_default())
    }

    fn update_keys(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            ids: Vec<String>,
            patch: MetaPatch,
        }
        let p: P = req(params)?;
        let elevated = self.is_elevated();
        let mut v = self.vault();
        if p.ids.len() > 1 && p.patch.name.is_some() {
            return Err("имя нельзя менять сразу у нескольких ключей".into());
        }
        // All-or-nothing check for weakening before touching anything.
        if !elevated {
            for id in &p.ids {
                let old = v.policy_of(id).map_err(err_str)?;
                if kh_core::Vault::is_weakening(&old, &patched(&old, &p.patch)) {
                    return Err("stepup_required".into());
                }
            }
        }
        let mut ok = 0;
        let mut errors = Vec::new();
        for id in &p.ids {
            match v.update_meta(id, &p.patch, elevated) {
                Ok(_) => ok += 1,
                Err(e) => errors.push(e.to_string()),
            }
        }
        drop(v);
        self.emit("vault");
        Ok(json!({ "ok": ok, "errors": errors }))
    }

    fn replace_value(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            id: String,
            value: String,
        }
        let p: P = req(params)?;
        let tier = self.vault().policy_of(&p.id).map_err(err_str)?.tier;
        if tier >= Tier::Pin {
            self.require_elevated()?;
        }
        let m = self.vault().replace_value(&p.id, &p.value).map_err(err_str)?;
        self.emit("vault");
        Ok(serde_json::to_value(m).unwrap_or_default())
    }

    fn delete_keys(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            ids: Vec<String>,
        }
        let p: P = req(params)?;
        self.require_elevated()?;
        let mut ok = 0;
        let mut errors = Vec::new();
        for id in &p.ids {
            match self.vault().delete_secret(id) {
                Ok(()) => ok += 1,
                Err(e) => errors.push(e.to_string()),
            }
        }
        self.emit("vault");
        Ok(json!({ "ok": ok, "errors": errors }))
    }

    fn reveal_value(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            id: String,
        }
        let p: P = req(params)?;
        self.require_elevated()?;
        let mut v = self.vault();
        let name = v.policy_of(&p.id).map_err(err_str)?.name;
        let value = v.read_value(&p.id).map_err(err_str)?;
        let _ = v.log(LogInput::new("reveal_ui", &name, "ok").detail("значение показано в окне MCP Keyholder"));
        Ok(json!(value.to_string()))
    }

    /// The value for the clipboard. The app copies it without passing it through the webview.
    fn copy_value(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            id: String,
        }
        let p: P = req(params)?;
        self.require_elevated()?;
        let mut v = self.vault();
        let name = v.policy_of(&p.id).map_err(err_str)?.name;
        let value = v.read_value(&p.id).map_err(err_str)?;
        let _ = v.log(LogInput::new("copy_ui", &name, "ok").detail("скопировано в буфер на 30 с"));
        Ok(json!({ "value": value.to_string() }))
    }

    fn dismiss_leak(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            id: String,
        }
        let p: P = req(params)?;
        self.require_elevated()?;
        self.vault().dismiss_leaks(&p.id).map_err(err_str)?;
        self.emit("vault");
        Ok(Value::Null)
    }

    // ---------- grants / sessions ----------

    fn list_grants(&self) -> CallResult {
        Ok(json!({
            "pending": self.broker.pending(),
            "active": self.broker.grants(),
            "sessions": self.broker.sessions().into_iter().filter(|s| s.purpose == "mcp").collect::<Vec<SessionInfo>>(),
        }))
    }

    fn revoke_grant(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            id: String,
        }
        let p: P = req(params)?;
        if let Some(g) = self.broker.revoke(&p.id) {
            let names = g.keys.iter().map(|k| k.name.as_str()).collect::<Vec<_>>().join(", ");
            let _ = self.vault().log(LogInput::new("revoke_grant", &names, "ok").detail(format!("клиент {}", g.client)));
        }
        self.emit("grants");
        Ok(Value::Null)
    }

    fn deny_request(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            id: String,
        }
        let p: P = req(params)?;
        self.deny(&p.id, "отклонено человеком", false);
        Ok(Value::Null)
    }

    fn unblock_session(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            id: String,
        }
        let p: P = req(params)?;
        self.broker.update_session(&p.id, |s| s.blocked_until = 0);
        self.emit("grants");
        Ok(Value::Null)
    }

    // ---------- permission presets ----------

    fn list_presets(&self) -> CallResult {
        let presets = self.vault().presets().map_err(err_str)?;
        Ok(json!(presets))
    }

    fn save_preset(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            name: String,
            keys: Vec<String>,
            ttl_minutes: u32,
        }
        let p: P = req(params)?;
        let presets = self.vault().save_preset(&p.name, &p.keys, p.ttl_minutes).map_err(err_str)?;
        Ok(json!(presets))
    }

    fn delete_preset(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            name: String,
        }
        let p: P = req(params)?;
        let presets = self.vault().delete_preset(&p.name).map_err(err_str)?;
        Ok(json!(presets))
    }

    // ---------- clients ----------

    fn list_clients(&self) -> CallResult {
        Ok(serde_json::to_value(self.vault().list_clients().map_err(err_str)?).unwrap_or_default())
    }

    fn add_client(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            name: String,
        }
        let p: P = req(params)?;
        self.require_elevated()?;
        let (client, token) = self.vault().create_client(&p.name).map_err(err_str)?;
        let config = json!({
            "mcpServers": { "keyholder": { "command": self.kh_path, "args": ["mcp"], "env": { "KH_TOKEN": token } } }
        });
        self.emit("clients");
        Ok(json!({
            "client": client,
            "token": token,
            "configJson": serde_json::to_string_pretty(&config).unwrap_or_default(),
            "claudeCommand": format!("claude mcp add keyholder --scope user -e KH_TOKEN={} -- \"{}\" mcp", token, self.kh_path),
        }))
    }

    fn revoke_client(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            id: String,
        }
        let p: P = req(params)?;
        self.require_elevated()?;
        let c = self.vault().revoke_client(&p.id).map_err(err_str)?;
        self.emit("clients");
        Ok(serde_json::to_value(c).unwrap_or_default())
    }

    fn unblock_client(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            id: String,
        }
        let p: P = req(params)?;
        self.require_elevated()?;
        let c = self.vault().set_client_blocked(&p.id, false, "снято человеком").map_err(err_str)?;
        self.emit("clients");
        Ok(serde_json::to_value(c).unwrap_or_default())
    }

    // ---------- log ----------

    fn list_log(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            limit: i64,
            before: Option<i64>,
        }
        let p: P = req(params)?;
        Ok(serde_json::to_value(self.vault().list_log(p.limit.clamp(1, 1000), p.before).map_err(err_str)?).unwrap_or_default())
    }

    fn verify_log(&self) -> CallResult {
        let s: ChainStatus = self.vault().verify_chain().map_err(err_str)?;
        Ok(serde_json::to_value(s).unwrap_or_default())
    }

    fn anchor_now(&self) -> CallResult {
        self.vault().write_anchor().map_err(err_str)?;
        Ok(Value::Null)
    }

    // ---------- import ----------

    fn import_commit(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            drafts: Vec<NewSecret>,
        }
        let p: P = req(params)?;
        let mut added = Vec::new();
        let mut errors = Vec::new();
        {
            let mut v = self.vault();
            for d in p.drafts {
                let name = d.name.clone();
                match v.add_secret(d) {
                    Ok(m) => added.push(m.name),
                    Err(e) => errors.push(format!("{name}: {e}")),
                }
            }
            let _ = v.log(LogInput::new("import", &format!("{} ключей", added.len()), "ok").detail(added.join(", ")));
        }
        self.emit("vault");
        Ok(json!({ "added": added, "errors": errors }))
    }

    // ---------- settings ----------

    fn get_settings(&self) -> CallResult {
        Ok(serde_json::to_value(self.vault().settings().map_err(err_str)?).unwrap_or_default())
    }

    fn set_settings(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            settings: Settings,
        }
        let p: P = req(params)?;
        let old = self.vault().settings().map_err(err_str)?;
        let weakening = p.settings.max_ttl_minutes > old.max_ttl_minutes
            || p.settings.autolock_minutes > old.autolock_minutes
            || (old.secure_desktop && !p.settings.secure_desktop)
            || (!p.settings.anchor_path.is_empty() && p.settings.anchor_path != old.anchor_path)
            || p.settings.login_mode != old.login_mode
            || (p.settings.full_lock != old.full_lock);
        if weakening {
            self.require_elevated()?;
        }
        self.vault().set_settings(&p.settings).map_err(err_str)?;
        self.emit("settings");
        Ok(Value::Null)
    }

    fn set_login_mode(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            mode: String,
        }
        let p: P = req(params)?;
        let mode = LoginMode::parse(&p.mode).ok_or("неизвестный способ входа")?;
        self.require_elevated()?;
        if !mode.available_in(self.runtime == Runtime::Service) {
            return Err("короткий вход возможен только в режиме службы: в портативном режиме ключи заперты мастер-паролем".into());
        }
        if mode == LoginMode::Pin && !self.vault().has_pin() {
            return Err("сначала задайте PIN".into());
        }
        let mut s = self.vault().settings().map_err(err_str)?;
        s.login_mode = mode;
        self.vault().set_settings(&s).map_err(err_str)?;
        if mode == LoginMode::Nothing {
            self.ui_unlocked.store(true, Ordering::Relaxed);
        }
        self.emit("settings");
        Ok(Value::Null)
    }

    /// Changing the password, the word or the authenticator needs a step-up (master password +
    /// code, typed on the separate desktop). Password and code passed here are optional extra
    /// checks for callers that collect them themselves; a second code right after the step-up
    /// would only make the human wait for the next 30-second step.
    fn change_password(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            #[serde(default)]
            password: Option<String>,
            #[serde(default)]
            code: Option<String>,
            new_password: String,
        }
        let p: P = req(params)?;
        self.require_elevated()?;
        let mut v = self.vault();
        if let Some(pw) = p.password.as_deref().filter(|x| !x.is_empty()) {
            if let Err(e) = v.verify_password(pw) {
                let _ = v.log(LogInput::new("change_password", "vault", "denied").detail("неверный пароль"));
                return Err(e.to_string());
            }
        }
        if let Some(code) = p.code.as_deref().filter(|x| !x.is_empty()) {
            v.check_otp(code).map_err(err_str)?;
        }
        v.change_password(&p.new_password).map_err(err_str)?;
        self.emit("vault");
        Ok(Value::Null)
    }

    fn change_antiphish(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            word: String,
            #[serde(default)]
            code: Option<String>,
        }
        let p: P = req(params)?;
        self.require_elevated()?;
        let mut v = self.vault();
        if let Some(code) = p.code.as_deref().filter(|x| !x.is_empty()) {
            v.check_otp(code).map_err(err_str)?;
        }
        v.set_antiphish(&p.word).map_err(err_str)?;
        self.emit("vault");
        Ok(Value::Null)
    }

    /// Re-issuing the authenticator needs the master password *and* the current code: the
    /// step-up checks both.
    fn reissue_totp_begin(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            #[serde(default)]
            password: Option<String>,
            #[serde(default)]
            code: Option<String>,
        }
        let p: P = req(params)?;
        self.require_elevated()?;
        let mut v = self.vault();
        if let Some(pw) = p.password.as_deref().filter(|x| !x.is_empty()) {
            v.verify_password(pw).map_err(err_str)?;
        }
        if let Some(code) = p.code.as_deref().filter(|x| !x.is_empty()) {
            v.check_otp(code).map_err(err_str)?;
        }
        let seed = v.begin_totp_reissue().map_err(err_str)?;
        drop(v);
        Ok(json!({ "otpauthUri": seed, "recovery": Vec::<String>::new() }))
    }

    fn reissue_totp_finish(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            code: String,
        }
        let p: P = req(params)?;
        // After a recovery code the authenticator is gone, so step-up (which needs it) is impossible.
        if !self.vault().reissue_via_recovery() {
            self.require_elevated()?;
        }
        let codes = self.vault().finish_totp_reissue(&p.code).map_err(err_str)?;
        self.emit("vault");
        Ok(json!({ "recovery": codes }))
    }

    /// Lost authenticator: master password + a recovery code start a fresh enrolment.
    fn recovery_used(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            password: String,
            code: String,
        }
        let p: P = req(params)?;
        let mut v = self.vault();
        if let Err(e) = v.verify_password(&p.password) {
            let _ = v.log(LogInput::new("recovery", "vault", "denied").detail("неверный пароль"));
            return Err(e.to_string());
        }
        let uri = v.start_recovery_reissue(&p.code).map_err(err_str)?;
        drop(v);
        Ok(json!({ "otpauthUri": uri }))
    }

    // ---------- whole-vault file (.mcpkey) ----------

    /// Builds the `.mcpkey` file; the interface then reads it with `export_chunk`.
    fn export_vault(&self) -> CallResult {
        self.require_elevated()?;
        let data = self.vault().export_file().map_err(err_str)?;
        let size = data.len();
        self.transfer.lock().unwrap_or_else(|e| e.into_inner()).export = Some(data);
        Ok(json!({ "size": size }))
    }

    fn export_chunk(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            offset: usize,
        }
        let p: P = req(params)?;
        let mut t = self.transfer.lock().unwrap_or_else(|e| e.into_inner());
        let data = t.export.as_ref().ok_or("экспорт не начат")?;
        if p.offset > data.len() {
            return Err("неверное смещение".into());
        }
        let end = (p.offset + TRANSFER_CHUNK).min(data.len());
        let chunk = BASE64.encode(&data[p.offset..end]);
        let done = end == data.len();
        if done {
            t.export = None;
        }
        Ok(json!({ "data": chunk, "done": done }))
    }

    fn import_chunk(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            offset: usize,
            data: String,
        }
        let p: P = req(params)?;
        let bytes = BASE64.decode(p.data.as_bytes()).map_err(|_| "повреждённый фрагмент файла")?;
        let mut t = self.transfer.lock().unwrap_or_else(|e| e.into_inner());
        if p.offset == 0 {
            t.import.clear();
        }
        if p.offset != t.import.len() {
            return Err("фрагменты файла пришли не по порядку".into());
        }
        if t.import.len() + bytes.len() > TRANSFER_MAX {
            t.import = Vec::new();
            return Err("файл слишком большой".into());
        }
        t.import.extend_from_slice(&bytes);
        Ok(json!({ "received": t.import.len() }))
    }

    /// Replaces the vault with the uploaded `.mcpkey` file. A fresh install takes it right
    /// away; an existing vault needs to be open and a step-up, like any other destructive
    /// change. The current file is kept aside either way.
    fn import_vault(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            password: String,
        }
        let p: P = req(params)?;
        let (initialized, unlocked) = {
            let v = self.vault();
            (v.is_initialized(), v.is_unlocked())
        };
        if initialized {
            if !unlocked {
                return Err("сначала откройте хранилище (или сбросьте его на экране входа)".into());
            }
            self.require_elevated()?;
        }
        let data = std::mem::take(&mut self.transfer.lock().unwrap_or_else(|e| e.into_inner()).import);
        if data.is_empty() {
            return Err("файл не загружен".into());
        }
        // Check the password before dropping grants and sessions of the current vault.
        kh_core::vault::read_export(&data, &p.password).map_err(err_str)?;
        self.elevated_until.store(0, Ordering::Relaxed);
        self.broker.clear_all("хранилище заменено");
        self.close_approval();
        *self.pending_setup.lock().unwrap_or_else(|e| e.into_inner()) = None;
        let backup = self.vault().import_file(&data, &p.password).map_err(err_str)?;
        self.after_unlock();
        self.emit("vault");
        Ok(json!({ "backup": backup.map(|b| b.display().to_string()) }))
    }

    // ---------- approval surface ----------

    fn approval_current(&self) -> CallResult {
        let (antiphish, has_pin) = {
            let v = self.vault();
            (v.antiphish_word().unwrap_or_default(), v.has_pin())
        };
        Ok(json!({
            "request": self.broker.current_shown(),
            "antiphish": antiphish,
            "queue": self.broker.queue_len(),
            "hasPin": has_pin,
        }))
    }

    fn approval_decide(&self, params: Value) -> CallResult {
        #[derive(Deserialize)]
        struct P {
            id: String,
            approve: bool,
            keep: Vec<String>,
            ttl_minutes: u32,
            code: Option<String>,
            block_session: bool,
            /// Confirm with Windows Hello instead of a code; the core runs the dialog itself.
            #[serde(default)]
            hello: bool,
        }
        let p: P = req(params)?;
        let view = self.broker.current_shown().ok_or("запроса уже нет")?;
        if view.id != p.id {
            return Err("на экране уже другой запрос".into());
        }
        if !p.approve {
            let why = if p.block_session {
                "отклонено человеком, сессия заблокирована на 10 минут"
            } else {
                "отклонено человеком"
            };
            self.deny(&p.id, why, p.block_session);
            return Ok(json!({ "ok": true }));
        }
        if now_ms() - view.shown_at.unwrap_or(now_ms()) < 1500 {
            return Err("подождите секунду и проверьте запрос".into());
        }
        let keys: Vec<_> = view.keys.iter().filter(|k| p.keep.contains(&k.name)).cloned().collect();
        if keys.is_empty() {
            return Err("отметьте хотя бы один ключ или отклоните запрос".into());
        }
        let ttl = p.ttl_minutes.clamp(1, view.ttl_minutes.max(1));
        let level = keys.iter().map(|k| k.tier).max().unwrap_or(Tier::Soft);
        if level >= Tier::Pin && p.hello {
            let names = keys.iter().map(|k| k.name.as_str()).collect::<Vec<_>>().join(", ");
            let message = format!("MCP Keyholder: {} просит {} на {} мин", view.client, names, ttl);
            self.verify_presence(&message)?;
            // The request may have been answered elsewhere while the dialog was open.
            if self.broker.front_id().as_deref() != Some(p.id.as_str()) {
                return Err("запроса уже нет".into());
            }
            let _ = self.vault().log(
                LogInput::new("hello", &view.client, "ok")
                    .by(&view.client, &view.session)
                    .detail("подтверждение присутствием (Windows Hello)"),
            );
        } else if level >= Tier::Pin {
            let code = p.code.unwrap_or_default();
            // PIN-tier keys take the PIN; without a PIN set they fall back to OTP.
            let r = {
                let mut v = self.vault();
                if level == Tier::Pin && v.has_pin() {
                    v.check_pin(&code)
                } else {
                    v.check_otp(&code)
                }
            };
            match r {
                Ok(()) => {}
                Err(kh_core::Error::BadCode) => {
                    let n = self.broker.note_otp_failure(&p.id);
                    let _ = self.vault().log(
                        LogInput::new("otp", &view.client, "bad_code").by(&view.client, &view.session).detail(format!("попытка {n} из 3")),
                    );
                    if n >= 3 {
                        if let Some(s) = self.broker.session(&view.session) {
                            if let Some(cid) = s.client_id {
                                let _ = self.vault().set_client_blocked(&cid, true, "3 неверных кода подряд");
                            }
                        }
                        self.deny(&p.id, "3 неверных кода — запрос отклонён, клиент заблокирован", false);
                        return Err("Три неверных кода. Запрос отклонён, клиент заблокирован.".into());
                    }
                    self.emit("approvals");
                    return Err(format!("Неверный код. Осталось попыток: {}", 3 - n));
                }
                Err(e) => return Err(e.to_string()),
            }
        }
        let grant = Grant {
            id: uuid::Uuid::new_v4().to_string(),
            session: view.session.clone(),
            client: view.client.clone(),
            process: view.process.clone(),
            keys,
            reason: view.reason.clone(),
            level,
            created_at: now_ms(),
            expires_at: now_ms() + ttl as i64 * 60_000,
            uses: 0,
        };
        let names = grant.keys.iter().map(|k| k.name.as_str()).collect::<Vec<_>>().join(", ");
        self.broker.add_grant(grant.clone());
        let _ = self.vault().log(
            LogInput::new("grant", &names, "granted")
                .by(&view.client, &view.session)
                .detail(format!("{} · {ttl} мин · {}", level.as_str(), view.reason)),
        );
        self.broker.resolve(&p.id, Outcome::Granted(grant));
        self.after_decision();
        Ok(json!({ "ok": true }))
    }

    pub(crate) fn after_decision(&self) {
        if self.broker.queue_len() == 0 {
            self.close_approval();
        }
        self.emit("approvals");
        self.emit("grants");
    }

    pub(crate) fn deny(&self, id: &str, why: &str, block_session: bool) {
        if let Some(view) = self.broker.resolve(id, Outcome::Denied(why.to_string())) {
            if block_session {
                self.broker.update_session(&view.session, |s| s.blocked_until = now_ms() + 10 * 60_000);
            }
            let names = view.keys.iter().map(|k| k.name.as_str()).collect::<Vec<_>>().join(", ");
            let _ = self.vault().log(LogInput::new("deny", &names, "denied").by(&view.client, &view.session).detail(why));
        }
        self.after_decision();
    }
}

/// Read-only calls the UI makes on its own (periodic refresh, popups re-reading state).
pub(crate) fn is_passive(method: &str) -> bool {
    matches!(
        method,
        "status"
            | "list_keys"
            | "list_grants"
            | "list_clients"
            | "list_log"
            | "verify_log"
            | "get_settings"
            | "list_presets"
            | "approval_current"
    )
}

fn patched(old: &Policy, p: &MetaPatch) -> Policy {
    let mut n = old.clone();
    if let Some(x) = &p.name {
        n.name = x.trim().to_string();
    }
    if let Some(x) = &p.group {
        n.group = x.trim().to_string();
    }
    if let Some(x) = p.tier {
        n.tier = x;
    }
    if let Some(x) = p.mode {
        n.mode = x;
    }
    if let Some(x) = &p.env_name {
        n.env_name = x.trim().to_string();
    }
    if let Some(x) = p.status {
        n.status = x;
    }
    n
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use data_encoding::BASE32_NOPAD;
    use kh_core::vault::PendingSetup;
    use kh_core::{now_ms, totp, Vault};
    use serde_json::json;

    use crate::{Daemon, Runtime};

    fn daemon() -> (tempfile::TempDir, std::sync::Arc<Daemon>) {
        let dir = tempfile::tempdir().unwrap();
        let mut v = Vault::open(&dir.path().join("vault.db")).unwrap();
        let p = PendingSetup::new("correct horse battery", "сова").unwrap();
        let seed = BASE32_NOPAD.decode(p.seed_base32().as_bytes()).unwrap();
        let code = totp::code_at_step(&seed, totp::step_at(now_ms() / 1000) - 1);
        v.finish_setup(&p, &code).unwrap();
        let d = Daemon::new(v, Runtime::Portable, "kh".into(), dir.path().to_path_buf());
        (dir, d)
    }

    #[test]
    fn stepup_needs_the_master_password() {
        let (_d, d) = daemon();
        assert_eq!(d.call("stepup", json!({ "hello": true })).unwrap_err(), "нужен мастер-пароль");
        assert!(d.call("stepup", json!({ "code": "123456" })).is_err());
        assert!(!d.is_elevated());
    }

    #[test]
    fn hello_is_never_taken_on_trust() {
        // No UI process to show the Windows Hello dialog: the flag alone must not elevate.
        let (_d, d) = daemon();
        assert!(d.call("stepup", json!({ "password": "correct horse battery", "hello": true })).is_err());
        assert!(!d.is_elevated());
        assert!(d.call("stepup", json!({ "password": "wrong password!!", "code": "000000" })).is_err());
        assert!(!d.is_elevated());
    }

    #[test]
    fn changes_after_stepup_need_no_second_code() {
        let (_d, d) = daemon();
        // Without a step-up nothing changes.
        assert_eq!(d.call("change_antiphish", json!({ "word": "ёжик" })).unwrap_err(), "stepup_required");
        assert_eq!(d.call("reissue_totp_begin", json!({})).unwrap_err(), "stepup_required");
        d.elevated_until.store(now_ms() + 60_000, Ordering::Relaxed);
        d.call("change_antiphish", json!({ "word": "ёжик" })).unwrap();
        assert_eq!(d.vault().antiphish_word().unwrap(), "ёжик");
        // An extra password, when a caller passes one, is still checked.
        assert!(d.call("change_password", json!({ "password": "wrong password!!", "new_password": "a brand new password" })).is_err());
        d.call("change_password", json!({ "new_password": "a brand new password" })).unwrap();
        d.vault().verify_password("a brand new password").unwrap();
        assert!(d.call("reissue_totp_begin", json!({})).unwrap().get("otpauthUri").is_some());
    }

    /// Reads a whole export through the chunked calls, as the app does.
    fn download(d: &Daemon) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let r = d.call("export_chunk", json!({ "offset": out.len() })).unwrap();
            out.extend(super::BASE64.decode(r["data"].as_str().unwrap().as_bytes()).unwrap());
            if r["done"].as_bool().unwrap() {
                return out;
            }
        }
    }

    #[test]
    fn mcpkey_goes_through_the_interface_in_chunks() {
        let (_d, d) = daemon();
        assert_eq!(d.call("export_vault", json!({})).unwrap_err(), "stepup_required");
        d.elevated_until.store(now_ms() + 60_000, Ordering::Relaxed);
        let size = d.call("export_vault", json!({})).unwrap()["size"].as_u64().unwrap() as usize;
        let file = download(&d);
        assert_eq!(file.len(), size);
        assert!(d.call("export_chunk", json!({ "offset": 0 })).is_err(), "the export is gone once read");

        // A fresh install takes the file without a step-up; chunks may come in any size.
        let (_e, fresh) = {
            let dir = tempfile::tempdir().unwrap();
            let v = Vault::open(&dir.path().join("vault.db")).unwrap();
            let f = Daemon::new(v, Runtime::Portable, "kh".into(), dir.path().to_path_buf());
            (dir, f)
        };
        let half = file.len() / 2;
        fresh.call("import_chunk", json!({ "offset": 0, "data": super::BASE64.encode(&file[..half]) })).unwrap();
        assert!(fresh.call("import_chunk", json!({ "offset": 5, "data": "" })).is_err());
        fresh.call("import_chunk", json!({ "offset": half, "data": super::BASE64.encode(&file[half..]) })).unwrap();
        assert!(fresh.call("import_vault", json!({ "password": "wrong password!!" })).is_err());
        fresh.call("import_chunk", json!({ "offset": 0, "data": super::BASE64.encode(&file) })).unwrap();
        fresh.call("import_vault", json!({ "password": "correct horse battery" })).unwrap();
        assert!(fresh.vault().is_unlocked());

        // Over an existing vault: open and step-up first.
        d.call("end_stepup", json!({})).unwrap();
        d.call("import_chunk", json!({ "offset": 0, "data": super::BASE64.encode(&file) })).unwrap();
        assert_eq!(d.call("import_vault", json!({ "password": "correct horse battery" })).unwrap_err(), "stepup_required");
    }

    #[test]
    fn background_refresh_is_not_activity() {
        let (_d, d) = daemon();
        d.ui_activity.store(0, Ordering::Relaxed);
        d.last_activity.store(0, Ordering::Relaxed);
        for m in ["status", "list_keys", "list_grants", "list_clients", "get_settings", "approval_current"] {
            let _ = d.call(m, json!({}));
        }
        assert_eq!(d.ui_activity.load(Ordering::Relaxed), 0);
        assert_eq!(d.last_activity.load(Ordering::Relaxed), 0);
        let _ = d.call("end_stepup", json!({}));
        assert!(d.ui_activity.load(Ordering::Relaxed) > 0);
    }
}

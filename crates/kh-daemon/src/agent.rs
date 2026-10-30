//! Agent-facing operations (what MCP tools and `kh run` end up calling).
//! Every path to a value goes through a grant; every decision is logged.

use std::collections::BTreeMap;
use std::time::Duration;

use data_encoding::BASE32_NOPAD;
use kh_core::protocol::methods as m;
use kh_core::vault::LogInput;
use kh_core::{crypto, now_ms, sanitize_untrusted, KeyStatus, LeakKind, Mode, SecretMeta, Tier};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::broker::{Enqueue, Grant, GrantKey, Outcome, PendingView, Removed, SessionInfo, Ticket};
use crate::Daemon;

const APPROVAL_WAIT: Duration = Duration::from_secs(170);
const UNLOCK_WAIT: Duration = Duration::from_secs(120);
const TICKET_MS: i64 = 60_000;
const CHECK_LEAK_MAX: usize = 1024 * 1024;

type R = Result<Value, String>;

fn log(d: &Daemon, s: &SessionInfo, action: &str, target: &str, outcome: &str, detail: impl Into<String>) {
    let _ = d.vault().log(LogInput::new(action, target, outcome).by(&s.client, &s.id).detail(detail));
}

async fn ensure_unlocked(d: &Daemon) -> Result<(), String> {
    if d.vault().is_unlocked() {
        return Ok(());
    }
    if !d.vault().is_initialized() {
        return Err("MCP Keyholder ещё не настроен: откройте приложение и создайте хранилище".into());
    }
    d.show_main();
    d.emit("unlock-needed");
    let _ = tokio::time::timeout(UNLOCK_WAIT, d.unlock_notify.notified()).await;
    if d.vault().is_unlocked() {
        Ok(())
    } else {
        Err("locked: хранилище MCP Keyholder заблокировано — попросите человека разблокировать его".into())
    }
}

/// Authenticates the session's client token (lazily, because the vault may have been locked at hello).
fn ensure_client(d: &Daemon, session: &str) -> Result<SessionInfo, String> {
    let s = d.broker.session(session).ok_or("сессия не найдена")?;
    if s.client_id.is_some() {
        let c = d.vault().list_clients().map_err(|e| e.to_string())?;
        let c = c.into_iter().find(|c| Some(&c.id) == s.client_id.as_ref());
        return match c {
            Some(c) if c.revoked => Err("клиент отозван".into()),
            Some(c) if c.blocked => Err("клиент заблокирован — человек может снять блокировку в MCP Keyholder → Клиенты".into()),
            Some(_) => Ok(s),
            None => Err("клиент удалён".into()),
        };
    }
    let token = s.token.clone().ok_or(
        "нет токена клиента: добавьте клиента в MCP Keyholder → Клиенты и передайте его токен в переменной KH_TOKEN",
    )?;
    let client = d.vault().auth_client(&token).map_err(|e| e.to_string())?;
    let Some(c) = client else {
        return Err("токен клиента не принят: добавьте клиента в MCP Keyholder → Клиенты и обновите KH_TOKEN".into());
    };
    if c.blocked {
        return Err("клиент заблокирован — человек может снять блокировку в MCP Keyholder → Клиенты".into());
    }
    let _ = d.vault().touch_client(&c.id);
    d.broker.update_session(session, |x| {
        x.client_id = Some(c.id.clone());
        x.client = c.name.clone();
    });
    d.broker.session(session).ok_or_else(|| "сессия не найдена".into())
}

fn status_of(m: &SecretMeta) -> &'static str {
    if m.quarantined {
        "integrity_error"
    } else if m.status == KeyStatus::Disabled {
        "disabled"
    } else if m.leak.is_some() {
        "leaked"
    } else if m.exposed {
        "exposed"
    } else {
        "ok"
    }
}

fn meta_by_name(d: &Daemon, name: &str) -> Result<SecretMeta, String> {
    d.vault()
        .list_secrets()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|m| m.name == name)
        .ok_or_else(|| format!("ключа «{name}» нет в MCP Keyholder (см. list_secrets)"))
}

fn usable(m: &SecretMeta) -> Result<(), String> {
    if m.quarantined {
        return Err(format!("ключ «{}» не прошёл проверку целостности и заблокирован", m.name));
    }
    if m.status == KeyStatus::Disabled {
        return Err(format!("ключ «{}» отключён", m.name));
    }
    if m.tier == Tier::Sealed {
        return Err(format!("ключ «{}» запечатан и агентам не выдаётся", m.name));
    }
    Ok(())
}

/// Short reason for the approval window's "removed" list.
fn short_unusable(m: &SecretMeta) -> Option<&'static str> {
    if m.quarantined {
        Some("ошибка целостности")
    } else if m.status == KeyStatus::Disabled {
        Some("отключён")
    } else if m.tier == Tier::Sealed {
        Some("запечатан, убран")
    } else {
        None
    }
}

fn keys_names(v: &PendingView) -> Vec<&str> {
    v.keys.iter().map(|k| k.name.as_str()).collect()
}

fn grant_json(g: &Grant) -> Value {
    json!({
        "grantId": g.id,
        "keys": g.keys.iter().map(|k| json!({"name": k.name, "mode": k.mode})).collect::<Vec<_>>(),
        "level": g.level,
        "expiresAt": g.expires_at,
        "expiresInMinutes": ((g.expires_at - now_ms()).max(0) + 59_999) / 60_000,
        "reason": g.reason,
    })
}

fn auto_grant(d: &Daemon, s: &SessionInfo, m: &SecretMeta) -> Grant {
    let ttl = d.vault().settings().map(|x| x.default_ttl_minutes).unwrap_or(60) as i64;
    let g = Grant {
        id: uuid::Uuid::new_v4().to_string(),
        session: s.id.clone(),
        client: s.client.clone(),
        process: s.process.clone(),
        keys: vec![GrantKey { id: m.id.clone(), name: m.name.clone(), mode: m.mode, tier: m.tier }],
        reason: "автоматически (уровень «Без окна»)".into(),
        level: Tier::Auto,
        created_at: now_ms(),
        expires_at: now_ms() + ttl * 60_000,
        uses: 0,
    };
    d.broker.add_grant(g.clone());
    log(d, s, "grant", &m.name, "auto", format!("на {ttl} мин"));
    g
}

/// Finds a grant covering `m` for this session, creating one for auto-tier keys.
fn covering_grant(d: &Daemon, s: &SessionInfo, m: &SecretMeta) -> Result<GrantKey, String> {
    if let Some((_, k)) = d.broker.use_grant(&s.id, &m.id) {
        return Ok(k);
    }
    if m.tier == Tier::Auto {
        auto_grant(d, s, m);
        if let Some((_, k)) = d.broker.use_grant(&s.id, &m.id) {
            return Ok(k);
        }
    }
    log(d, s, "access", &m.name, "denied", "нет в разрешении");
    Err(format!(
        "not_in_grant: ключа «{}» нет в ваших разрешениях — сначала вызовите request_grant",
        m.name
    ))
}

impl Daemon {
    pub async fn handle_agent(&self, session: &str, method: &str, params: Value) -> R {
        let d = self;
        d.touch();
        let purpose = d.broker.session(session).map(|s| s.purpose).unwrap_or_default();

        if method == m::STATUS {
            let v = d.vault();
            return Ok(json!({
                "app": env!("CARGO_PKG_VERSION"),
                "initialized": v.is_initialized(),
                "unlocked": v.is_unlocked(),
                "runtime": d.runtime.as_str(),
            }));
        }
        if method == m::REDEEM_TICKET {
            ensure_unlocked(d).await?;
            return redeem_ticket(d, session, params);
        }
        if purpose == "run" {
            return Err("этот канал только для kh run --ticket".into());
        }

        ensure_unlocked(d).await?;
        let s = ensure_client(d, session)?;
        match method {
            m::LIST_SECRETS => list_secrets(d, &s, params),
            m::REQUEST_GRANT => request_grant(d, &s, params).await,
            m::MY_GRANTS => Ok(json!({ "grants": d.broker.grants_for(&s.id).iter().map(grant_json).collect::<Vec<_>>() })),
            m::GET_SECRET => get_secret(d, &s, params),
            m::PREPARE_RUN => prepare_run(d, &s, params),
            m::REPORT_LEAK => report_leak(d, &s, params),
            m::CHECK_LEAK => check_leak(d, &s, params),
            _ => Err(format!("неизвестный метод {method}")),
        }
    }

    /// `kh` CLI convenience: the agent protocol's status without a session.
    pub fn agent_status(&self) -> Value {
        let v = self.vault();
        json!({
            "app": env!("CARGO_PKG_VERSION"),
            "initialized": v.is_initialized(),
            "unlocked": v.is_unlocked(),
            "runtime": self.runtime.as_str(),
        })
    }
}

#[derive(Deserialize)]
struct ListParams {
    query: Option<String>,
}

fn list_secrets(d: &Daemon, s: &SessionInfo, params: Value) -> R {
    let p: ListParams = serde_json::from_value(params).unwrap_or(ListParams { query: None });
    let q = p.query.unwrap_or_default().to_lowercase();
    let metas = d.vault().list_secrets().map_err(|e| e.to_string())?;
    let grants = d.broker.grants_for(&s.id);
    let items: Vec<Value> = metas
        .iter()
        .filter(|m| m.tier != Tier::Sealed)
        .filter(|m| {
            q.is_empty()
                || m.name.contains(&q)
                || m.description.to_lowercase().contains(&q)
                || m.group.contains(&q)
                || m.tags.iter().any(|t| t.contains(&q))
        })
        .map(|m| {
            let g = grants.iter().filter(|g| g.keys.iter().any(|k| k.id == m.id)).max_by_key(|g| g.expires_at);
            json!({
                "name": m.name,
                "description": m.description,
                "group": m.group,
                "tags": m.tags,
                "tier": m.tier,
                "mode": m.mode,
                "envName": if m.mode == Mode::Env { Some(&m.env_name) } else { None },
                "status": status_of(m),
                "inGrant": g.is_some() || (m.tier == Tier::Auto && m.status == KeyStatus::Active),
                "grantExpiresAt": g.map(|g| g.expires_at),
            })
        })
        .collect();
    log(d, s, "list_secrets", "*", "ok", format!("{} ключей", items.len()));
    Ok(json!({
        "secrets": items,
        "howTo": "Call request_grant with the keys you need (one request for everything). Tier auto is granted automatically; soft/otp show a confirmation window to the human. Then use get_secret (mode reveal) or prepare_run (mode env).",
    }))
}

#[derive(Deserialize)]
struct KeyReq {
    name: String,
    mode: Option<Mode>,
}

#[derive(Deserialize)]
struct GrantParams {
    reason: Option<String>,
    #[serde(default)]
    keys: Vec<KeyReq>,
    ttl_minutes: Option<u32>,
    /// A permission preset saved earlier: its keys and default lifetime join this request.
    preset: Option<String>,
}

async fn request_grant(d: &Daemon, s: &SessionInfo, params: Value) -> R {
    let mut p: GrantParams = serde_json::from_value(params).map_err(|e| format!("неверные параметры: {e}"))?;
    let reason = sanitize_untrusted(p.reason.as_deref().unwrap_or(""), 200);
    if reason.is_empty() {
        return Err("укажите reason — коротко и честно, зачем нужны ключи".into());
    }
    if let Some(name) = &p.preset {
        let presets = d.vault().presets().map_err(|e| e.to_string())?;
        let Some(pr) = presets.iter().find(|x| &x.name == name) else {
            return Ok(json!({"status": "denied", "message": format!("пресета «{name}» нет: человек сохраняет их в окне подтверждения")}));
        };
        for k in &pr.keys {
            if !p.keys.iter().any(|x| &x.name == k) {
                p.keys.push(KeyReq { name: k.clone(), mode: None });
            }
        }
        if p.ttl_minutes.is_none() {
            p.ttl_minutes = Some(pr.ttl_minutes);
        }
    }
    if p.keys.is_empty() || p.keys.len() > 32 {
        return Err("keys: от 1 до 32 ключей (или укажите preset)".into());
    }
    if s.blocked_until > now_ms() {
        log(d, s, "request_grant", "*", "denied", "сессия заблокирована");
        return Ok(json!({"status": "denied", "message": "Сессия временно заблокирована человеком."}));
    }
    if !d.broker.rate_ok(&format!("grant:{}", s.client), 5, 60_000) {
        log(d, s, "request_grant", "*", "rate_limited", "больше 5 запросов в минуту");
        return Ok(json!({"status": "rate_limited", "message": "Не больше 5 запросов в минуту. Объедините ключи в один запрос."}));
    }
    let metas = d.vault().list_secrets().map_err(|e| e.to_string())?;
    let settings = d.vault().settings().map_err(|e| e.to_string())?;
    let mut keys: Vec<GrantKey> = Vec::new();
    let mut removed: Vec<Removed> = Vec::new();
    for k in &p.keys {
        let name = sanitize_untrusted(&k.name, 64);
        if keys.iter().any(|x| x.name == name) {
            continue;
        }
        let Some(m) = metas.iter().find(|m| m.name == name) else {
            removed.push(Removed { name, why: "нет такого ключа".into() });
            continue;
        };
        if let Some(why) = short_unusable(m) {
            removed.push(Removed { name, why: why.into() });
            continue;
        }
        if let Some(mode) = k.mode {
            if mode != m.mode {
                removed.push(Removed { name, why: format!("только режим {}", m.mode.as_str()) });
                continue;
            }
        }
        keys.push(GrantKey { id: m.id.clone(), name: m.name.clone(), mode: m.mode, tier: m.tier });
    }
    let removed_json = serde_json::to_value(&removed).unwrap_or_default();
    if keys.is_empty() {
        log(d, s, "request_grant", "*", "denied", "нет подходящих ключей");
        return Ok(json!({"status": "denied", "message": "Ни один ключ не подходит.", "removed": removed_json}));
    }
    let ttl = p.ttl_minutes.unwrap_or(settings.default_ttl_minutes).clamp(1, settings.max_ttl_minutes);
    let level = keys.iter().map(|k| k.tier).max().unwrap_or(Tier::Auto);
    let names = keys.iter().map(|k| k.name.as_str()).collect::<Vec<_>>().join(", ");

    if level == Tier::Auto {
        let g = Grant {
            id: uuid::Uuid::new_v4().to_string(),
            session: s.id.clone(),
            client: s.client.clone(),
            process: s.process.clone(),
            keys,
            reason: reason.clone(),
            level,
            created_at: now_ms(),
            expires_at: now_ms() + ttl as i64 * 60_000,
            uses: 0,
        };
        d.broker.add_grant(g.clone());
        log(d, s, "grant", &names, "auto", format!("на {ttl} мин · {reason}"));
        d.emit("grants");
        let mut v = grant_json(&g);
        v["status"] = json!("granted");
        v["removed"] = removed_json;
        return Ok(v);
    }

    let id = uuid::Uuid::new_v4().to_string();
    let view = PendingView {
        id: id.clone(),
        session: s.id.clone(),
        client: s.client.clone(),
        claimed_client: s.claimed_client.clone(),
        process: s.process.clone(),
        reason: reason.clone(),
        keys,
        removed,
        ttl_minutes: ttl,
        level,
        created_at: now_ms(),
        shown_at: None,
        otp_failures: 0,
    };
    // The same session asking for the same keys again waits on the running request
    // instead of piling up a second window.
    let signature = {
        let mut names: Vec<&str> = keys_names(&view);
        names.sort_unstable();
        format!("{}|{}|{}", view.session, names.join(","), ttl)
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    match d.broker.enqueue(view.clone(), signature, tx) {
        Enqueue::New | Enqueue::Joined => {}
        Enqueue::Busy => {
            return Ok(json!({"status": "pending", "message": "Предыдущий запрос этой сессии ещё ждёт решения человека."}));
        }
    }
    log(d, s, "request_grant", &names, "pending", format!("{} · {ttl} мин · {reason}", level.as_str()));
    d.show_approval();
    d.emit("approvals");

    match tokio::time::timeout(APPROVAL_WAIT, rx).await {
        Ok(Ok(Outcome::Granted(g))) => {
            let mut v = grant_json(&g);
            v["status"] = json!("granted");
            v["removed"] = removed_json;
            Ok(v)
        }
        Ok(Ok(Outcome::Denied(why))) => Ok(json!({"status": "denied", "message": why, "removed": removed_json})),
        Ok(Err(_)) => Ok(json!({"status": "denied", "message": "запрос отменён"})),
        Err(_) => {
            let was_front = d.broker.front_id().as_deref() == Some(id.as_str());
            d.broker.drop_request(&id);
            log(d, s, "request_grant", &names, "timeout", "человек не ответил");
            if was_front {
                if d.broker.queue_len() == 0 {
                    d.close_approval();
                }
                d.emit("approvals");
            }
            Ok(json!({"status": "timeout", "message": "Человек не ответил за 3 минуты. Если окно всё ещё открыто, решение применится к этой сессии — проверьте my_grants."}))
        }
    }
}

#[derive(Deserialize)]
struct NameParams {
    name: String,
}

fn get_secret(d: &Daemon, s: &SessionInfo, params: Value) -> R {
    let p: NameParams = serde_json::from_value(params).map_err(|e| format!("неверные параметры: {e}"))?;
    let m = meta_by_name(d, &p.name)?;
    usable(&m)?;
    if m.mode != Mode::Reveal {
        log(d, s, "get_secret", &m.name, "denied", format!("режим {}", m.mode.as_str()));
        return Err(format!(
            "ключ «{}» выдаётся в режиме {}: значение агенту не отдаётся{}",
            m.name,
            m.mode.as_str(),
            if m.mode == Mode::Env { " — используйте prepare_run и kh run" } else { "" }
        ));
    }
    covering_grant(d, s, &m)?;
    let value = d.vault().read_value(&m.id).map_err(|e| e.to_string())?;
    let _ = d.vault().touch_use(&m.id);
    let _ = d.vault().add_leak(&m.id, LeakKind::Exposed, &s.client, &s.id, "выдан в режиме reveal");
    log(d, s, "get_secret", &m.name, "ok", "reveal");
    d.emit("vault");
    Ok(json!({
        "name": m.name,
        "value": value.as_str(),
        "note": "This value is now considered exposed. Never print it in chat, code, logs or commits. If it ends up anywhere it shouldn't, call report_leak.",
    }))
}

#[derive(Deserialize)]
struct RunParams {
    keys: Vec<String>,
    command: Option<String>,
}

fn prepare_run(d: &Daemon, s: &SessionInfo, params: Value) -> R {
    let p: RunParams = serde_json::from_value(params).map_err(|e| format!("неверные параметры: {e}"))?;
    if p.keys.is_empty() || p.keys.len() > 32 {
        return Err("keys: от 1 до 32 ключей".into());
    }
    let mut ids = Vec::new();
    let mut env = BTreeMap::new();
    for name in &p.keys {
        let m = meta_by_name(d, name)?;
        usable(&m)?;
        if m.mode != Mode::Env {
            return Err(format!("ключ «{}» в режиме {}, а не env", m.name, m.mode.as_str()));
        }
        covering_grant(d, s, &m)?;
        ids.push(m.id.clone());
        env.insert(m.env_name.clone(), m.name.clone());
    }
    let ticket = BASE32_NOPAD.encode(&crypto::random_bytes::<20>()).to_lowercase();
    d.broker.add_ticket(ticket.clone(), Ticket { session: s.id.clone(), key_ids: ids, expires_at: now_ms() + TICKET_MS });
    log(d, s, "prepare_run", &p.keys.join(", "), "ok", "билет на 60 с");
    let cmd = sanitize_untrusted(p.command.as_deref().unwrap_or("<command> [args]"), 500);
    Ok(json!({
        "ticket": ticket,
        "expiresInSeconds": TICKET_MS / 1000,
        "env": env,
        "command": format!("\"{}\" run --ticket {} -- {}", d.kh_path, ticket, cmd),
        "note": "Run the command as-is within 60 seconds. The ticket works once. Your process receives the variables listed in env; do not print them.",
    }))
}

#[derive(Deserialize)]
struct TicketParams {
    ticket: String,
}

fn redeem_ticket(d: &Daemon, session: &str, params: Value) -> R {
    let p: TicketParams = serde_json::from_value(params).map_err(|e| format!("неверные параметры: {e}"))?;
    let runner = d.broker.session(session).ok_or("сессия не найдена")?;
    let t = d.broker.take_ticket(p.ticket.trim()).ok_or("билет недействителен, истёк или уже использован")?;
    let owner = d.broker.session(&t.session).ok_or("сессия, получившая билет, закрыта")?;
    let mut env = serde_json::Map::new();
    let mut names = Vec::new();
    for id in &t.key_ids {
        let m = d.vault().get_meta(id).map_err(|e| e.to_string())?;
        usable(&m)?;
        if m.mode != Mode::Env {
            return Err(format!("ключ «{}» больше не в режиме env", m.name));
        }
        covering_grant(d, &owner, &m)?;
        let v = d.vault().read_value(id).map_err(|e| e.to_string())?;
        env.insert(m.env_name.clone(), json!(v.as_str()));
        let _ = d.vault().touch_use(id);
        let _ = d.vault().add_leak(id, LeakKind::Exposed, &owner.client, &owner.id, "выдан в режиме env (kh run)");
        names.push(m.name);
    }
    log(d, &owner, "kh_run", &names.join(", "), "ok", format!("процесс: {}", runner.process));
    d.emit("vault");
    Ok(json!({ "env": env }))
}

#[derive(Deserialize)]
struct LeakParams {
    name: String,
    comment: Option<String>,
}

fn report_leak(d: &Daemon, s: &SessionInfo, params: Value) -> R {
    let p: LeakParams = serde_json::from_value(params).map_err(|e| format!("неверные параметры: {e}"))?;
    if !d.broker.rate_ok(&format!("leak:{}", s.id), 10, 3_600_000) {
        return Err("не больше 10 сообщений об утечке в час".into());
    }
    let comment = sanitize_untrusted(p.comment.as_deref().unwrap_or(""), 500);
    let Ok(m) = meta_by_name(d, &p.name) else {
        log(d, s, "report_leak", &sanitize_untrusted(&p.name, 64), "unknown_key", comment);
        return Ok(json!({"ok": false, "message": "Такого ключа нет в MCP Keyholder; сообщение записано в журнал."}));
    };
    d.vault().add_leak(&m.id, LeakKind::Reported, &s.client, &s.id, &comment).map_err(|e| e.to_string())?;
    if d.vault().settings().map(|x| x.disable_on_leak_report).unwrap_or(false) {
        let patch = kh_core::MetaPatch { status: Some(KeyStatus::Disabled), ..Default::default() };
        let _ = d.vault().update_meta(&m.id, &patch, false);
    }
    d.emit("leak");
    Ok(json!({
        "ok": true,
        "message": "Thank you. The key is marked as leaked and the human will see a warning to rotate it. Do not use or repeat the value.",
    }))
}

#[derive(Deserialize)]
struct CheckParams {
    text: String,
}

fn check_leak(d: &Daemon, s: &SessionInfo, params: Value) -> R {
    let p: CheckParams = serde_json::from_value(params).map_err(|e| format!("неверные параметры: {e}"))?;
    if p.text.len() > CHECK_LEAK_MAX {
        return Err("текст больше 1 МБ — разбейте на части".into());
    }
    let limit = if s.purpose == "scan" { 500 } else { 20 };
    if !d.broker.rate_ok(&format!("check:{}", s.id), limit, 3_600_000) {
        return Err(format!("не больше {limit} проверок в час"));
    }
    let hits = d.vault().scan_text(&p.text).map_err(|e| e.to_string())?;
    for (id, _) in &hits {
        let _ = d.vault().add_leak(id, LeakKind::Found, &s.client, &s.id, "значение найдено в тексте, присланном на проверку");
    }
    let names: Vec<String> = hits.into_iter().map(|(_, n)| n).collect();
    log(d, s, "check_leak", &format!("{} байт", p.text.len()), if names.is_empty() { "clean" } else { "found" }, names.join(", "));
    if !names.is_empty() {
        d.emit("leak");
    }
    Ok(json!({
        "found": names,
        "message": if names.is_empty() {
            "No stored secret values found (values shorter than 16 chars or low-entropy are not checked)."
        } else {
            "These keys were found in the text and are now marked as leaked; the human will be asked to rotate them. Remove the values from the text."
        },
    }))
}

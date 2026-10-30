//! In-memory state for agent sessions: grants, the approval queue, tickets and rate limits.
//! Nothing here is persisted: locking the vault or closing a session drops it.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use kh_core::{now_ms, Mode, Tier};
use serde::Serialize;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantKey {
    pub id: String,
    pub name: String,
    pub mode: Mode,
    pub tier: Tier,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub id: String,
    pub session: String,
    pub client: String,
    pub process: String,
    pub keys: Vec<GrantKey>,
    pub reason: String,
    pub level: Tier,
    pub created_at: i64,
    pub expires_at: i64,
    pub uses: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Removed {
    pub name: String,
    pub why: String,
}

/// What the approval window shows. Immutable once queued.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingView {
    pub id: String,
    pub session: String,
    /// Registered client name (verified by token).
    pub client: String,
    /// Name the agent reported in MCP `initialize` (unverified).
    pub claimed_client: String,
    /// Process chain on the other end of the pipe (verified by the OS).
    pub process: String,
    /// Agent-provided reason (unverified, sanitised).
    pub reason: String,
    pub keys: Vec<GrantKey>,
    pub removed: Vec<Removed>,
    pub ttl_minutes: u32,
    pub level: Tier,
    pub created_at: i64,
    pub shown_at: Option<i64>,
    pub otp_failures: u32,
}

#[derive(Clone)]
pub enum Outcome {
    Granted(Grant),
    Denied(String),
}

struct Pending {
    view: PendingView,
    /// Same session + same keys + same lifetime: repeated requests wait on one decision.
    signature: String,
    waiters: Vec<oneshot::Sender<Outcome>>,
}

/// What happened to a request that an agent wanted to queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enqueue {
    /// A new request is on the queue.
    New,
    /// The same request is already waiting: this call joined it.
    Joined,
    /// The session has a different request waiting; ours was not added.
    Busy,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub id: String,
    pub purpose: String,
    pub client_id: Option<String>,
    pub client: String,
    pub claimed_client: String,
    pub process: String,
    pub connected_at: i64,
    pub blocked_until: i64,
    #[serde(skip)]
    pub token: Option<Zeroizing<String>>,
}

pub struct Ticket {
    pub session: String,
    pub key_ids: Vec<String>,
    pub expires_at: i64,
}

#[derive(Default)]
struct Inner {
    sessions: HashMap<String, SessionInfo>,
    grants: Vec<Grant>,
    queue: VecDeque<Pending>,
    counters: HashMap<String, VecDeque<i64>>,
    tickets: HashMap<String, Ticket>,
}

#[derive(Default)]
pub struct Broker {
    inner: Mutex<Inner>,
}

impl Inner {
    fn prune(&mut self) {
        let now = now_ms();
        self.grants.retain(|g| g.expires_at > now);
        self.tickets.retain(|_, t| t.expires_at > now);
    }
}

impl Broker {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ---------- sessions ----------

    pub fn add_session(&self, s: SessionInfo) {
        self.lock().sessions.insert(s.id.clone(), s);
    }

    pub fn session(&self, id: &str) -> Option<SessionInfo> {
        self.lock().sessions.get(id).cloned()
    }

    pub fn update_session(&self, id: &str, f: impl FnOnce(&mut SessionInfo)) {
        if let Some(s) = self.lock().sessions.get_mut(id) {
            f(s);
        }
    }

    pub fn sessions(&self) -> Vec<SessionInfo> {
        self.lock().sessions.values().cloned().collect()
    }

    /// Drops everything tied to a closed session.
    pub fn end_session(&self, id: &str) {
        let mut g = self.lock();
        g.sessions.remove(id);
        g.grants.retain(|x| x.session != id);
        g.tickets.retain(|_, t| t.session != id);
        let mut keep = VecDeque::new();
        while let Some(mut p) = g.queue.pop_front() {
            if p.view.session == id {
                for tx in p.waiters.drain(..) {
                    let _ = tx.send(Outcome::Denied("сессия агента закрыта".into()));
                }
            } else {
                keep.push_back(p);
            }
        }
        g.queue = keep;
    }

    /// Sliding-window rate limit. Returns false when `limit` events already happened in `window_ms`.
    pub fn rate_ok(&self, key: &str, limit: usize, window_ms: i64) -> bool {
        let now = now_ms();
        let mut g = self.lock();
        let q = g.counters.entry(key.to_string()).or_default();
        while q.front().is_some_and(|t| now - t > window_ms) {
            q.pop_front();
        }
        if q.len() >= limit {
            return false;
        }
        q.push_back(now);
        true
    }

    // ---------- grants ----------

    pub fn add_grant(&self, g: Grant) {
        self.lock().grants.push(g);
    }

    pub fn grants(&self) -> Vec<Grant> {
        let mut g = self.lock();
        g.prune();
        g.grants.clone()
    }

    pub fn grants_for(&self, session: &str) -> Vec<Grant> {
        self.grants().into_iter().filter(|g| g.session == session).collect()
    }

    /// The newest active grant of `session` that covers key `key_id`; counts one use.
    pub fn use_grant(&self, session: &str, key_id: &str) -> Option<(Grant, GrantKey)> {
        let mut g = self.lock();
        g.prune();
        let grant = g
            .grants
            .iter_mut()
            .filter(|x| x.session == session)
            .rev()
            .find(|x| x.keys.iter().any(|k| k.id == key_id))?;
        grant.uses += 1;
        let key = grant.keys.iter().find(|k| k.id == key_id)?.clone();
        Some((grant.clone(), key))
    }

    pub fn revoke(&self, grant_id: &str) -> Option<Grant> {
        let mut g = self.lock();
        let pos = g.grants.iter().position(|x| x.id == grant_id)?;
        Some(g.grants.remove(pos))
    }

    /// On vault lock: drop all grants and tickets, deny everything pending.
    pub fn clear_all(&self, why: &str) {
        let mut g = self.lock();
        g.grants.clear();
        g.tickets.clear();
        while let Some(mut p) = g.queue.pop_front() {
            for tx in p.waiters.drain(..) {
                let _ = tx.send(Outcome::Denied(why.to_string()));
            }
        }
    }

    // ---------- approvals ----------

    pub fn has_pending(&self, session: &str) -> bool {
        self.lock().queue.iter().any(|p| p.view.session == session)
    }

    /// Queues a request, or joins the identical one the same session already has waiting.
    pub fn enqueue(&self, view: PendingView, signature: String, tx: oneshot::Sender<Outcome>) -> Enqueue {
        let mut g = self.lock();
        if let Some(p) = g
            .queue
            .iter_mut()
            .find(|p| p.view.session == view.session && p.signature == signature)
        {
            p.waiters.push(tx);
            return Enqueue::Joined;
        }
        if g.queue.iter().any(|p| p.view.session == view.session) {
            return Enqueue::Busy;
        }
        g.queue.push_back(Pending { view, signature, waiters: vec![tx] });
        Enqueue::New
    }

    pub fn queue_len(&self) -> usize {
        self.lock().queue.len()
    }

    pub fn pending(&self) -> Vec<PendingView> {
        self.lock().queue.iter().map(|p| p.view.clone()).collect()
    }

    /// The request on screen. The first call after it reaches the front records when it was shown.
    pub fn current_shown(&self) -> Option<PendingView> {
        let mut g = self.lock();
        let p = g.queue.front_mut()?;
        if p.view.shown_at.is_none() {
            p.view.shown_at = Some(now_ms());
        }
        Some(p.view.clone())
    }

    pub fn front_id(&self) -> Option<String> {
        self.lock().queue.front().map(|p| p.view.id.clone())
    }

    pub fn note_otp_failure(&self, id: &str) -> u32 {
        let mut g = self.lock();
        match g.queue.iter_mut().find(|p| p.view.id == id) {
            Some(p) => {
                p.view.otp_failures += 1;
                p.view.otp_failures
            }
            None => 0,
        }
    }

    /// Removes request `id` and resolves it.
    pub fn resolve(&self, id: &str, outcome: Outcome) -> Option<PendingView> {
        let mut g = self.lock();
        let pos = g.queue.iter().position(|p| p.view.id == id)?;
        let mut p = g.queue.remove(pos)?;
        // Every waiter — the original request and the ones that joined it — gets the same answer.
        for tx in p.waiters.drain(..) {
            let _ = tx.send(outcome.clone());
        }
        Some(p.view)
    }

    /// Drops a request whose waiters all gave up (timeout).
    pub fn drop_request(&self, id: &str) -> Option<PendingView> {
        let mut g = self.lock();
        let pos = g.queue.iter().position(|p| p.view.id == id)?;
        g.queue.remove(pos).map(|p| p.view)
    }

    // ---------- tickets ----------

    pub fn add_ticket(&self, id: String, t: Ticket) {
        self.lock().tickets.insert(id, t);
    }

    /// One-shot: a ticket can be redeemed once.
    pub fn take_ticket(&self, id: &str) -> Option<Ticket> {
        let mut g = self.lock();
        g.prune();
        g.tickets.remove(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(id: &str, key: &str) -> PendingView {
        PendingView {
            id: id.into(),
            session: "s1".into(),
            client: "c".into(),
            claimed_client: String::new(),
            process: "kh.exe".into(),
            reason: "тест".into(),
            keys: vec![GrantKey { id: key.into(), name: key.into(), mode: Mode::Reveal, tier: Tier::Soft }],
            removed: vec![],
            ttl_minutes: 15,
            level: Tier::Soft,
            created_at: 0,
            shown_at: None,
            otp_failures: 0,
        }
    }

    fn grant() -> Grant {
        Grant {
            id: "g1".into(),
            session: "s1".into(),
            client: "c".into(),
            process: "kh.exe".into(),
            keys: vec![GrantKey { id: "k".into(), name: "k".into(), mode: Mode::Reveal, tier: Tier::Soft }],
            reason: "тест".into(),
            level: Tier::Soft,
            created_at: 0,
            expires_at: now_ms() + 60_000,
            uses: 0,
        }
    }

    #[test]
    fn identical_requests_wait_on_one_decision() {
        let b = Broker::default();
        let (tx1, rx1) = oneshot::channel();
        assert_eq!(b.enqueue(view("a", "k"), "sig".into(), tx1), Enqueue::New);
        let (tx2, rx2) = oneshot::channel();
        assert_eq!(b.enqueue(view("b", "k"), "sig".into(), tx2), Enqueue::Joined);
        assert_eq!(b.queue_len(), 1, "второй одинаковый запрос не создаёт второй окно-запрос");

        b.resolve("a", Outcome::Granted(grant()));
        match rx1.blocking_recv() {
            Ok(Outcome::Granted(g)) => assert_eq!(g.id, "g1"),
            _ => panic!("первый ждавший должен получить разрешение"),
        }
        match rx2.blocking_recv() {
            Ok(Outcome::Granted(g)) => assert_eq!(g.id, "g1"),
            _ => panic!("присоединившийся ждавший должен получить то же разрешение"),
        }
    }

    #[test]
    fn different_request_in_same_session_is_busy() {
        let b = Broker::default();
        let (tx1, _rx1) = oneshot::channel();
        assert_eq!(b.enqueue(view("a", "k1"), "sig1".into(), tx1), Enqueue::New);
        let (tx2, _rx2) = oneshot::channel();
        assert_eq!(b.enqueue(view("b", "k2"), "sig2".into(), tx2), Enqueue::Busy);
        assert_eq!(b.queue_len(), 1);
    }

    #[test]
    fn closing_the_session_denies_every_waiter() {
        let b = Broker::default();
        let (tx1, rx1) = oneshot::channel();
        b.enqueue(view("a", "k"), "sig".into(), tx1);
        let (tx2, rx2) = oneshot::channel();
        b.enqueue(view("b", "k"), "sig".into(), tx2);
        b.end_session("s1");
        for rx in [rx1, rx2] {
            match rx.blocking_recv() {
                Ok(Outcome::Denied(_)) => {}
                _ => panic!("оба ждавших должны получить отказ"),
            }
        }
        assert_eq!(b.queue_len(), 0);
    }
}

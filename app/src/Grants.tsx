import { useEffect, useState } from "react";
import { api, errText, left, type Grant, type PendingView, type SessionInfo } from "./api";
import { TierPill } from "./ui";

export function GrantsPage({ data, reload }: { data: { pending: PendingView[]; active: Grant[]; sessions: SessionInfo[] }; reload: () => void }) {
  const [, tick] = useState(0);
  const [error, setError] = useState("");
  useEffect(() => {
    const t = setInterval(() => tick((x) => x + 1), 1000);
    return () => clearInterval(t);
  }, []);
  const act = (p: Promise<unknown>) => p.then(reload).catch((e) => setError(errText(e)));
  const now = Date.now();

  return (
    <>
      <div className="col" style={{ gap: 4 }}>
        <h1>Разрешения</h1>
        <p className="muted">Агент получает только ключи из одобренного списка и только на время разрешения. Всё остальное — отказ.</p>
      </div>
      {error && <p className="error">{error}</p>}

      <section className="col">
        <h2>
          В очереди <span className="muted" style={{ fontWeight: 500 }}>{data.pending.length}</span>
        </h2>
        {data.pending.length === 0 && <p className="muted small">Запросов нет.</p>}
        <div className="grid-cards">
          {data.pending.map((p, i) => (
            <div key={p.id} className="card pad col" style={{ borderColor: p.level === "otp" ? "var(--warn-line)" : undefined }}>
              <div className="row">
                <span className="grow" style={{ fontWeight: 600 }}>
                  {p.client} · {p.keys.length} {p.keys.length === 1 ? "ключ" : "ключа"}
                </span>
                <TierPill tier={p.level} />
              </div>
              <span className="small muted">«{p.reason}» · ждёт {Math.round((now - p.createdAt) / 1000)} с</span>
              <div className="row wrap" style={{ gap: 6 }}>
                {p.keys.map((k) => (
                  <span key={k.id} className="chip mono">
                    {k.name} · {k.mode}
                  </span>
                ))}
              </div>
              <div className="row">
                {i === 0 && (
                  <button className="btn primary sm" onClick={() => act(api.showApproval())}>
                    Открыть окно
                  </button>
                )}
                <button className="btn sm" onClick={() => act(api.denyRequest(p.id))}>
                  Отклонить
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="col">
        <h2>
          Активные <span className="muted" style={{ fontWeight: 500 }}>{data.active.length}</span>
        </h2>
        {data.active.length === 0 && <p className="muted small">Сейчас ни у одного агента нет доступа.</p>}
        <div className="grid-cards">
          {data.active.map((g) => {
            const total = g.expiresAt - g.createdAt;
            const pct = Math.max(0, Math.min(100, ((g.expiresAt - now) / total) * 100));
            return (
              <div key={g.id} className="card pad col" style={{ gap: 12 }}>
                <div className="col" style={{ gap: 2 }}>
                  <div className="row">
                    <span className="grow" style={{ fontWeight: 600 }}>
                      {g.client}
                    </span>
                    <TierPill tier={g.level} />
                  </div>
                  <span className="small muted mono ellipsis" title={g.process}>
                    {g.process || "процесс неизвестен"}
                  </span>
                </div>
                <div className="row wrap" style={{ gap: 6 }}>
                  {g.keys.map((k) => (
                    <span key={k.id} className="chip mono">
                      {k.name} · {k.mode}
                    </span>
                  ))}
                </div>
                <span className="small" style={{ color: "var(--ink-2)" }}>
                  «{g.reason}»
                </span>
                <div className="col" style={{ gap: 6 }}>
                  <div className="row small" style={{ justifyContent: "space-between", color: "var(--ink-2)" }}>
                    <span>Осталось {left(g.expiresAt)}</span>
                    <span>{g.uses} обращ.</span>
                  </div>
                  <div className="progress" aria-hidden="true">
                    <div style={{ width: `${pct}%` }} />
                  </div>
                </div>
                <button className="btn sm danger" style={{ alignSelf: "flex-start" }} onClick={() => act(api.revokeGrant(g.id))}>
                  Отозвать
                </button>
              </div>
            );
          })}
        </div>
      </section>

      <section className="col">
        <h2>
          Подключённые агенты <span className="muted" style={{ fontWeight: 500 }}>{data.sessions.length}</span>
        </h2>
        {data.sessions.length === 0 && <p className="muted small">Ни один агент сейчас не подключён.</p>}
        {data.sessions.length > 0 && (
          <div className="card">
            {data.sessions.map((s, i) => (
              <div key={s.id} className="row" style={{ padding: "12px 16px", borderTop: i ? "1px solid var(--line-soft)" : undefined }}>
                <div className="col grow" style={{ gap: 2 }}>
                  <span style={{ fontWeight: 600 }}>
                    {s.client === "—" ? "клиент не определён" : s.client}
                    {s.claimedClient && <span className="muted small" style={{ fontWeight: 400 }}> · называет себя {s.claimedClient}</span>}
                  </span>
                  <span className="small muted mono ellipsis">{s.process || s.id}</span>
                </div>
                {s.blockedUntil > now ? (
                  <>
                    <span className="pill danger">заблокирован {left(s.blockedUntil)}</span>
                    <button className="btn sm" onClick={() => act(api.unblockSession(s.id))}>
                      Снять
                    </button>
                  </>
                ) : (
                  <span className="pill ok">на связи</span>
                )}
              </div>
            ))}
          </div>
        )}
      </section>
    </>
  );
}

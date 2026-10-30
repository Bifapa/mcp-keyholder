import { useCallback, useEffect, useState } from "react";
import { api, errText, timeOf, type ChainStatus, type LogEntry } from "./api";
import { Icon } from "./ui";

const ACTION: Record<string, string> = {
  setup: "vault created",
  unlock: "unlock",
  lock: "lock",
  add_key: "key added",
  edit_key: "key edited",
  rotate_key: "value replaced",
  delete_key: "key deleted",
  import: "import",
  list_secrets: "key list",
  request_grant: "access request",
  grant: "grant issued",
  deny: "denied by you",
  revoke_grant: "grant revoked",
  access: "access",
  get_secret: "value given",
  prepare_run: "kh run ticket",
  kh_run: "kh run",
  report_leak: "leak reported",
  leak_found: "leak found",
  exposed: "value exposed",
  check_leak: "text check",
  dismiss_leak: "leak mark cleared",
  stepup: "step-up",
  reveal_ui: "value shown",
  copy_ui: "value copied",
  add_client: "client added",
  revoke_client: "client revoked",
  block_client: "client blocked",
  unblock_client: "client unblocked",
  otp: "OTP code",
  otp_lockout: "code entry blocked",
  settings: "settings",
};

function outcomeClass(o: string) {
  if (["ok", "granted", "auto", "clean"].includes(o)) return "ok";
  if (["denied", "leaked", "found", "bad_code", "locked"].includes(o)) return "danger";
  return "warn";
}

export function LogPage({ refreshKey }: { refreshKey: number }) {
  const [rows, setRows] = useState<LogEntry[]>([]);
  const [chain, setChain] = useState<ChainStatus | null>(null);
  const [q, setQ] = useState("");
  const [more, setMore] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const r = await api.listLog(200, null);
      setRows(r);
      setMore(r.length === 200);
      setChain(await api.verifyLog());
    } catch (e) {
      setError(errText(e));
    }
  }, []);
  useEffect(() => {
    load();
  }, [load, refreshKey]);

  const loadMore = async () => {
    const last = rows[rows.length - 1];
    if (!last) return;
    const r = await api.listLog(200, last.seq);
    setRows((x) => [...x, ...r]);
    setMore(r.length === 200);
  };

  const ql = q.trim().toLowerCase();
  const shown = ql ? rows.filter((r) => [r.client, r.target, r.action, ACTION[r.action] ?? "", r.outcome, r.detail].join(" ").toLowerCase().includes(ql)) : rows;

  return (
    <>
      <div className="head">
        <div className="col" style={{ gap: 4 }}>
          <h1>Log</h1>
          <p className="muted">Who used which keys, when and why. Each entry is signed and chained to the previous one.</p>
        </div>
        {chain && (
          <span className={`pill ${chain.ok ? "ok" : "danger"}`} style={{ padding: "6px 12px" }}>
            {chain.ok ? Icon.check(14) : "!"} {chain.ok ? `Chain intact · ${chain.entries} ${chain.entries === 1 ? "entry" : "entries"}` : `Log broken: ${chain.message} (entry ${chain.firstBadSeq})`}
          </span>
        )}
      </div>
      <div className="row wrap">
        <label className="search">
          {Icon.search(16)}
          <span className="sr-only">Filter</span>
          <input type="search" placeholder="Filter: client, key, action, result" value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
        <button className="btn outline" onClick={load}>
          Refresh and verify
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      <div className="card" style={{ overflowX: "auto" }}>
        <div style={{ minWidth: 860 }}>
          <div className="row small muted" style={{ display: "grid", gridTemplateColumns: "150px 130px minmax(160px,1fr) 170px 110px minmax(160px,1.2fr)", gap: 12, padding: "12px 16px", fontWeight: 600 }}>
            <span>Time</span>
            <span>Client</span>
            <span>Key</span>
            <span>Action</span>
            <span>Result</span>
            <span>Details</span>
          </div>
          {shown.map((r) => (
            <div key={r.seq} style={{ display: "grid", gridTemplateColumns: "150px 130px minmax(160px,1fr) 170px 110px minmax(160px,1.2fr)", gap: 12, padding: "9px 16px", borderTop: "1px solid var(--line-soft)", alignItems: "center" }}>
              <span className="mono small muted">{timeOf(r.ts)}</span>
              <span className="small ellipsis">{r.client}</span>
              <span className="mono small ellipsis" title={r.target}>
                {r.target}
              </span>
              <span className="small" style={{ color: "var(--ink-2)" }}>
                {ACTION[r.action] ?? r.action}
              </span>
              <span>
                <span className={`pill ${outcomeClass(r.outcome)}`}>{r.outcome}</span>
              </span>
              <span className="small muted" style={{ overflowWrap: "anywhere" }}>
                {r.detail}
              </span>
            </div>
          ))}
          {shown.length === 0 && <div className="empty">No entries</div>}
        </div>
      </div>
      {more && !ql && (
        <button className="btn outline" style={{ alignSelf: "center" }} onClick={loadMore}>
          Show more
        </button>
      )}
    </>
  );
}

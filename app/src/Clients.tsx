import { useState } from "react";
import { ago, api, errText, type Client } from "./api";
import { useStepUp } from "./stepup";
import { Icon, Modal } from "./ui";

export function ClientsPage({ clients, reload, khPath }: { clients: Client[]; reload: () => void; khPath: string }) {
  const stepup = useStepUp();
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("claude-code");
  const [created, setCreated] = useState<{ token: string; configJson: string; claudeCommand: string; name: string } | null>(null);
  const [error, setError] = useState("");

  const add = async () => {
    setError("");
    try {
      const r = await stepup(() => api.addClient(name.trim().toLowerCase()));
      if (!r) return;
      setCreated({ token: r.token, configJson: r.configJson, claudeCommand: r.claudeCommand, name: r.client.name });
      setAdding(false);
      reload();
    } catch (e) {
      setError(errText(e));
    }
  };
  const act = async (fn: () => Promise<unknown>) => {
    setError("");
    try {
      await stepup(fn);
      reload();
    } catch (e) {
      setError(errText(e));
    }
  };

  return (
    <>
      <div className="head">
        <div className="col" style={{ gap: 4 }}>
          <h1>Clients</h1>
          <p className="muted">Each agent connects with its own token, so the log knows who made each request.</p>
        </div>
        <button className="btn primary" onClick={() => setAdding(true)}>
          {Icon.plus(16)} Add client
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      <div className="card">
        {clients.length === 0 && <div className="empty">No clients yet. Add the first one — for example, claude-code.</div>}
        {clients.map((c, i) => (
          <div key={c.id} className="row wrap" style={{ padding: "12px 16px", borderTop: i ? "1px solid var(--line-soft)" : undefined }}>
            <div className="col grow" style={{ gap: 2 }}>
              <span className="mono" style={{ fontWeight: 600 }}>
                {c.name}
              </span>
              <span className="small muted">
                created {ago(c.createdAt)} · last seen {ago(c.lastSeenAt)}
              </span>
            </div>
            {c.revoked ? (
              <span className="pill off">revoked</span>
            ) : c.blocked ? (
              <>
                <span className="pill danger">blocked</span>
                <button className="btn sm" onClick={() => act(() => api.unblockClient(c.id))}>
                  Unblock
                </button>
              </>
            ) : (
              <span className="pill ok">active</span>
            )}
            {!c.revoked && (
              <button className="btn sm danger" onClick={() => confirm(`Revoke the token for “${c.name}”?`) && act(() => api.revokeClient(c.id))}>
                Revoke
              </button>
            )}
          </div>
        ))}
      </div>

      <div className="card pad col">
        <h2>How to connect an agent</h2>
        <ol className="col small" style={{ margin: 0, paddingLeft: 20, gap: 6, color: "var(--ink-2)" }}>
          <li>Click “Add client” and confirm with your password and code.</li>
          <li>Copy the command for Claude Code or the JSON for another MCP client. The token is shown only once.</li>
          <li>Restart the agent. It will see the tools list_secrets, request_grant, get_secret, prepare_run, report_leak, check_leak.</li>
        </ol>
        <span className="small muted">
          kh: <span className="mono">{khPath}</span>
        </span>
      </div>

      {adding && (
        <Modal
          title="New client"
          onClose={() => setAdding(false)}
          footer={
            <>
              <button className="btn" onClick={() => setAdding(false)}>
                Cancel
              </button>
              <button className="btn primary" disabled={!name.trim()} onClick={add}>
                Create token
              </button>
            </>
          }
        >
          <label className="field">
            Client name
            <input className="input mono" value={name} onChange={(e) => setName(e.target.value.toLowerCase())} placeholder="claude-code" />
            <span className="hint">For example: claude-code, cursor, claude-desktop. Latin letters, digits, . _ / -</span>
          </label>
        </Modal>
      )}
      {created && (
        <Modal wide title={`Client “${created.name}” created`} onClose={() => setCreated(null)} footer={<button className="btn primary" onClick={() => setCreated(null)}>Done</button>}>
          <p className="banner warn small" style={{ padding: "10px 14px" }}>
            The token is shown only once. It gives no access to keys by itself — it only signs the agent's requests.
          </p>
          <CopyBlock label="Claude Code (run in a terminal)" text={created.claudeCommand} />
          <CopyBlock label="JSON for mcp.json / other clients" text={created.configJson} />
        </Modal>
      )}
    </>
  );
}

function CopyBlock({ label, text }: { label: string; text: string }) {
  const [done, setDone] = useState(false);
  return (
    <div className="col" style={{ gap: 6 }}>
      <div className="row">
        <span className="grow" style={{ fontWeight: 600, fontSize: 13, color: "var(--ink-2)" }}>
          {label}
        </span>
        <button
          className="btn sm outline"
          onClick={async () => {
            await navigator.clipboard.writeText(text).catch(() => {});
            setDone(true);
            setTimeout(() => setDone(false), 1500);
          }}
        >
          {done ? Icon.check(15) : Icon.copy(15)} {done ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="raw mono" style={{ lineHeight: 1.6, margin: 0, userSelect: "all" }}>
        {text}
      </pre>
    </div>
  );
}

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
          <h1>Клиенты</h1>
          <p className="muted">Каждый агент подключается со своим токеном — так журнал знает, кто обращался.</p>
        </div>
        <button className="btn primary" onClick={() => setAdding(true)}>
          {Icon.plus(16)} Добавить клиента
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      <div className="card">
        {clients.length === 0 && <div className="empty">Клиентов пока нет. Добавьте первый — например, claude-code.</div>}
        {clients.map((c, i) => (
          <div key={c.id} className="row wrap" style={{ padding: "12px 16px", borderTop: i ? "1px solid var(--line-soft)" : undefined }}>
            <div className="col grow" style={{ gap: 2 }}>
              <span className="mono" style={{ fontWeight: 600 }}>
                {c.name}
              </span>
              <span className="small muted">
                создан {ago(c.createdAt)} · последний раз на связи {ago(c.lastSeenAt)}
              </span>
            </div>
            {c.revoked ? (
              <span className="pill off">отозван</span>
            ) : c.blocked ? (
              <>
                <span className="pill danger">заблокирован</span>
                <button className="btn sm" onClick={() => act(() => api.unblockClient(c.id))}>
                  Снять блокировку
                </button>
              </>
            ) : (
              <span className="pill ok">активен</span>
            )}
            {!c.revoked && (
              <button className="btn sm danger" onClick={() => confirm(`Отозвать токен «${c.name}»?`) && act(() => api.revokeClient(c.id))}>
                Отозвать
              </button>
            )}
          </div>
        ))}
      </div>

      <div className="card pad col">
        <h2>Как подключить агента</h2>
        <ol className="col small" style={{ margin: 0, paddingLeft: 20, gap: 6, color: "var(--ink-2)" }}>
          <li>Нажмите «Добавить клиента» и подтвердите паролем и кодом.</li>
          <li>Скопируйте команду для Claude Code или JSON для другого MCP-клиента. Токен показывается один раз.</li>
          <li>Перезапустите агента. Он увидит инструменты list_secrets, request_grant, get_secret, prepare_run, report_leak, check_leak.</li>
        </ol>
        <span className="small muted">
          kh: <span className="mono">{khPath}</span>
        </span>
      </div>

      {adding && (
        <Modal
          title="Новый клиент"
          onClose={() => setAdding(false)}
          footer={
            <>
              <button className="btn" onClick={() => setAdding(false)}>
                Отмена
              </button>
              <button className="btn primary" disabled={!name.trim()} onClick={add}>
                Создать токен
              </button>
            </>
          }
        >
          <label className="field">
            Имя клиента
            <input className="input mono" value={name} onChange={(e) => setName(e.target.value.toLowerCase())} placeholder="claude-code" />
            <span className="hint">Например: claude-code, cursor, claude-desktop. Латиница, цифры, . _ / -</span>
          </label>
        </Modal>
      )}
      {created && (
        <Modal wide title={`Клиент «${created.name}» создан`} onClose={() => setCreated(null)} footer={<button className="btn primary" onClick={() => setCreated(null)}>Готово</button>}>
          <p className="banner warn small" style={{ padding: "10px 14px" }}>
            Токен показывается один раз. Он не даёт доступа к ключам сам по себе — только подписывает запросы агента.
          </p>
          <CopyBlock label="Claude Code (выполнить в терминале)" text={created.claudeCommand} />
          <CopyBlock label="JSON для mcp.json / других клиентов" text={created.configJson} />
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
          {done ? Icon.check(15) : Icon.copy(15)} {done ? "Скопировано" : "Скопировать"}
        </button>
      </div>
      <pre className="raw mono" style={{ lineHeight: 1.6, margin: 0, userSelect: "all" }}>
        {text}
      </pre>
    </div>
  );
}

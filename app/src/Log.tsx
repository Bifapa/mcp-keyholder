import { useCallback, useEffect, useState } from "react";
import { api, errText, timeOf, type ChainStatus, type LogEntry } from "./api";
import { Icon } from "./ui";

const ACTION: Record<string, string> = {
  setup: "создание хранилища",
  unlock: "разблокировка",
  lock: "блокировка",
  add_key: "ключ добавлен",
  edit_key: "ключ изменён",
  rotate_key: "значение заменено",
  delete_key: "ключ удалён",
  import: "импорт",
  list_secrets: "список ключей",
  request_grant: "запрос доступа",
  grant: "разрешение выдано",
  deny: "отказ человека",
  revoke_grant: "разрешение отозвано",
  access: "обращение",
  get_secret: "выдача значения",
  prepare_run: "билет kh run",
  kh_run: "kh run",
  report_leak: "сообщение об утечке",
  leak_found: "утечка найдена",
  exposed: "значение раскрыто",
  check_leak: "проверка текста",
  dismiss_leak: "отметка снята",
  stepup: "повышение прав",
  reveal_ui: "показ значения",
  copy_ui: "копирование значения",
  add_client: "клиент добавлен",
  revoke_client: "клиент отозван",
  block_client: "клиент заблокирован",
  unblock_client: "клиент разблокирован",
  otp: "код OTP",
  otp_lockout: "ввод кодов закрыт",
  settings: "настройки",
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
          <h1>Журнал</h1>
          <p className="muted">Кто, когда и зачем обращался к ключам. Каждая запись подписана и связана с предыдущей.</p>
        </div>
        {chain && (
          <span className={`pill ${chain.ok ? "ok" : "danger"}`} style={{ padding: "6px 12px" }}>
            {chain.ok ? Icon.check(14) : "!"} {chain.ok ? `Цепочка цела · ${chain.entries} записей` : `Журнал нарушен: ${chain.message} (запись ${chain.firstBadSeq})`}
          </span>
        )}
      </div>
      <div className="row wrap">
        <label className="search">
          {Icon.search(16)}
          <span className="sr-only">Фильтр</span>
          <input type="search" placeholder="Фильтр: клиент, ключ, действие, результат" value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
        <button className="btn outline" onClick={load}>
          Обновить и проверить
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      <div className="card" style={{ overflowX: "auto" }}>
        <div style={{ minWidth: 860 }}>
          <div className="row small muted" style={{ display: "grid", gridTemplateColumns: "150px 130px minmax(160px,1fr) 170px 110px minmax(160px,1.2fr)", gap: 12, padding: "12px 16px", fontWeight: 600 }}>
            <span>Время</span>
            <span>Клиент</span>
            <span>Ключ</span>
            <span>Действие</span>
            <span>Результат</span>
            <span>Детали</span>
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
          {shown.length === 0 && <div className="empty">Записей нет</div>}
        </div>
      </div>
      {more && !ql && (
        <button className="btn outline" style={{ alignSelf: "center" }} onClick={loadMore}>
          Показать ещё
        </button>
      )}
    </>
  );
}

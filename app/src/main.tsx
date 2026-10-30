import { StrictMode, useCallback, useEffect, useState, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { api, applyTheme, errText, getTheme, onChanged, type AppStatus, type Client, type Grant, type PendingView, type SecretMeta, type SessionInfo } from "./api";
import { Login, Setup, Unlock } from "./Auth";
import { ClientsPage } from "./Clients";
import { GrantsPage } from "./Grants";
import { ImportPage } from "./Import";
import { KeysPage } from "./Keys";
import { LogPage } from "./Log";
import { SettingsPage } from "./SettingsPage";
import { StepUpProvider } from "./stepup";
import { UpdateBanner } from "./updates";
import { ErrorBoundary, Icon } from "./ui";
import logoUrl from "./assets/logo.svg";
import "./styles.css";

type Page = "keys" | "grants" | "clients" | "log" | "import" | "settings";

applyTheme(getTheme());
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => applyTheme(getTheme()));

function App() {
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [page, setPage] = useState<Page>("keys");
  const [keys, setKeys] = useState<SecretMeta[]>([]);
  const [groups, setGroups] = useState<string[]>([]);
  const [grants, setGrants] = useState<{ pending: PendingView[]; active: Grant[]; sessions: SessionInfo[] }>({ pending: [], active: [], sessions: [] });
  const [clients, setClients] = useState<Client[]>([]);
  const [logKey, setLogKey] = useState(0);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const s = await api.status();
      setStatus(s);
      if (!s.unlocked) return;
      const [k, g, c] = await Promise.all([api.listKeys(), api.listGrants(), api.listClients()]);
      setKeys(k.keys);
      setGroups(k.groups);
      setGrants(g);
      setClients(c);
      setLogKey((x) => x + 1);
      setError("");
    } catch (e) {
      setError(errText(e));
    }
  }, []);

  useEffect(() => {
    refresh();
    const un = onChanged(() => refresh());
    const t = setInterval(refresh, 30_000);
    return () => {
      un.then((f) => f());
      clearInterval(t);
    };
  }, [refresh]);

  if (!status) return null;
  if (status.error) {
    return (
      <div className="center-screen">
        <div className="auth-card">
          <h1 style={{ fontSize: 21 }}>MCP Keyholder не может связаться со службой</h1>
          <p className="muted">{status.error}</p>
          <p className="muted small">
            Пока служба не отвечает, портативное хранилище не открывается: иначе рядом появилась бы вторая, пустая копия. Запустите
            службу (services.msc → MCP Keyholder) и перезапустите приложение.
          </p>
          <button className="btn primary" onClick={refresh}>
            Повторить
          </button>
        </div>
      </div>
    );
  }
  if (!status.initialized) return <Setup onDone={refresh} />;
  if (!status.unlocked) return <Unlock onDone={refresh} otpLockedUntil={status.otpLockedUntil} />;
  if (status.uiLocked) return <Login mode={status.loginMode} onDone={refresh} />;

  const leaked = keys.filter((k) => k.leak).length;
  const nav: { id: Page; label: string; icon: ReactNode; count?: number; badge?: number }[] = [
    { id: "keys", label: "Ключи", icon: Icon.key(), count: keys.length, badge: leaked || undefined },
    { id: "grants", label: "Разрешения", icon: Icon.shield(), badge: grants.pending.length || undefined, count: grants.active.length || undefined },
    { id: "clients", label: "Клиенты", icon: Icon.monitor(), count: clients.filter((c) => !c.revoked).length },
    { id: "log", label: "Журнал", icon: Icon.list() },
    { id: "import", label: "Импорт", icon: Icon.download() },
    { id: "settings", label: "Настройки", icon: Icon.gear() },
  ];

  return (
    <StepUpProvider elevatedUntil={status.elevatedUntil}>
      <div className="shell">
        <nav className="side" aria-label="Разделы">
          <div className="brand">
            <img className="logo-img" src={logoUrl} alt="" />
            MCP Keyholder
          </div>
          <div className="nav">
            {nav.map((n) => (
              <button key={n.id} aria-current={page === n.id ? "page" : undefined} onClick={() => setPage(n.id)}>
                {n.icon}
                <span className="label">{n.label}</span>
                {n.badge ? <span className="badge">{n.badge}</span> : n.count !== undefined ? <span className="count">{n.count}</span> : null}
              </button>
            ))}
          </div>
          <div className="side-card">
            <div className="row small" style={{ fontWeight: 600, gap: 8 }}>
              <span className="dot" aria-hidden="true" />
              Хранилище открыто
            </div>
            <span className="small muted">
              Режим: {status.runtime === "service" ? "служба" : "портативный"} · агентов на связи: {grants.sessions.length}
            </span>
            <button className="btn sm" onClick={() => api.lock().then(refresh)}>
              {Icon.lock(15)} Заблокировать
            </button>
          </div>
        </nav>
        <main className="main">
          <UpdateBanner service={status.runtime === "service"} />
          {status.pipeAlarm && (
            <div className="banner leak" role="alert">
              <span className="bang" aria-hidden="true">
                !
              </span>
              <span className="grow small">{status.pipeAlarm}</span>
            </div>
          )}
          {error && <p className="error">{error}</p>}
          {page === "keys" && <KeysPage keys={keys} groups={groups} reload={refresh} goImport={() => setPage("import")} />}
          {page === "grants" && <GrantsPage data={grants} reload={refresh} />}
          {page === "clients" && <ClientsPage clients={clients} reload={refresh} khPath={status.khPath} />}
          {page === "log" && <LogPage refreshKey={logKey} />}
          {page === "import" && <ImportPage existing={keys.map((k) => k.name)} onDone={refresh} />}
          {page === "settings" && <SettingsPage status={status} />}
        </main>
      </div>
    </StepUpProvider>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </StrictMode>,
);

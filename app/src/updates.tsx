import { useEffect, useState } from "react";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { errText } from "./api";

// Updates come as signed installers from the public releases repository. The signature is
// checked against the key built into the app, so only builds signed by us install.
// Offline, or before the first release, a check simply finds nothing.

const AUTO_KEY = "kh-auto-update";
const EVERY_MS = 6 * 60 * 60 * 1000;

export function autoUpdateOn(): boolean {
  try {
    return localStorage.getItem(AUTO_KEY) !== "off";
  } catch {
    return true;
  }
}

export function setAutoUpdate(on: boolean) {
  try {
    localStorage.setItem(AUTO_KEY, on ? "on" : "off");
  } catch {
    // Not remembered; checks stay as they were.
  }
}

/** Downloads, verifies and runs the installer, then restarts (on Windows the installer does). */
export async function installUpdate(u: Update, onProgress: (pct: number | null) => void) {
  let total = 0;
  let got = 0;
  await u.downloadAndInstall((e) => {
    if (e.event === "Started") total = e.data.contentLength ?? 0;
    if (e.event === "Progress") {
      got += e.data.chunkLength;
      onProgress(total ? Math.min(100, Math.round((got * 100) / total)) : null);
    }
  });
  await relaunch();
}

function UpdateAction({ update, service }: { update: Update; service: boolean }) {
  const [pct, setPct] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const go = async () => {
    setBusy(true);
    setError("");
    try {
      await installUpdate(update, setPct);
    } catch (e) {
      setError(errText(e));
      setBusy(false);
    }
  };
  return (
    <>
      <button className="btn primary sm" disabled={busy} onClick={go}>
        {busy ? (pct === null ? "Загружаю…" : `Загружаю… ${pct}%`) : "Обновить и перезапустить"}
      </button>
      {service && <span className="small muted">Службу после обновления переустановите: «Настройки» → «Режим службы».</span>}
      {error && <span className="error">{error}</span>}
    </>
  );
}

/** Top-of-window notice when a newer version is out. */
export function UpdateBanner({ service }: { service: boolean }) {
  const [update, setUpdate] = useState<Update | null>(null);
  useEffect(() => {
    if (!autoUpdateOn()) return;
    let alive = true;
    const run = () =>
      check()
        .then((u) => alive && u && setUpdate(u))
        .catch(() => {});
    run();
    const t = setInterval(run, EVERY_MS);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);
  if (!update) return null;
  return (
    <div className="banner info" role="status">
      <span className="grow small">
        <b>Доступна версия {update.version}</b> · что нового — в CHANGELOG на странице релиза
      </span>
      <UpdateAction update={update} service={service} />
    </div>
  );
}

/** Settings: automatic checks on/off and a manual check. */
export function UpdateSettings({ version, service }: { version: string; service: boolean }) {
  const [auto, setAuto] = useState(autoUpdateOn());
  const [update, setUpdate] = useState<Update | null>(null);
  const [state, setState] = useState("");
  const [busy, setBusy] = useState(false);
  const checkNow = async () => {
    setBusy(true);
    setState("");
    setUpdate(null);
    try {
      const u = await check();
      if (u) setUpdate(u);
      else setState(`Установлена последняя версия (${version})`);
    } catch (e) {
      setState(`Не удалось проверить: ${errText(e)}`);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="col" style={{ gap: 10 }}>
      <label className="row small">
        <input
          type="checkbox"
          checked={auto}
          onChange={(e) => {
            setAuto(e.target.checked);
            setAutoUpdate(e.target.checked);
          }}
        />
        Проверять обновления автоматически (раз в 6 часов, без интернета — молча пропускается)
      </label>
      <div className="row wrap">
        <button className="btn sm" disabled={busy} onClick={checkNow}>
          {busy ? "Проверяю…" : "Проверить обновления"}
        </button>
        {update ? (
          <>
            <span className="small">
              <b>Доступна версия {update.version}</b>
            </span>
            <UpdateAction update={update} service={service} />
          </>
        ) : (
          state && <span className="small muted">{state}</span>
        )}
      </div>
    </div>
  );
}

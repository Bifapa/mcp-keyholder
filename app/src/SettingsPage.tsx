import { useEffect, useState, type ChangeEvent } from "react";
import {
  api,
  applyTheme,
  errText,
  getTheme,
  type AppStatus,
  type LoginMode,
  type Preset,
  type Settings,
  type Theme,
} from "./api";
import { useElevation, useStepUp } from "./stepup";
import { Icon, LockedButton, PasswordInput, Segmented, useSecondsLeft } from "./ui";
import { DEFAULT_NOISE_COLORS, NoiseWord, reducedMotion } from "./noiseword";
import { UpdateSettings } from "./updates";
import { exportVault, VaultFileImport } from "./vaultfile";

/** Changes the core accepts only after a step-up; mirrors `set_settings` in the core. */
function confirmReasons(a: Settings, b: Settings): string[] {
  const r: string[] = [];
  if (b.autolockMinutes > a.autolockMinutes) r.push("auto-lock made longer");
  if (b.maxTtlMinutes > a.maxTtlMinutes) r.push("maximum duration made longer");
  if (a.secureDesktop && !b.secureDesktop) r.push("separate desktop turned off");
  if (b.anchorPath && b.anchorPath !== a.anchorPath) r.push("new anchor file");
  if (b.fullLock !== a.fullLock) r.push("full lock changed");
  if (a.noiseWord && !b.noiseWord) r.push("noise word turned off");
  return r;
}

function Done({ text }: { text: string }) {
  if (!text) return null;
  return (
    <span className="ok-note" role="status">
      {Icon.check(15)} {text}
    </span>
  );
}

/** What the lock on buttons means, and how long the current confirmation lasts. */
function ConfirmLegend() {
  const { until, end } = useElevation();
  const left = useSecondsLeft(until);
  const time = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
  return (
    <div className={`confirm-legend ${left > 0 ? "on" : ""}`}>
      <span className="lock-badge">{left > 0 ? Icon.check(16) : Icon.lock(16)}</span>
      <div className="col grow" style={{ gap: 2 }}>
        <span style={{ fontWeight: 600 }}>
          {left > 0 ? `Confirmed — ${time} left` : "Buttons with a lock ask for your master password and code"}
        </span>
        <span className="small">
          {left > 0
            ? "While the countdown runs, actions with a lock go through without asking again."
            : "You enter the password and authenticator code once, in a separate MCP Keyholder window. After that, settings can be changed for 3 minutes without entering them again."}
        </span>
      </div>
      {left > 0 && (
        <button className="btn sm outline" onClick={end}>
          End now
        </button>
      )}
    </div>
  );
}

export function SettingsPage({ status }: { status: AppStatus }) {
  const stepup = useStepUp();
  const [theme, setTheme] = useState<Theme>(getTheme());
  const [orig, setOrig] = useState<Settings | null>(null);
  const [s, setS] = useState<Settings | null>(null);
  const [note, setNote] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .getSettings()
      .then((v) => {
        setOrig(v);
        setS(v);
      })
      .catch((e) => setError(errText(e)));
  }, []);

  const edit = (patch: Partial<Settings>) => {
    if (!s) return;
    setNote("");
    setS({ ...s, ...patch });
  };

  const save = async () => {
    if (!s) return;
    setError("");
    setNote("");
    try {
      const r = await stepup(() => api.setSettings(s).then(() => true));
      if (r) {
        setOrig(s);
        setNote("Saved");
      }
    } catch (e) {
      setError(errText(e));
    }
  };

  const num = (k: keyof Settings) => (e: ChangeEvent<HTMLInputElement>) =>
    edit({ [k]: Math.max(1, parseInt(e.target.value || "0", 10) || 1) } as Partial<Settings>);

  const service = status.runtime === "service";
  const dirty = !!s && !!orig && JSON.stringify(s) !== JSON.stringify(orig);
  const reasons = s && orig ? confirmReasons(orig, s) : [];

  return (
    <>
      <h1>Settings</h1>
      <ConfirmLegend />
      <div className="card pad col" style={{ gap: 14 }}>
        <h2>Appearance</h2>
        <Segmented<Theme>
          label="Theme"
          value={theme}
          onChange={(t) => {
            setTheme(t);
            applyTheme(t);
          }}
          options={[
            { id: "system", label: "System" },
            { id: "light", label: "Light" },
            { id: "dark", label: "Dark" },
          ]}
        />
      </div>
      {s && (
        <div className="card pad col" style={{ gap: 14 }}>
          <h2>Protection</h2>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 12 }}>
            <label className="field">
              Auto-lock, minutes
              <input className="input" type="number" min={1} max={1440} value={s.autolockMinutes} onChange={num("autolockMinutes")} />
            </label>
            <label className="field">
              Default grant duration, minutes
              <input className="input" type="number" min={1} value={s.defaultTtlMinutes} onChange={num("defaultTtlMinutes")} />
            </label>
            <label className="field">
              Maximum duration, minutes
              <input className="input" type="number" min={1} value={s.maxTtlMinutes} onChange={num("maxTtlMinutes")} />
            </label>
          </div>
          <label className="row small">
            <input type="checkbox" checked={s.disableOnLeakReport} onChange={(e) => edit({ disableOnLeakReport: e.target.checked })} />
            Disable a key when an agent reports a leak
          </label>
          {status.platform !== "macos" && (
          <label className="row small">
            <input
              type="checkbox"
              checked={s.secureDesktop}
              disabled={!status.desktopAvailable}
              onChange={(e) => edit({ secureDesktop: e.target.checked })}
            />
            Confirm PIN, OTP and password on a separate Windows desktop
          </label>
          )}
          <NoiseOption
            on={s.noiseWord}
            colors={s.noiseColors?.length ? s.noiseColors : DEFAULT_NOISE_COLORS}
            onChange={(v) => edit({ noiseWord: v })}
            onColors={(c) => edit({ noiseColors: c })}
          />
          <label className="field">
            Log anchor: file for the chain head (empty — off)
            <input
              className="input mono"
              placeholder="D:\backup\keyholder-anchor.txt"
              value={s.anchorPath}
              onChange={(e) => edit({ anchorPath: e.target.value })}
            />
            <span className="hint">Each entry is a line with a number and a hash. If the database is rolled back, the anchor will show it.</span>
          </label>
          {service && (
            <>
              <div className="col" style={{ gap: 6 }}>
                <span className="field-title">Interface sign-in {Icon.lock(13)}</span>
                <Segmented<LoginMode>
                  label="Interface sign-in"
                  value={s.loginMode}
                  onChange={async (m) => {
                    if (m === s.loginMode) return;
                    setError("");
                    setNote("");
                    try {
                      const r = await stepup(() => api.setLoginMode(m).then(() => true));
                      if (!r) return;
                      setS({ ...s, loginMode: m });
                      setOrig((o) => (o ? { ...o, loginMode: m } : o));
                      setNote("Sign-in method changed");
                    } catch (e) {
                      setError(errText(e));
                    }
                  }}
                  options={[
                    { id: "nothing", label: "Nothing" },
                    { id: "pin", label: "PIN" },
                    { id: "otp", label: "OTP" },
                    { id: "password", label: "Password" },
                  ]}
                />
                <span className="hint">Applies at once. The service keeps the vault keys itself (DPAPI), so sign-in can be short.</span>
              </div>
              <label className="row small">
                <input type="checkbox" checked={s.fullLock} onChange={(e) => edit({ fullLock: e.target.checked })} />
                Full lock: on auto-lock the service forgets the keys until the master password is entered
              </label>
            </>
          )}
          <p className="hint">
            Tightening applies right away. Loosening protection — longer durations, turning off the separate desktop, a new anchor file —
            is saved after you confirm with your password and code.
          </p>
          <div className="row wrap">
            {reasons.length > 0 ? (
              <LockedButton className="primary" disabled={!dirty} onClick={save}>
                Save
              </LockedButton>
            ) : (
              <button className="btn primary" disabled={!dirty} onClick={save}>
                Save
              </button>
            )}
            <button className="btn" onClick={() => api.anchorNow().then(() => setNote("Anchor written"), (e) => setError(errText(e)))}>
              Write anchor now
            </button>
            {dirty ? (
              <span className="small muted">
                {reasons.length > 0 ? `Needs confirmation: ${reasons.join(", ")}` : "Unsaved changes"}
              </span>
            ) : (
              <Done text={note} />
            )}
          </div>
          {error && <p className="error">{error}</p>}
        </div>
      )}
      <PinCard hasPin={status.hasPin} />
      <PasswordCard />
      <WordCard />
      <TotpCard />
      <TransferCard />
      <PresetsCard />
      {status.platform !== "macos" && <ServiceCard status={status} />}
      <div className="card pad col">
        <h2>About</h2>
        <dl className="fact" style={{ gridTemplateColumns: "160px 1fr", margin: 0 }}>
          <dt>Version</dt>
          <dd>{status.version} · {service ? "service mode" : "portable mode"}</dd>
          <dt>Vault</dt>
          <dd className="mono small">{status.vaultPath}</dd>
          <dt>Data</dt>
          <dd className="mono small">{status.dataDir}</dd>
          <dt>kh (for agents)</dt>
          <dd className="mono small">{status.khPath}</dd>
        </dl>
        <UpdateSettings version={status.version} service={service} />
        <p className="hint">
          Portable mode protects against an agent that uses MCP, files and windows. Service mode protects against a program that
          deliberately reads MCP Keyholder's memory: the core runs under a separate account. Details: CONCEPT.md, section 11.
        </p>
      </div>
    </>
  );
}

/** Ready-made palettes for the noise word: 2, 3 and 4 greys, and a few colours. */
const NOISE_PRESETS: { name: string; colors: string[] }[] = [
  { name: "Black & white", colors: ["#000000", "#ffffff"] },
  { name: "3 greys", colors: ["#000000", "#808080", "#ffffff"] },
  { name: "4 greys", colors: DEFAULT_NOISE_COLORS },
  { name: "Purple", colors: ["#140f26", "#4a3a9c", "#8f78f0", "#e6defd"] },
  { name: "Amber", colors: ["#1a1000", "#7a4a00", "#e09a20", "#ffe2a8"] },
  { name: "Green", colors: ["#001400", "#0a5a0a", "#2fbf2f", "#b9ffb9"] },
];

function Swatches({ colors }: { colors: string[] }) {
  return (
    <span className="swatches" aria-hidden="true">
      {colors.map((c, i) => (
        <span key={i} style={{ background: c }} />
      ))}
    </span>
  );
}

/** The noise-word option, off by default, offered with palettes and a live demo on a sample word. */
function NoiseOption({
  on,
  colors,
  onChange,
  onColors,
}: {
  on: boolean;
  colors: string[];
  onChange: (v: boolean) => void;
  onColors: (c: string[]) => void;
}) {
  const [demo, setDemo] = useState(false);
  const same = (a: string[], b: string[]) => a.length === b.length && a.every((c, i) => c.toLowerCase() === b[i].toLowerCase());
  const setColor = (i: number, c: string) => onColors(colors.map((x, j) => (j === i ? c : x)));
  return (
    <div className="sub-panel col" style={{ gap: 10 }}>
      <label className="row small">
        <input type="checkbox" checked={on} onChange={(e) => onChange(e.target.checked)} />
        Show the anti-phishing word as moving noise
      </label>
      <span className="hint">
        The word is drawn with drifting noise: you read it in motion, while a screenshot or any single captured frame shows only
        noise. Approval windows are already hidden from screen capture; this also covers captures that get around that.
      </span>
      <div className="col" style={{ gap: 6 }}>
        <span className="field-title">Colours</span>
        <div className="row wrap" style={{ gap: 6 }}>
          {NOISE_PRESETS.map((p) => (
            <button key={p.name} type="button" className={`btn sm ${same(p.colors, colors) ? "outline selected" : "outline"}`} onClick={() => onColors(p.colors)}>
              <Swatches colors={p.colors} /> {p.name}
            </button>
          ))}
        </div>
        <div className="row wrap" style={{ gap: 8 }}>
          {colors.map((c, i) => (
            <span key={i} className="color-pick">
              <input type="color" value={c} aria-label={`Colour ${i + 1}`} onChange={(e) => setColor(i, e.target.value)} />
              {colors.length > 2 && (
                <button type="button" className="link" aria-label={`Remove colour ${i + 1}`} onClick={() => onColors(colors.filter((_, j) => j !== i))}>
                  ×
                </button>
              )}
            </span>
          ))}
          {colors.length < 6 && (
            <button type="button" className="link" onClick={() => onColors([...colors, "#808080"])}>
              + Add colour
            </button>
          )}
        </div>
        <span className="hint">2 to 6 colours; each cell of the noise takes one at random. Colours far apart read best.</span>
      </div>
      <button className="link" style={{ alignSelf: "flex-start" }} onClick={() => setDemo((v) => !v)} aria-expanded={demo}>
        {demo ? "Hide the demo" : "Show a demo"}
      </button>
      {demo &&
        (reducedMotion() ? (
          <span className="hint">Animations are off in Windows, so the demo can't play — without motion the word can't be read.</span>
        ) : (
          <div className="antiphish-block">
            <span className="small muted">Demo — the word here is “sample”, not yours</span>
            <NoiseWord word="sample" height={112} colors={colors} />
          </div>
        ))}
    </div>
  );
}

function PresetsCard() {
  const [list, setList] = useState<Preset[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    api.listPresets().then(setList).catch((e) => setError(errText(e)));
  }, []);
  return (
    <div className="card pad col" style={{ gap: 12 }}>
      <h2>Grant presets</h2>
      <p className="muted small">
        A set of keys and a duration that an agent can request by one name: <span className="mono">request_grant({"{ preset }"})</span>.
        A preset is saved with a button in the approval window, and a person still has to approve every request.
      </p>
      {list.length === 0 && !error && <p className="muted small">No presets yet.</p>}
      {list.map((p) => (
        <div key={p.name} className="row" style={{ justifyContent: "space-between" }}>
          <span className="mono">{p.name}</span>
          <span className="muted small grow">
            {p.keys.join(", ")} · {p.ttlMinutes} min
          </span>
          <button className="link" onClick={() => api.deletePreset(p.name).then(setList, (e) => setError(errText(e)))}>
            Delete
          </button>
        </div>
      ))}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

function PasswordCard() {
  const stepup = useStepUp();
  const [next, setNext] = useState("");
  const [next2, setNext2] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState("");

  const tooShort = next.length > 0 && next.length < 10;
  const mismatch = next2.length > 0 && next !== next2;
  const ready = next.length >= 10 && next === next2;

  const change = async () => {
    setError("");
    setNote("");
    try {
      const r = await stepup(() => api.changePassword(next).then(() => true));
      if (!r) return;
      setNext("");
      setNext2("");
      setNote("Master password changed");
    } catch (e) {
      setError(errText(e));
    }
  };

  return (
    <div className="card pad col" style={{ gap: 14 }}>
      <h2>Master password</h2>
      <p className="muted small">The password that opens the vault. Changing it leaves the keys themselves in place.</p>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 12 }}>
        <label className="field">
          New password
          <PasswordInput autoComplete="new-password" value={next} onChange={(e) => (setNext(e.target.value), setNote(""))} />
          <span className={`hint ${tooShort ? "bad" : ""}`}>At least 10 characters</span>
        </label>
        <label className="field">
          Repeat new password
          <PasswordInput autoComplete="new-password" value={next2} onChange={(e) => (setNext2(e.target.value), setNote(""))} />
          {mismatch && <span className="hint bad">The passwords don't match</span>}
        </label>
      </div>
      <div className="row wrap">
        <LockedButton disabled={!ready} onClick={change}>
          Change password
        </LockedButton>
        <Done text={note} />
      </div>
      {error && <p className="error">{error}</p>}
    </div>
  );
}

function WordCard() {
  const stepup = useStepUp();
  const [word, setWord] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState("");
  const len = [...word.trim()].length;
  const ready = len >= 3 && len <= 8;

  const change = async () => {
    setError("");
    setNote("");
    try {
      const r = await stepup(() => api.changeAntiphish(word).then(() => true));
      if (!r) return;
      setWord("");
      setNote("Word changed");
    } catch (e) {
      setError(errText(e));
    }
  };

  return (
    <div className="card pad col" style={{ gap: 14 }}>
      <h2>Anti-phishing word</h2>
      <p className="muted small">
        This word is shown in every genuine MCP Keyholder approval window. If a window asks for a password or code and the word is missing
        or different, it is not MCP Keyholder — don't enter anything.
      </p>
      <label className="field" style={{ maxWidth: 360 }}>
        New word
        <input
          className="input"
          maxLength={8}
          value={word}
          onChange={(e) => (setWord(e.target.value), setNote(""))}
          onKeyDown={(e) => e.key === "Enter" && ready && change()}
        />
        <span className={`hint ${word && !ready ? "bad" : ""}`}>3 to 8 characters — short words read best in the noise</span>
      </label>
      <div className="row wrap">
        <LockedButton disabled={!ready} onClick={change}>
          Change word
        </LockedButton>
        <Done text={note} />
      </div>
      {error && <p className="error">{error}</p>}
    </div>
  );
}

function TotpCard() {
  const stepup = useStepUp();
  const [lost, setLost] = useState(false);
  const [password, setPassword] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [qr, setQr] = useState("");
  const [newCode, setNewCode] = useState("");
  const [recovery, setRecovery] = useState<string[]>([]);
  const [note, setNote] = useState("");
  const [error, setError] = useState("");

  const begin = async (viaRecovery: boolean) => {
    setError("");
    setNote("");
    setRecovery([]);
    try {
      const r = await (viaRecovery ? api.recoveryUsed(password, recoveryCode) : stepup(() => api.reissueTotpBegin()));
      if (!r) return;
      setQr(await api.qrSvg(r.otpauthUri));
    } catch (e) {
      setError(errText(e));
    }
  };

  const cancel = async () => {
    setQr("");
    setNewCode("");
    await api.reissueTotpCancel().catch(() => {});
  };

  const finish = async () => {
    setError("");
    try {
      const r = await stepup(() => api.reissueTotpFinish(newCode));
      if (!r) return;
      setRecovery(r.recovery);
      setQr("");
      setNewCode("");
      setPassword("");
      setRecoveryCode("");
      setLost(false);
      setNote("Authenticator reissued");
    } catch (e) {
      setError(errText(e));
    }
  };

  return (
    <div className="card pad col" style={{ gap: 14 }}>
      <h2>Authenticator</h2>
      <p className="muted small">
        Reissue it if you changed your phone or app. Old codes stop working, and you get new recovery codes.
      </p>
      {qr ? (
        <div className="sub-panel col" style={{ gap: 12 }}>
          <span className="small" style={{ fontWeight: 600 }}>
            Scan the QR code with your authenticator app and enter the code it shows
          </span>
          <img className="qr" alt="New QR code for the authenticator app" src={`data:image/svg+xml;utf8,${encodeURIComponent(qr)}`} />
          <label className="field" style={{ maxWidth: 220 }}>
            Code from the new app
            <input
              className="input otp-input mono"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              value={newCode}
              onChange={(e) => setNewCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              onKeyDown={(e) => e.key === "Enter" && newCode.length === 6 && finish()}
            />
          </label>
          <div className="row">
            <button className="btn primary" disabled={newCode.length < 6} onClick={finish}>
              Done
            </button>
            <button className="btn" onClick={cancel}>
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <>
          <div className="row wrap">
            <LockedButton onClick={() => begin(false)} title="Asks for your master password and a code from the current app">
              Reissue
            </LockedButton>
            <button className="link" onClick={() => setLost((v) => !v)} aria-expanded={lost}>
              No access to the old app?
            </button>
            <Done text={note} />
          </div>
          {lost && (
            <div className="sub-panel col" style={{ gap: 12 }}>
              <span className="small muted">
                Use one of the recovery codes you saved during setup. Each code works once.
              </span>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 12 }}>
                <label className="field">
                  Master password
                  <PasswordInput autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
                </label>
                <label className="field">
                  Recovery code
                  <input className="input mono" value={recoveryCode} onChange={(e) => setRecoveryCode(e.target.value.toUpperCase())} />
                </label>
              </div>
              <div className="row">
                <button className="btn" disabled={!password || recoveryCode.length < 8} onClick={() => begin(true)}>
                  Reissue with a recovery code
                </button>
              </div>
            </div>
          )}
        </>
      )}
      {recovery.length > 0 && (
        <div className="col" style={{ gap: 6 }}>
          <span className="small muted">New recovery codes — save them, they won't be shown again:</span>
          <div className="codes mono">
            {recovery.map((c) => (
              <span key={c}>{c}</span>
            ))}
          </div>
        </div>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

function TransferCard() {
  const stepup = useStepUp();
  const [importing, setImporting] = useState(false);
  const [note, setNote] = useState("");
  const [error, setError] = useState("");

  const doExport = async () => {
    setError("");
    setNote("");
    try {
      const r = await exportVault(stepup);
      if (r) setNote(`Saved: ${r.path} (${Math.max(1, Math.round(r.size / 1024))} KB)`);
    } catch (e) {
      setError(errText(e));
    }
  };

  return (
    <div className="card pad col" style={{ gap: 14 }}>
      <h2>Move vault</h2>
      <p className="muted small">
        A <span className="mono">.mcpkey</span> file is the whole vault: keys, agent clients, settings, the log and the
        authenticator. It is encrypted and opens only with the master password that was in effect at export time. Use it to
        move to another computer or as a backup.
      </p>
      <div className="row wrap">
        <LockedButton onClick={doExport}>Export to .mcpkey</LockedButton>
        <button className="btn" onClick={() => setImporting((v) => !v)} aria-expanded={importing}>
          Load from .mcpkey…
        </button>
      </div>
      {note && <Done text={note} />}
      {importing && (
        <div className="sub-panel col" style={{ gap: 12 }}>
          <span className="small">
            <b>The current vault will be replaced</b> with the file's contents. A copy of it stays alongside, in{" "}
            <span className="mono">vault.db.before-import-…</span>, so nothing is lost. After loading, the master password, word and
            authenticator from the file apply. Loading asks for the current vault's password and code, then the file's master
            password.
          </span>
          <VaultFileImport
            run={stepup}
            onDone={(backup) => {
              setImporting(false);
              setNote(backup ? `Vault loaded. The previous one is saved at: ${backup}` : "Vault loaded");
            }}
          />
        </div>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

function ServiceCard({ status }: { status: AppStatus }) {
  const [note, setNote] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const run = async (install: boolean) => {
    setBusy(true);
    setError("");
    setNote("");
    try {
      await (install ? api.installService() : api.uninstallService());
      // On success the app restarts itself in the new mode; reaching here means nothing changed.
      setNote(install ? "Done — MCP Keyholder is restarting." : "Done — MCP Keyholder is restarting.");
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card pad col" style={{ gap: 12 }}>
      <h2>Service mode</h2>
      <p className="muted small">
        In service mode the core runs under a separate account, <span className="mono">NT SERVICE\KeyHolder</span>, and keeps the database in{" "}
        <span className="mono">%ProgramData%\KeyHolder</span>. Processes running as your user can't read the core's memory or the database, or
        replace the service binaries. Administrator rights are needed once; after that the app starts with Windows
        to show approval windows.
      </p>
      {status.runtime === "service" ? (
        <>
          <p className="small">
            Now: <span className="pill otp">service</span> · data in {status.dataDir}
          </p>
          <button className="btn" disabled={busy} onClick={() => run(false)}>
            Turn off service mode
          </button>
        </>
      ) : (
        <button className="btn primary" disabled={busy} onClick={() => run(true)}>
          Turn on service mode
        </button>
      )}
      {note && <span className="muted small">{note}</span>}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

function PinCard({ hasPin }: { hasPin: boolean }) {
  const stepup = useStepUp();
  const [pin, setPin] = useState("");
  const [pin2, setPin2] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState("");
  const mismatch = pin2.length > 0 && pin !== pin2;
  const ready = pin.length >= 4 && pin === pin2;
  const save = async () => {
    setError("");
    setNote("");
    try {
      const r = await stepup(() => api.setPin(pin).then(() => true));
      if (r) {
        setNote(hasPin ? "PIN changed" : "PIN set");
        setPin("");
        setPin2("");
      }
    } catch (e) {
      setError(errText(e));
    }
  };
  const digits = (v: string) => v.replace(/\D/g, "").slice(0, 6);
  return (
    <div className="card pad col" style={{ gap: 14 }}>
      <h2>PIN</h2>
      <p className="muted small">
        A fixed 4–6 digit code for keys at the “PIN” level. Only you know it.{" "}
        {hasPin ? "PIN is set." : "No PIN set yet: until you set one, “PIN” keys are approved with an authenticator code."}
      </p>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(160px, 200px))", gap: 12 }}>
        <label className="field">
          {hasPin ? "New PIN" : "PIN"}
          <input className="input mono" type="password" inputMode="numeric" value={pin} onChange={(e) => (setPin(digits(e.target.value)), setNote(""))} />
          <span className={`hint ${pin && pin.length < 4 ? "bad" : ""}`}>4–6 digits</span>
        </label>
        <label className="field">
          Repeat PIN
          <input className="input mono" type="password" inputMode="numeric" value={pin2} onChange={(e) => (setPin2(digits(e.target.value)), setNote(""))} />
          {mismatch && <span className="hint bad">Doesn't match</span>}
        </label>
      </div>
      <div className="row wrap">
        <LockedButton disabled={!ready} onClick={save}>
          {hasPin ? "Change PIN" : "Set PIN"}
        </LockedButton>
        <Done text={note} />
      </div>
      {error && <p className="error">{error}</p>}
    </div>
  );
}

import { StrictMode, useCallback, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { api, applyTheme, DESKTOP_OFF, errText, getTheme, onChanged, TIER_LABEL, type PendingView, type Tier } from "./api";
import { ErrorBoundary, Icon, TierPill } from "./ui";
import "./styles.css";

applyTheme(getTheme());

const ORDER: Tier[] = ["auto", "soft", "pin", "otp", "sealed"];
const DELAY_MS = 1500;

/** The anti-phishing word is drawn on a canvas: not in the accessibility tree, not selectable text. */
function AntiPhish({ word }: { word: string }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const c = ref.current;
    if (!c) return;
    const dpr = window.devicePixelRatio || 1;
    const css = getComputedStyle(document.documentElement);
    const ctx = c.getContext("2d");
    if (!ctx) return;
    ctx.font = "600 15px 'Segoe UI', system-ui, sans-serif";
    const w = Math.ceil(ctx.measureText(word).width) + 4;
    c.width = w * dpr;
    c.height = 22 * dpr;
    c.style.width = `${w}px`;
    c.style.height = "22px";
    ctx.scale(dpr, dpr);
    ctx.font = "600 15px 'Segoe UI', system-ui, sans-serif";
    ctx.fillStyle = css.getPropertyValue("--accent-soft-ink").trim() || "#4c2bb0";
    ctx.textBaseline = "middle";
    ctx.fillText(word, 2, 11);
  }, [word]);
  return <canvas ref={ref} aria-hidden="true" />;
}

function Approve() {
  const [req, setReq] = useState<PendingView | null>(null);
  const [word, setWord] = useState("");
  const [queue, setQueue] = useState(0);
  const [hasPin, setHasPin] = useState(false);
  const [keep, setKeep] = useState<Set<string>>(new Set());
  const [ttl, setTtl] = useState(60);
  const [code, setCode] = useState("");
  const [manualCode, setManualCode] = useState(false);
  const [hello, setHello] = useState(false);
  const [presetName, setPresetName] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [now, setNow] = useState(Date.now());
  const currentId = useRef<string | null>(null);

  const load = useCallback(async () => {
    try {
      const r = await api.approvalCurrent();
      setWord(r.antiphish);
      setQueue(r.queue);
      setHasPin(r.hasPin);
      setReq(r.request);
      if (r.request && r.request.id !== currentId.current) {
        currentId.current = r.request.id;
        setKeep(new Set(r.request.keys.map((k) => k.name)));
        setTtl(r.request.ttlMinutes);
        setCode("");
        setManualCode(false);
        setError("");
      }
    } catch (e) {
      setError(errText(e));
    }
  }, []);

  useEffect(() => {
    api.helloAvailable().then(setHello, () => setHello(false));
    load();
    const un = onChanged((w) => (w === "approvals" || w === "lock") && load());
    const t = setInterval(() => setNow(Date.now()), 250);
    return () => {
      un.then((f) => f());
      clearInterval(t);
    };
  }, [load]);

  if (!req) {
    return (
      <div className="approve">
        <p className="muted">No requests.</p>
      </div>
    );
  }

  const kept = req.keys.filter((k) => keep.has(k.name));
  const level = kept.reduce<Tier>((m, k) => (ORDER.indexOf(k.tier) > ORDER.indexOf(m) ? k.tier : m), "auto");
  const usePin = level === "pin" && hasPin;
  const needOtp = level === "otp" || (level === "pin" && !hasPin);
  const needCode = usePin || needOtp;
  const shownFor = now - (req.shownAt ?? now);
  const ready = shownFor >= DELAY_MS;
  const ttlOptions = [...new Set([15, 30, 60, 120, 240, req.ttlMinutes])].filter((m) => m <= req.ttlMinutes).sort((a, b) => a - b);

  const decide = async (approve: boolean, block = false) => {
    setBusy(true);
    setError("");
    try {
      if (!approve) {
        await api.approvalDecide({ id: req.id, approve: false, keep: [], ttl_minutes: ttl, code: null, block_session: block });
      } else if (needCode && !manualCode) {
        // `pin`/`otp`: the code is typed on the separate Windows desktop and never passes through this window.
        try {
          await api.approvalNative({ id: req.id, keep: [...keep], ttl_minutes: ttl, block_session: block });
        } catch (e) {
          const m = errText(e);
          if (m === DESKTOP_OFF) {
            setManualCode(true);
            setError("The separate desktop isn't available — enter the code in this window.");
            return;
          }
          throw e;
        }
      } else {
        await api.approvalDecide({
          id: req.id,
          approve: true,
          keep: [...keep],
          ttl_minutes: ttl,
          code: needCode ? code : null,
          block_session: block,
        });
      }
      currentId.current = null;
      await load();
    } catch (e) {
      setError(errText(e));
      setCode("");
      await load();
    } finally {
      setBusy(false);
    }
  };

  const decideHello = async () => {
    setBusy(true);
    setError("");
    try {
      await api.approvalHello({ id: req.id, keep: [...keep], ttl_minutes: ttl, block_session: false });
      currentId.current = null;
      await load();
    } catch (e) {
      setError(errText(e));
      await load();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="approve" onKeyDown={(e) => e.key === "Enter" && e.preventDefault()}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <span className={`pill ${needOtp ? "otp" : usePin ? "pin" : "soft"}`}>
          {needCode ? Icon.lock(13) : Icon.shield(13)} {needOtp ? "OTP code required" : usePin ? "PIN required" : "Approval"}
        </span>
        <span className="row small muted" style={{ gap: 6 }} title="Your anti-phishing word. If it's missing, this is not MCP Keyholder.">
          word: <AntiPhish word={word} />
        </span>
      </div>

      <h1 style={{ fontSize: 19 }}>
        {req.client} asks for {req.keys.length} {req.keys.length === 1 ? "key" : "keys"}
      </h1>

      <dl className="fact" style={{ margin: 0 }}>
        <dt>Client</dt>
        <dd>
          {req.client} <span className="muted small">(by token)</span>
        </dd>
        <dt>Process</dt>
        <dd className="mono small">{req.process || "unknown"}</dd>
        {req.claimedClient && (
          <>
            <dt>Claims to be</dt>
            <dd className="small">
              {req.claimedClient} <span className="muted">· according to the agent</span>
            </dd>
          </>
        )}
      </dl>

      <div style={{ background: "var(--surface-2)", borderRadius: 12, padding: "10px 14px" }}>
        <div className="small muted" style={{ fontWeight: 600 }}>
          Reason · according to the agent
        </div>
        <div style={{ overflowWrap: "anywhere" }}>{req.reason}</div>
      </div>

      <fieldset className="col" style={{ border: 0, margin: 0, padding: 0, gap: 8 }}>
        <legend className="small muted" style={{ fontWeight: 600, padding: 0, marginBottom: 8 }}>
          Keys
        </legend>
        {req.keys.map((k) => (
          <label key={k.id} className="keyrow">
            <input
              type="checkbox"
              checked={keep.has(k.name)}
              onChange={() =>
                setKeep((s) => {
                  const n = new Set(s);
                  if (n.has(k.name)) n.delete(k.name);
                  else n.add(k.name);
                  return n;
                })
              }
            />
            <span className="mono grow ellipsis" style={{ fontWeight: 500 }}>
              {k.name}
            </span>
            <span className="mono small muted">{k.mode}</span>
            <TierPill tier={k.tier} />
          </label>
        ))}
        <div className="row" style={{ gap: 8 }}>
          <input
            className="input"
            style={{ maxWidth: 220 }}
            placeholder="Preset name"
            value={presetName}
            onChange={(e) => setPresetName(e.target.value)}
          />
          <button
            className="btn sm"
            disabled={!presetName.trim() || kept.length === 0}
            onClick={async () => {
              try {
                await api.savePreset(presetName.trim(), kept.map((k) => k.name), ttl);
                setPresetName("");
                setError("");
              } catch (e) {
                setError(errText(e));
              }
            }}
          >
            Save as preset
          </button>
          <span className="small muted">the agent can request it by this name</span>
        </div>
        {req.removed.map((r) => (
          <div key={r.name} className="keyrow removed">
            <span className="mono grow ellipsis" style={{ textDecoration: "line-through" }}>
              {r.name}
            </span>
            <span className="small">{r.why}</span>
          </div>
        ))}
      </fieldset>

      <label className="row small" style={{ color: "var(--ink-2)" }}>
        Duration
        <select className="select" style={{ width: "auto" }} value={ttl} onChange={(e) => setTtl(Number(e.target.value))}>
          {ttlOptions.map((m) => (
            <option key={m} value={m}>
              {m < 60 ? `${m} min` : `${m / 60} h`}
            </option>
          ))}
        </select>
        <span className="muted">· level: {TIER_LABEL[level]}</span>
      </label>

      {needCode && manualCode && (
        <div className="otp-box">
          <label className="field" style={{ color: "var(--ink)" }}>
            {usePin ? "PIN" : "Authenticator code"}
            <input
              className="input otp-input mono"
              type={usePin ? "password" : "text"}
              inputMode="numeric"
              autoComplete={usePin ? "off" : "one-time-code"}
              maxLength={6}
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
            />
          </label>
          <div className="row small" style={{ justifyContent: "space-between", color: "var(--warn-ink)" }}>
            <span>{usePin ? "Don't enter your PIN if you weren't expecting this window." : "One code, one approval. Don't enter a code if you weren't expecting this window."}</span>
            <span style={{ flex: "none" }}>Attempts left: {3 - req.otpFailures}</span>
          </div>
        </div>
      )}

      {error && <p className="error">{error}</p>}

      <div className="col" style={{ marginTop: "auto", gap: 10 }}>
        <div className="row">
          <button className="btn grow" disabled={busy} onClick={() => decide(false)}>
            Deny
          </button>
          <button className="btn primary grow" disabled={busy || !ready || kept.length === 0 || (needCode && manualCode && code.length < (usePin ? 4 : 6))} onClick={() => decide(true)}>
            {ready ? "Allow" : `Allow (${Math.ceil((DELAY_MS - shownFor) / 1000)})`}
          </button>
        </div>
        {needCode && hello && (
          <button className="btn" disabled={busy || !ready || kept.length === 0} onClick={decideHello}>
            Confirm with Windows Hello
          </button>
        )}
        <div className="row" style={{ justifyContent: "space-between" }}>
          <button className="link" disabled={busy} onClick={() => decide(false, true)}>
            Deny and block the session for 10 min
          </button>
          {queue > 1 && <span className="small muted">{queue - 1} more in queue</span>}
        </div>
      </div>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ErrorBoundary>
      <Approve />
    </ErrorBoundary>
  </StrictMode>,
);

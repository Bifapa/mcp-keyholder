import { useState } from "react";
import { api, DESKTOP_OFF, errText, type LoginMode } from "./api";
import logoUrl from "./assets/logo.svg";
import { PasswordInput } from "./ui";
import { VaultFileImport } from "./vaultfile";

function Brand() {
  return (
    <div className="row" style={{ gap: 12 }}>
      <img className="logo-img" src={logoUrl} alt="" style={{ width: 46, height: 46 }} />
      <div className="col" style={{ gap: 0 }}>
        <span style={{ fontSize: 18, fontWeight: 700 }}>MCP Keyholder</span>
        <span className="muted small">keys for agents, under lock</span>
      </div>
    </div>
  );
}

export function Unlock({ onDone, otpLockedUntil }: { onDone: () => void; otpLockedUntil: number | null }) {
  const [password, setPassword] = useState("");
  const [manual, setManual] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  // The password is typed on the separate Windows desktop: nothing reaches this page.
  const native = async () => {
    setBusy(true);
    setError("");
    try {
      await api.unlockNative();
      onDone();
    } catch (e) {
      if (errText(e) === DESKTOP_OFF) setManual(true);
      else setError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const submit = async () => {
    if (!password) return;
    setBusy(true);
    setError("");
    try {
      await api.unlock(password);
      setPassword("");
      onDone();
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="center-screen">
      <div className="auth-card">
        <Brand />
        <div className="col" style={{ gap: 4 }}>
          <h1 style={{ fontSize: 21 }}>Vault locked</h1>
          <p className="muted">
            {manual
              ? "Enter your master password. While the vault is locked, agents get nothing."
              : "You type the master password on a separate Windows desktop: neither the agent nor this window can see it."}
          </p>
        </div>
        {manual ? (
          <label className="field">
            Master password
            <PasswordInput
              autoFocus
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && submit()}
            />
          </label>
        ) : (
          <button className="btn primary" disabled={busy} onClick={native}>
            {busy ? "Unlocking…" : "Unlock"}
          </button>
        )}
        {error && <p className="error">{error}</p>}
        {otpLockedUntil && <p className="error">Code entry is temporarily blocked after several wrong attempts.</p>}
        {manual && (
          <button className="btn primary" disabled={busy || !password} onClick={submit}>
            {busy ? "Unlocking…" : "Unlock"}
          </button>
        )}
        <ResetVault onDone={onDone} />
      </div>
    </div>
  );
}

/** Lost master password: the vault cannot be decrypted, so the only way on is a fresh start. */
function ResetVault({ onDone }: { onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  if (!open) {
    return (
      <p className="muted small">
        Forgot your master password? It can't be recovered — by design.{" "}
        <button className="link" onClick={() => setOpen(true)}>
          Reset vault
        </button>
      </p>
    );
  }
  const reset = async () => {
    setBusy(true);
    setError("");
    try {
      await api.resetVault(confirm);
      onDone();
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="banner leak col" style={{ alignItems: "stretch", gap: 10 }}>
      <span style={{ fontWeight: 600 }}>Reset vault</span>
      <span className="small" style={{ color: "var(--ink-2)" }}>
        All keys, clients and the log will become unavailable: a new empty vault is created, and agents will need new tokens.
        The old file is not deleted — it stays next to the new one, encrypted, and opens with the old password if you remember it.
      </span>
      <label className="field">
        Type RESET
        <input className="input" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />
      </label>
      {error && <p className="error">{error}</p>}
      <div className="row">
        <button className="btn danger" disabled={busy || confirm.trim() !== "RESET"} onClick={reset}>
          {busy ? "Resetting…" : "Reset and start over"}
        </button>
        <button className="btn" onClick={() => (setOpen(false), setConfirm(""), setError(""))}>
          Cancel
        </button>
      </div>
    </div>
  );
}

/** Service mode: the interface is locked; open it with nothing, a PIN or a code. */
export function Login({ mode, onDone }: { mode: LoginMode; onDone: () => void }) {
  const [credential, setCredential] = useState("");
  const [manual, setManual] = useState(mode === "password");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const native = async () => {
    setBusy(true);
    setError("");
    try {
      await api.loginNative();
      onDone();
    } catch (e) {
      if (errText(e) === DESKTOP_OFF) setManual(true);
      else setError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const submit = async () => {
    setBusy(true);
    setError("");
    try {
      await api.login(credential);
      setCredential("");
      onDone();
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const hint =
    mode === "nothing"
      ? "Sign-in without a password: the service keeps the keys for you. Click “Sign in”."
      : mode === "pin"
        ? "Enter your PIN — it is asked for on a separate Windows desktop."
        : mode === "otp"
          ? "You type the authenticator code on a separate Windows desktop."
          : "Enter your master password.";

  return (
    <div className="center-screen">
      <div className="auth-card">
        <Brand />
        <div className="col" style={{ gap: 4 }}>
          <h1 style={{ fontSize: 21 }}>Sign in to MCP Keyholder</h1>
          <p className="muted">{hint}</p>
        </div>
        {manual ? (
          <label className="field">
            {mode === "pin" ? "PIN" : mode === "otp" ? "Authenticator code" : "Master password"}
            {mode === "otp" || mode === "pin" ? (
              <input
                className="input mono"
                type="text"
                inputMode="numeric"
                autoFocus
                autoComplete={mode === "otp" ? "one-time-code" : "off"}
                maxLength={mode === "otp" ? 6 : 64}
                value={credential}
                onChange={(e) => setCredential(e.target.value.replace(/\D/g, ""))}
                onKeyDown={(e) => e.key === "Enter" && submit()}
              />
            ) : (
              <PasswordInput
                autoFocus
                autoComplete="current-password"
                maxLength={64}
                value={credential}
                onChange={(e) => setCredential(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && submit()}
              />
            )}
          </label>
        ) : null}
        {error && <p className="error">{error}</p>}
        {manual ? (
          <button className="btn primary" disabled={busy || (mode !== "nothing" && !credential)} onClick={submit}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
        ) : (
          <button className="btn primary" disabled={busy} onClick={native}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
        )}
      </div>
    </div>
  );
}

export function Setup({ onDone }: { onDone: () => void }) {
  const [step, setStep] = useState<1 | 2>(1);
  const [password, setPassword] = useState("");
  const [password2, setPassword2] = useState("");
  const [word, setWord] = useState("");
  const [qr, setQr] = useState("");
  const [recovery, setRecovery] = useState<string[]>([]);
  const [secretText, setSecretText] = useState("");
  const [saved, setSaved] = useState(false);
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const begin = async () => {
    setError("");
    if (password.length < 10) return setError("The master password must be at least 10 characters.");
    if (password !== password2) return setError("The passwords don't match.");
    if ([...word.trim()].length < 3 || [...word.trim()].length > 8) return setError("The anti-phishing word must be 3 to 8 characters.");
    setBusy(true);
    try {
      const r = await api.setupBegin(password, word);
      setQr(r.qrSvg);
      setRecovery(r.recovery);
      setStep(2);
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const finish = async () => {
    setBusy(true);
    setError("");
    try {
      await api.setupFinish(code);
      setPassword("");
      setPassword2("");
      onDone();
    } catch (e) {
      setError(errText(e) === "wrong code" ? "That code didn't work. Wait for the next code in the app and try again." : errText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="center-screen">
      <div className="auth-card" style={{ maxWidth: step === 2 ? 560 : 460 }}>
        <Brand />
        {step === 1 && (
          <>
            <div className="col" style={{ gap: 4 }}>
              <h1 style={{ fontSize: 21 }}>New vault</h1>
              <p className="muted">
                The master password encrypts all keys. It isn't stored anywhere and can't be recovered.
              </p>
            </div>
            <label className="field">
              Master password (at least 10 characters)
              <PasswordInput autoFocus autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </label>
            <label className="field">
              Repeat password
              <PasswordInput autoComplete="new-password" value={password2} onChange={(e) => setPassword2(e.target.value)} />
            </label>
            <label className="field">
              Anti-phishing word (3 to 8 characters)
              <input className="input" value={word} maxLength={8} onChange={(e) => setWord(e.target.value)} placeholder="e.g. owl" />
              <span className="hint">It appears in every genuine MCP Keyholder approval window. No word — don't enter your code.</span>
            </label>
            {error && <p className="error">{error}</p>}
            <button className="btn primary" disabled={busy} onClick={begin}>
              {busy ? "Preparing…" : "Next"}
            </button>
            <div className="col" style={{ gap: 8, borderTop: "1px solid var(--line)", paddingTop: 14 }}>
              <span className="small muted">Moving from another computer?</span>
              <VaultFileImport label="Move a vault from a .mcpkey file" onDone={() => onDone()} />
            </div>
          </>
        )}
        {step === 2 && (
          <>
            <div className="col" style={{ gap: 4 }}>
              <h1 style={{ fontSize: 21 }}>Connect an authenticator app</h1>
              <p className="muted">
                Scan the QR code with Google Authenticator, Aegis, 1Password or any TOTP app. Its codes approve access to
                important keys — the agent doesn't know them.
              </p>
            </div>
            <img className="qr" alt="QR code for the authenticator app" src={`data:image/svg+xml;utf8,${encodeURIComponent(qr)}`} />
            {secretText ? (
              <p className="mono small" style={{ textAlign: "center", wordBreak: "break-all" }}>
                {secretText}
              </p>
            ) : (
              <button className="link" style={{ alignSelf: "center" }} onClick={async () => setSecretText(await api.setupSecretText())}>
                Won't scan? Show the secret as text
              </button>
            )}
            <div className="col" style={{ gap: 6 }}>
              <h2>Recovery codes</h2>
              <p className="muted small">
                Write them down or print them. Each code works once and is needed if you lose your phone. They won't be shown again.
              </p>
              <div className="codes mono">
                {recovery.map((c) => (
                  <span key={c}>{c}</span>
                ))}
              </div>
              <label className="row small" style={{ fontWeight: 500 }}>
                <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
                I've saved the recovery codes
              </label>
            </div>
            <label className="field">
              Authenticator code
              <input
                className="input otp-input mono"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                onKeyDown={(e) => e.key === "Enter" && saved && code.length === 6 && finish()}
              />
            </label>
            {error && <p className="error">{error}</p>}
            <button className="btn primary" disabled={busy || !saved || code.length < 6} onClick={finish}>
              {busy ? "Creating vault…" : "Create vault"}
            </button>
          </>
        )}
      </div>
    </div>
  );
}

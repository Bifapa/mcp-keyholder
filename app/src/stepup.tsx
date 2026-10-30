import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api, DESKTOP_OFF, errText, STEPUP_REQUIRED } from "./api";
import { Modal, PasswordInput } from "./ui";

type Run = <T>(fn: () => Promise<T>) => Promise<T | undefined>;

const Ctx = createContext<Run>(async (fn) => fn());
const UntilCtx = createContext<{ until: number; end: () => void }>({ until: 0, end: () => {} });

/** Runs an action; if the core answers "stepup_required", asks for master password + code and retries once. */
export function useStepUp(): Run {
  return useContext(Ctx);
}

/** Until when (epoch ms) actions run without asking again, and a way to end that early. */
export function useElevation() {
  return useContext(UntilCtx);
}

export function StepUpProvider({ children, elevatedUntil = 0 }: { children: ReactNode; elevatedUntil?: number }) {
  const [until, setUntil] = useState(elevatedUntil);
  useEffect(() => setUntil(elevatedUntil), [elevatedUntil]);
  const end = useCallback(() => {
    setUntil(0);
    api.endStepup().catch(() => {});
  }, []);
  const [open, setOpen] = useState(false);
  const resolver = useRef<((ok: boolean) => void) | null>(null);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [hello, setHello] = useState(false);

  useEffect(() => {
    api.helloAvailable().then(setHello, () => setHello(false));
  }, []);

  const run: Run = useCallback(async (fn) => {
    try {
      return await fn();
    } catch (e) {
      if (errText(e) !== STEPUP_REQUIRED) throw e;
      // Master password and code are typed on the separate Windows desktop; they never enter this page.
      try {
        setUntil(await api.stepupNative());
        return await fn();
      } catch (native) {
        if (errText(native) !== DESKTOP_OFF) throw native;
      }
      // The desktop is switched off (or unavailable): ask here instead.
      const { promise, resolve } = Promise.withResolvers<boolean>();
      resolver.current = resolve;
      setOpen(true);
      if (!(await promise)) return undefined;
      return await fn();
    }
  }, []);

  const close = (ok: boolean) => {
    setOpen(false);
    setPassword("");
    setCode("");
    resolver.current?.(ok);
    resolver.current = null;
  };

  const submitHello = async () => {
    setBusy(true);
    setError("");
    try {
      setUntil(await api.stepupHello(password));
      close(true);
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const submit = async () => {
    setBusy(true);
    setError("");
    try {
      setUntil(await api.stepup(password, code));
      setPassword("");
      setCode("");
      close(true);
    } catch (e) {
      setError(errText(e) === "stepup_required" ? "Сначала подтвердите пароль и код." : errText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Ctx.Provider value={run}>
      <UntilCtx.Provider value={{ until, end }}>{children}</UntilCtx.Provider>
      {open && (
        <Modal title="Повышение прав" onClose={() => close(false)}>
          <p className="muted small">
            Показ и копирование значений, смена защиты и клиентов требуют мастер-пароль и код из аутентификатора. Права действуют 3 минуты.
          </p>
          <label className="field">
            Мастер-пароль
            <PasswordInput
              autoFocus
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          <label className="field">
            Код из приложения-аутентификатора
            <input
              className="input otp-input mono"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              onKeyDown={(e) => e.key === "Enter" && password && code.length === 6 && submit()}
            />
          </label>
          {error && <p className="error">{error}</p>}
          <div className="row" style={{ justifyContent: "flex-end" }}>
            <button className="btn" onClick={() => close(false)}>
              Отмена
            </button>
            {hello && (
              <button className="btn" disabled={busy || !password} onClick={submitHello} title="Мастер-пароль и Windows Hello вместо кода">
                Windows Hello
              </button>
            )}
            <button className="btn primary" disabled={busy || !password || code.length < 6} onClick={submit}>
              Повысить права
            </button>
          </div>
        </Modal>
      )}
    </Ctx.Provider>
  );
}

export { DESKTOP_OFF };

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
        <span className="muted small">ключи для агентов под замком</span>
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
          <h1 style={{ fontSize: 21 }}>Хранилище заблокировано</h1>
          <p className="muted">
            {manual
              ? "Введите мастер-пароль. Пока хранилище закрыто, агенты не получают ничего."
              : "Мастер-пароль вводится на отдельном рабочем столе Windows: ни агент, ни это окно его не видят."}
          </p>
        </div>
        {manual ? (
          <label className="field">
            Мастер-пароль
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
            {busy ? "Открываю…" : "Разблокировать"}
          </button>
        )}
        {error && <p className="error">{error}</p>}
        {otpLockedUntil && <p className="error">Ввод кодов временно закрыт после нескольких ошибок.</p>}
        {manual && (
          <button className="btn primary" disabled={busy || !password} onClick={submit}>
            {busy ? "Открываю…" : "Разблокировать"}
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
        Забыли мастер-пароль? Восстановить его нельзя — так задумано.{" "}
        <button className="link" onClick={() => setOpen(true)}>
          Сбросить хранилище
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
      <span style={{ fontWeight: 600 }}>Сброс хранилища</span>
      <span className="small" style={{ color: "var(--ink-2)" }}>
        Все ключи, клиенты и журнал станут недоступны: будет создано новое пустое хранилище, а агентам понадобятся новые токены.
        Старый файл не удаляется — он остаётся рядом в зашифрованном виде и откроется прежним паролем, если вы его вспомните.
      </span>
      <label className="field">
        Введите СБРОСИТЬ
        <input className="input" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />
      </label>
      {error && <p className="error">{error}</p>}
      <div className="row">
        <button className="btn danger" disabled={busy || confirm.trim() !== "СБРОСИТЬ"} onClick={reset}>
          {busy ? "Сбрасываю…" : "Сбросить и начать заново"}
        </button>
        <button className="btn" onClick={() => (setOpen(false), setConfirm(""), setError(""))}>
          Отмена
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
      ? "Вход без пароля: служба хранит ключи за вас. Нажмите «Войти»."
      : mode === "pin"
        ? "Введите PIN — его спрашивают на отдельном рабочем столе Windows."
        : mode === "otp"
          ? "Код из приложения-аутентификатора вводится на отдельном рабочем столе Windows."
          : "Введите мастер-пароль.";

  return (
    <div className="center-screen">
      <div className="auth-card">
        <Brand />
        <div className="col" style={{ gap: 4 }}>
          <h1 style={{ fontSize: 21 }}>Вход в MCP Keyholder</h1>
          <p className="muted">{hint}</p>
        </div>
        {manual ? (
          <label className="field">
            {mode === "pin" ? "PIN-код" : mode === "otp" ? "Код из приложения" : "Мастер-пароль"}
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
            {busy ? "Вхожу…" : "Войти"}
          </button>
        ) : (
          <button className="btn primary" disabled={busy} onClick={native}>
            {busy ? "Вхожу…" : "Войти"}
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
    if (password.length < 10) return setError("Мастер-пароль — не короче 10 символов.");
    if (password !== password2) return setError("Пароли не совпадают.");
    if (word.trim().length < 3) return setError("Анти-фишинговое слово — от 3 символов.");
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
      setError(errText(e) === "неверный код" ? "Код не подошёл. Подождите следующий код в приложении и попробуйте снова." : errText(e));
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
              <h1 style={{ fontSize: 21 }}>Новое хранилище</h1>
              <p className="muted">
                Мастер-пароль шифрует все ключи. Он нигде не хранится, и восстановить его нельзя.
              </p>
            </div>
            <label className="field">
              Мастер-пароль (от 10 символов)
              <PasswordInput autoFocus autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </label>
            <label className="field">
              Ещё раз
              <PasswordInput autoComplete="new-password" value={password2} onChange={(e) => setPassword2(e.target.value)} />
            </label>
            <label className="field">
              Анти-фишинговое слово
              <input className="input" value={word} maxLength={32} onChange={(e) => setWord(e.target.value)} placeholder="например: сова" />
              <span className="hint">Оно будет в каждом настоящем окне подтверждения MCP Keyholder. Нет слова — не вводите код.</span>
            </label>
            {error && <p className="error">{error}</p>}
            <button className="btn primary" disabled={busy} onClick={begin}>
              {busy ? "Готовлю…" : "Дальше"}
            </button>
            <div className="col" style={{ gap: 8, borderTop: "1px solid var(--line)", paddingTop: 14 }}>
              <span className="small muted">Переезжаете с другого компьютера?</span>
              <VaultFileImport label="Перенести хранилище из файла .mcpkey" onDone={() => onDone()} />
            </div>
          </>
        )}
        {step === 2 && (
          <>
            <div className="col" style={{ gap: 4 }}>
              <h1 style={{ fontSize: 21 }}>Подключите приложение-аутентификатор</h1>
              <p className="muted">
                Отсканируйте QR в Google Authenticator, Aegis, 1Password или любом приложении с TOTP. Коды из него подтверждают
                выдачу важных ключей — агент их не знает.
              </p>
            </div>
            <img className="qr" alt="QR-код для приложения-аутентификатора" src={`data:image/svg+xml;utf8,${encodeURIComponent(qr)}`} />
            {secretText ? (
              <p className="mono small" style={{ textAlign: "center", wordBreak: "break-all" }}>
                {secretText}
              </p>
            ) : (
              <button className="link" style={{ alignSelf: "center" }} onClick={async () => setSecretText(await api.setupSecretText())}>
                Не сканируется? Показать секрет текстом
              </button>
            )}
            <div className="col" style={{ gap: 6 }}>
              <h2>Коды восстановления</h2>
              <p className="muted small">
                Запишите или распечатайте. Каждый код одноразовый и нужен, если потеряете телефон. Больше они показаны не будут.
              </p>
              <div className="codes mono">
                {recovery.map((c) => (
                  <span key={c}>{c}</span>
                ))}
              </div>
              <label className="row small" style={{ fontWeight: 500 }}>
                <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
                Я сохранил коды восстановления
              </label>
            </div>
            <label className="field">
              Код из приложения
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
              {busy ? "Создаю хранилище…" : "Создать хранилище"}
            </button>
          </>
        )}
      </div>
    </div>
  );
}

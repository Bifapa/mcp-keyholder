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
import { UpdateSettings } from "./updates";
import { exportVault, VaultFileImport } from "./vaultfile";

/** Changes the core accepts only after a step-up; mirrors `set_settings` in the core. */
function confirmReasons(a: Settings, b: Settings): string[] {
  const r: string[] = [];
  if (b.autolockMinutes > a.autolockMinutes) r.push("автоблокировка дольше");
  if (b.maxTtlMinutes > a.maxTtlMinutes) r.push("максимальный срок больше");
  if (a.secureDesktop && !b.secureDesktop) r.push("отдельный рабочий стол выключается");
  if (b.anchorPath && b.anchorPath !== a.anchorPath) r.push("новый файл якоря");
  if (b.fullLock !== a.fullLock) r.push("полная блокировка");
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
          {left > 0 ? `Подтверждено — ещё ${time}` : "Кнопки с замком спрашивают мастер-пароль и код"}
        </span>
        <span className="small">
          {left > 0
            ? "Пока идёт отсчёт, действия с замком выполняются без повторного ввода."
            : "Пароль и код из аутентификатора вводятся один раз, в отдельном окне MCP Keyholder. После этого 3 минуты настройки меняются без повторного ввода."}
        </span>
      </div>
      {left > 0 && (
        <button className="btn sm outline" onClick={end}>
          Завершить
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
        setNote("Сохранено");
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
      <h1>Настройки</h1>
      <ConfirmLegend />
      <div className="card pad col" style={{ gap: 14 }}>
        <h2>Оформление</h2>
        <Segmented<Theme>
          label="Тема"
          value={theme}
          onChange={(t) => {
            setTheme(t);
            applyTheme(t);
          }}
          options={[
            { id: "system", label: "Как в системе" },
            { id: "light", label: "Светлая" },
            { id: "dark", label: "Тёмная" },
          ]}
        />
      </div>
      {s && (
        <div className="card pad col" style={{ gap: 14 }}>
          <h2>Защита</h2>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 12 }}>
            <label className="field">
              Автоблокировка, минут
              <input className="input" type="number" min={1} max={1440} value={s.autolockMinutes} onChange={num("autolockMinutes")} />
            </label>
            <label className="field">
              Срок разрешения по умолчанию, минут
              <input className="input" type="number" min={1} value={s.defaultTtlMinutes} onChange={num("defaultTtlMinutes")} />
            </label>
            <label className="field">
              Максимальный срок, минут
              <input className="input" type="number" min={1} value={s.maxTtlMinutes} onChange={num("maxTtlMinutes")} />
            </label>
          </div>
          <label className="row small">
            <input type="checkbox" checked={s.disableOnLeakReport} onChange={(e) => edit({ disableOnLeakReport: e.target.checked })} />
            Отключать ключ, когда агент сообщает об утечке
          </label>
          <label className="row small">
            <input
              type="checkbox"
              checked={s.secureDesktop}
              disabled={!status.desktopAvailable}
              onChange={(e) => edit({ secureDesktop: e.target.checked })}
            />
            Подтверждать PIN, OTP и пароль на отдельном рабочем столе Windows
          </label>
          <label className="field">
            Якорь журнала: файл для головы цепочки (пусто — выключено)
            <input
              className="input mono"
              placeholder="D:\backup\keyholder-anchor.txt"
              value={s.anchorPath}
              onChange={(e) => edit({ anchorPath: e.target.value })}
            />
            <span className="hint">Каждая запись — строка с номером и хэшем. Если база откатится, по якорю это будет видно.</span>
          </label>
          {service && (
            <>
              <div className="col" style={{ gap: 6 }}>
                <span className="field-title">Вход в интерфейс {Icon.lock(13)}</span>
                <Segmented<LoginMode>
                  label="Вход в интерфейс"
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
                      setNote("Способ входа изменён");
                    } catch (e) {
                      setError(errText(e));
                    }
                  }}
                  options={[
                    { id: "nothing", label: "Ничего" },
                    { id: "pin", label: "PIN" },
                    { id: "otp", label: "OTP" },
                    { id: "password", label: "Пароль" },
                  ]}
                />
                <span className="hint">Применяется сразу. Служба хранит ключи хранилища у себя (DPAPI), поэтому вход может быть коротким.</span>
              </div>
              <label className="row small">
                <input type="checkbox" checked={s.fullLock} onChange={(e) => edit({ fullLock: e.target.checked })} />
                Полная блокировка: при автоблокировке служба забывает ключи до ввода мастер-пароля
              </label>
            </>
          )}
          <p className="hint">
            Ужесточать можно сразу. Ослабление защиты — более долгие сроки, выключение отдельного рабочего стола, новый файл якоря —
            сохраняется после подтверждения паролем и кодом.
          </p>
          <div className="row wrap">
            {reasons.length > 0 ? (
              <LockedButton className="primary" disabled={!dirty} onClick={save}>
                Сохранить
              </LockedButton>
            ) : (
              <button className="btn primary" disabled={!dirty} onClick={save}>
                Сохранить
              </button>
            )}
            <button className="btn" onClick={() => api.anchorNow().then(() => setNote("Якорь записан"), (e) => setError(errText(e)))}>
              Записать якорь сейчас
            </button>
            {dirty ? (
              <span className="small muted">
                {reasons.length > 0 ? `Нужно подтверждение: ${reasons.join(", ")}` : "Есть несохранённые изменения"}
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
      <ServiceCard status={status} />
      <div className="card pad col">
        <h2>О программе</h2>
        <dl className="fact" style={{ gridTemplateColumns: "160px 1fr", margin: 0 }}>
          <dt>Версия</dt>
          <dd>{status.version} · {service ? "режим службы" : "портативный режим"}</dd>
          <dt>Хранилище</dt>
          <dd className="mono small">{status.vaultPath}</dd>
          <dt>Данные</dt>
          <dd className="mono small">{status.dataDir}</dd>
          <dt>kh (для агентов)</dt>
          <dd className="mono small">{status.khPath}</dd>
        </dl>
        <UpdateSettings version={status.version} service={service} />
        <p className="hint">
          Портативный режим защищает от агента, который пользуется MCP, файлами и окнами. От программы, которая сознательно читает
          память MCP Keyholder, защищает режим службы: ядро работает под отдельной учётной записью. Подробности — CONCEPT.md, раздел 11.
        </p>
      </div>
    </>
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
      <h2>Пресеты разрешений</h2>
      <p className="muted small">
        Набор ключей и срок, которые агент может запросить одним словом: <span className="mono">request_grant({"{ preset }"})</span>.
        Пресет сохраняется кнопкой в окне подтверждения и всё равно требует подтверждения человека.
      </p>
      {list.length === 0 && !error && <p className="muted small">Пресетов пока нет.</p>}
      {list.map((p) => (
        <div key={p.name} className="row" style={{ justifyContent: "space-between" }}>
          <span className="mono">{p.name}</span>
          <span className="muted small grow">
            {p.keys.join(", ")} · {p.ttlMinutes} мин
          </span>
          <button className="link" onClick={() => api.deletePreset(p.name).then(setList, (e) => setError(errText(e)))}>
            Удалить
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
      setNote("Мастер-пароль изменён");
    } catch (e) {
      setError(errText(e));
    }
  };

  return (
    <div className="card pad col" style={{ gap: 14 }}>
      <h2>Мастер-пароль</h2>
      <p className="muted small">Пароль, которым открывается хранилище. Сами ключи при смене остаются на месте.</p>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 12 }}>
        <label className="field">
          Новый пароль
          <PasswordInput autoComplete="new-password" value={next} onChange={(e) => (setNext(e.target.value), setNote(""))} />
          <span className={`hint ${tooShort ? "bad" : ""}`}>Не короче 10 символов</span>
        </label>
        <label className="field">
          Новый пароль ещё раз
          <PasswordInput autoComplete="new-password" value={next2} onChange={(e) => (setNext2(e.target.value), setNote(""))} />
          {mismatch && <span className="hint bad">Пароли не совпадают</span>}
        </label>
      </div>
      <div className="row wrap">
        <LockedButton disabled={!ready} onClick={change}>
          Сменить пароль
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
  const ready = len >= 3 && len <= 32;

  const change = async () => {
    setError("");
    setNote("");
    try {
      const r = await stepup(() => api.changeAntiphish(word).then(() => true));
      if (!r) return;
      setWord("");
      setNote("Слово изменено");
    } catch (e) {
      setError(errText(e));
    }
  };

  return (
    <div className="card pad col" style={{ gap: 14 }}>
      <h2>Анти-фишинговое слово</h2>
      <p className="muted small">
        Это слово показывается в каждом настоящем окне подтверждения MCP Keyholder. Если окно просит пароль или код, а слова в нём нет
        или оно другое — это не MCP Keyholder, ничего не вводите.
      </p>
      <label className="field" style={{ maxWidth: 360 }}>
        Новое слово
        <input
          className="input"
          maxLength={32}
          value={word}
          onChange={(e) => (setWord(e.target.value), setNote(""))}
          onKeyDown={(e) => e.key === "Enter" && ready && change()}
        />
        <span className={`hint ${word && !ready ? "bad" : ""}`}>От 3 до 32 символов</span>
      </label>
      <div className="row wrap">
        <LockedButton disabled={!ready} onClick={change}>
          Сменить слово
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
      setNote("Аутентификатор перевыпущен");
    } catch (e) {
      setError(errText(e));
    }
  };

  return (
    <div className="card pad col" style={{ gap: 14 }}>
      <h2>Аутентификатор</h2>
      <p className="muted small">
        Перевыпустите, если сменили телефон или приложение. Старые коды перестанут работать, появятся новые коды восстановления.
      </p>
      {qr ? (
        <div className="sub-panel col" style={{ gap: 12 }}>
          <span className="small" style={{ fontWeight: 600 }}>
            Отсканируйте QR в приложении-аутентификаторе и введите код, который оно покажет
          </span>
          <img className="qr" alt="Новый QR для приложения-аутентификатора" src={`data:image/svg+xml;utf8,${encodeURIComponent(qr)}`} />
          <label className="field" style={{ maxWidth: 220 }}>
            Код из нового приложения
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
              Готово
            </button>
            <button className="btn" onClick={cancel}>
              Отмена
            </button>
          </div>
        </div>
      ) : (
        <>
          <div className="row wrap">
            <LockedButton onClick={() => begin(false)} title="Спросит мастер-пароль и код из текущего приложения">
              Перевыпустить
            </LockedButton>
            <button className="link" onClick={() => setLost((v) => !v)} aria-expanded={lost}>
              Нет доступа к старому приложению?
            </button>
            <Done text={note} />
          </div>
          {lost && (
            <div className="sub-panel col" style={{ gap: 12 }}>
              <span className="small muted">
                Подойдёт один из кодов восстановления, сохранённых при настройке. Каждый код срабатывает один раз.
              </span>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 12 }}>
                <label className="field">
                  Мастер-пароль
                  <PasswordInput autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
                </label>
                <label className="field">
                  Код восстановления
                  <input className="input mono" value={recoveryCode} onChange={(e) => setRecoveryCode(e.target.value.toUpperCase())} />
                </label>
              </div>
              <div className="row">
                <button className="btn" disabled={!password || recoveryCode.length < 8} onClick={() => begin(true)}>
                  Перевыпустить по коду восстановления
                </button>
              </div>
            </div>
          )}
        </>
      )}
      {recovery.length > 0 && (
        <div className="col" style={{ gap: 6 }}>
          <span className="small muted">Новые коды восстановления — сохраните их, больше они не покажутся:</span>
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
      if (r) setNote(`Сохранено: ${r.path} (${Math.max(1, Math.round(r.size / 1024))} КБ)`);
    } catch (e) {
      setError(errText(e));
    }
  };

  return (
    <div className="card pad col" style={{ gap: 14 }}>
      <h2>Перенос хранилища</h2>
      <p className="muted small">
        Файл <span className="mono">.mcpkey</span> — всё хранилище целиком: ключи, клиенты агентов, настройки, журнал и
        аутентификатор. Он зашифрован и открывается только мастер-паролем, который действует на момент экспорта. Подходит для
        переезда на другой компьютер и как резервная копия.
      </p>
      <div className="row wrap">
        <LockedButton onClick={doExport}>Экспортировать в .mcpkey</LockedButton>
        <button className="btn" onClick={() => setImporting((v) => !v)} aria-expanded={importing}>
          Загрузить из .mcpkey…
        </button>
      </div>
      {note && <Done text={note} />}
      {importing && (
        <div className="sub-panel col" style={{ gap: 12 }}>
          <span className="small">
            <b>Текущее хранилище будет заменено</b> содержимым файла. Его копия останется рядом, в файле{" "}
            <span className="mono">vault.db.before-import-…</span>, так что ничего не потеряется. После загрузки действуют
            мастер-пароль, слово и аутентификатор из файла. Загрузка спросит пароль и код текущего хранилища, затем мастер-пароль
            файла.
          </span>
          <VaultFileImport
            run={stepup}
            onDone={(backup) => {
              setImporting(false);
              setNote(backup ? `Хранилище загружено. Прежнее сохранено: ${backup}` : "Хранилище загружено");
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
      setNote(install ? "Готово — MCP Keyholder перезапускается." : "Готово — MCP Keyholder перезапускается.");
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card pad col" style={{ gap: 12 }}>
      <h2>Режим службы</h2>
      <p className="muted small">
        В режиме службы ядро работает под отдельной учётной записью <span className="mono">NT SERVICE\KeyHolder</span> и держит базу в{" "}
        <span className="mono">%ProgramData%\KeyHolder</span>. Процессы вашего пользователя не могут прочитать память ядра, базу или
        подменить бинарники службы. Нужны права администратора один раз; приложение после этого запускается вместе с Windows,
        чтобы показывать окна подтверждения.
      </p>
      {status.runtime === "service" ? (
        <>
          <p className="small">
            Сейчас: <span className="pill otp">служба</span> · данные в {status.dataDir}
          </p>
          <button className="btn" disabled={busy} onClick={() => run(false)}>
            Выключить режим службы
          </button>
        </>
      ) : (
        <button className="btn primary" disabled={busy} onClick={() => run(true)}>
          Включить режим службы
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
        setNote(hasPin ? "PIN изменён" : "PIN задан");
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
      <h2>PIN-код</h2>
      <p className="muted small">
        Постоянный код из 4–6 цифр для ключей уровня «PIN». Знаете его только вы.{" "}
        {hasPin ? "PIN задан." : "PIN ещё не задан: пока ключи уровня «PIN» подтверждаются кодом из аутентификатора."}
      </p>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(160px, 200px))", gap: 12 }}>
        <label className="field">
          {hasPin ? "Новый PIN" : "PIN"}
          <input className="input mono" type="password" inputMode="numeric" value={pin} onChange={(e) => (setPin(digits(e.target.value)), setNote(""))} />
          <span className={`hint ${pin && pin.length < 4 ? "bad" : ""}`}>4–6 цифр</span>
        </label>
        <label className="field">
          Ещё раз
          <input className="input mono" type="password" inputMode="numeric" value={pin2} onChange={(e) => (setPin2(digits(e.target.value)), setNote(""))} />
          {mismatch && <span className="hint bad">Не совпадает</span>}
        </label>
      </div>
      <div className="row wrap">
        <LockedButton disabled={!ready} onClick={save}>
          {hasPin ? "Сменить PIN" : "Задать PIN"}
        </LockedButton>
        <Done text={note} />
      </div>
      {error && <p className="error">{error}</p>}
    </div>
  );
}

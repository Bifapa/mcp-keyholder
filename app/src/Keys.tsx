import { useEffect, useMemo, useState } from "react";
import { ago, api, defaultEnvName, errText, MODE_INFO, TIER_HINT, TIER_LABEL, type Mode, type SecretMeta, type Tier } from "./api";
import { useStepUp } from "./stepup";
import { Icon, Modal, ModeText, Segmented, TierPill } from "./ui";

type Filter = "all" | Tier | "leak";
const TIERS: Tier[] = ["auto", "soft", "pin", "otp", "sealed"];
const MODES: Mode[] = ["reveal", "env", "proxy", "sign", "recipe"];

export function KeysPage({ keys, groups, reload, goImport }: { keys: SecretMeta[]; groups: string[]; reload: () => void; goImport: () => void }) {
  const stepup = useStepUp();
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [editing, setEditing] = useState<SecretMeta | "new" | null>(null);
  const [descOpen, setDescOpen] = useState(false);
  const [note, setNote] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    setSel((s) => new Set([...s].filter((id) => keys.some((k) => k.id === id))));
  }, [keys]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return keys.filter((k) => {
      if (filter === "leak" && !k.leak) return false;
      if (filter !== "all" && filter !== "leak" && k.tier !== filter) return false;
      if (!q) return true;
      return k.name.includes(q) || k.description.toLowerCase().includes(q) || k.group.includes(q) || k.tags.some((t) => t.includes(q));
    });
  }, [keys, filter, query]);

  const leaked = keys.filter((k) => k.leak);
  const counts = (f: Filter) => (f === "all" ? keys.length : f === "leak" ? leaked.length : keys.filter((k) => k.tier === f).length);
  const allChecked = visible.length > 0 && visible.every((k) => sel.has(k.id));
  const toggle = (id: string) =>
    setSel((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  const bulk = async (patch: Parameters<typeof api.updateKeys>[1], label: string) => {
    setError("");
    setNote("");
    try {
      const r = await stepup(() => api.updateKeys([...sel], patch));
      if (!r) return;
      setNote(`${label}: изменено ${r.ok}${r.errors.length ? `, ошибок ${r.errors.length}` : ""}`);
      if (r.errors.length) setError(r.errors.join("\n"));
      reload();
    } catch (e) {
      setError(errText(e));
    }
  };

  const remove = async () => {
    if (!confirm(`Удалить ключей: ${sel.size}? Это нельзя отменить.`)) return;
    try {
      const r = await stepup(() => api.deleteKeys([...sel]));
      if (!r) return;
      setSel(new Set());
      setNote(`Удалено: ${r.ok}`);
      reload();
    } catch (e) {
      setError(errText(e));
    }
  };

  const selected = keys.filter((k) => sel.has(k.id));
  const anyDisabled = selected.some((k) => k.status === "disabled");

  return (
    <>
      <div className="head">
        <div className="col" style={{ gap: 4 }}>
          <h1>Ключи</h1>
          <p className="muted">
            {keys.length} {plural(keys.length, "ключ", "ключа", "ключей")} · {groups.length} {plural(groups.length, "группа", "группы", "групп")} · значения зашифрованы
          </p>
        </div>
        <div className="row wrap">
          <button className="btn outline" onClick={goImport}>
            {Icon.download(16)} Импорт
          </button>
          <button className="btn primary" onClick={() => setEditing("new")}>
            {Icon.plus(16)} Добавить ключ
          </button>
        </div>
      </div>

      {leaked.map((k) => (
        <div key={k.id} className="banner leak" role="status">
          <span className="bang" style={{ width: 28, height: 28, fontSize: 16 }} aria-hidden="true">
            !
          </span>
          <div className="grow col" style={{ gap: 2 }}>
            <span style={{ fontWeight: 600 }}>
              <span className="mono">{k.name}</span> помечен как слитый — замените значение
            </span>
            <span className="small" style={{ color: "var(--ink-2)" }}>
              {k.leak!.kind === "reported" ? `${k.leak!.client} сообщил` : `найден в тексте от ${k.leak!.client}`}, {ago(k.leak!.at)}
              {k.leak!.comment && <>: «{k.leak!.comment}»</>} <span className="muted">· со слов агента</span>
            </span>
          </div>
          <button className="btn primary sm" onClick={() => setEditing(k)}>
            Заменить значение
          </button>
          <button
            className="btn outline sm"
            onClick={async () => {
              try {
                await stepup(() => api.dismissLeak(k.id));
                reload();
              } catch (e) {
                setError(errText(e));
              }
            }}
          >
            Снять отметку
          </button>
        </div>
      ))}

      <div className="row wrap" style={{ gap: 12 }}>
        <label className="search">
          {Icon.search(16)}
          <span className="sr-only">Поиск</span>
          <input type="search" placeholder="Поиск по имени, описанию, группе, тегу" value={query} onChange={(e) => setQuery(e.target.value)} />
        </label>
        <Segmented<Filter>
          label="Фильтр"
          value={filter}
          onChange={setFilter}
          options={[
            { id: "all", label: "Все", count: counts("all") },
            ...TIERS.map((t) => ({ id: t as Filter, label: TIER_LABEL[t], count: counts(t) })),
            { id: "leak", label: "Слитые", count: counts("leak") },
          ]}
        />
      </div>

      {sel.size > 0 && (
        <div className="toolbar" role="toolbar" aria-label="Действия с выбранными">
          <span style={{ fontWeight: 600, color: "var(--accent-soft-ink)", marginRight: 6 }}>Выбрано: {sel.size}</span>
          <select
            className="select"
            aria-label="Сменить группу"
            value=""
            onChange={(e) => {
              let g = e.target.value;
              if (g === "__new") g = prompt("Новая группа (латиница, цифры, . _ / -)")?.trim().toLowerCase() ?? "";
              if (g) bulk({ group: g }, "Группа");
            }}
          >
            <option value="">Группа…</option>
            {groups.map((g) => (
              <option key={g} value={g}>
                {g}
              </option>
            ))}
            <option value="__new">Новая группа…</option>
          </select>
          <select className="select" aria-label="Сменить подтверждение" value="" onChange={(e) => e.target.value && bulk({ tier: e.target.value as Tier }, "Подтверждение")}>
            <option value="">Подтверждение…</option>
            {TIERS.map((t) => (
              <option key={t} value={t}>
                {TIER_LABEL[t]}
              </option>
            ))}
          </select>
          <select className="select" aria-label="Сменить режим" value="" onChange={(e) => e.target.value && bulk({ mode: e.target.value as Mode }, "Режим")}>
            <option value="">Режим выдачи…</option>
            {MODES.filter((m) => MODE_INFO[m].available).map((m) => (
              <option key={m} value={m}>
                {m} — {MODE_INFO[m].title}
              </option>
            ))}
          </select>
          <button
            className="btn sm outline"
            onClick={() => {
              const t = prompt("Добавить тег ко всем выбранным")?.trim().toLowerCase();
              if (!t) return;
              (async () => {
                for (const k of selected) await api.updateKeys([k.id], { tags: [...k.tags, t] }).catch(() => {});
                reload();
              })();
            }}
          >
            Тег
          </button>
          <button className="btn sm outline" onClick={() => setDescOpen(true)}>
            Описания…
          </button>
          <button className="btn sm outline" onClick={() => bulk({ status: anyDisabled ? "active" : "disabled" }, anyDisabled ? "Включено" : "Отключено")}>
            {anyDisabled ? "Включить" : "Отключить"}
          </button>
          <button className="btn sm danger" onClick={remove}>
            Удалить
          </button>
          <button className="link" style={{ marginLeft: "auto", color: "var(--accent-soft-ink)" }} onClick={() => setSel(new Set())}>
            Снять выделение
          </button>
        </div>
      )}
      {note && <p className="muted small">{note}</p>}
      {error && <p className="error" style={{ whiteSpace: "pre-line" }}>{error}</p>}

      <div className="card table">
        <div className="tr th">
          <input
            type="checkbox"
            aria-label="Выбрать все"
            checked={allChecked}
            onChange={() => setSel((s) => {
              const n = new Set(s);
              visible.forEach((k) => (allChecked ? n.delete(k.id) : n.add(k.id)));
              return n;
            })}
          />
          <span>Ключ</span>
          <span>Группа</span>
          <span>Подтверждение</span>
          <span>Режим</span>
          <span>Использован</span>
          <span />
        </div>
        {visible.length === 0 && (
          <div className="empty">
            {keys.length === 0 ? (
              <div className="col" style={{ alignItems: "center" }}>
                <span>Хранилище пустое.</span>
                <div className="row">
                  <button className="btn primary sm" onClick={() => setEditing("new")}>
                    Добавить первый ключ
                  </button>
                  <button className="btn outline sm" onClick={goImport}>
                    Импорт из файлов
                  </button>
                </div>
              </div>
            ) : (
              "Ничего не найдено"
            )}
          </div>
        )}
        {visible.map((k) => (
          <div key={k.id} className={`tr clickable ${sel.has(k.id) ? "sel" : ""}`} onClick={() => setEditing(k)}>
            <input type="checkbox" aria-label={`Выбрать ${k.name}`} checked={sel.has(k.id)} onClick={(e) => e.stopPropagation()} onChange={() => toggle(k.id)} />
            <div className="col" style={{ gap: 2, minWidth: 0 }}>
              <span className="row" style={{ gap: 8, minWidth: 0 }}>
                {k.leak && (
                  <span className="bang" role="img" aria-label="Помечен как слитый">
                    !
                  </span>
                )}
                {k.quarantined && <span className="pill danger">целостность!</span>}
                <span className="mono ellipsis" style={{ fontWeight: 500, textDecoration: k.status === "disabled" ? "line-through" : undefined, color: k.status === "disabled" ? "var(--muted)" : undefined }}>
                  {k.name}
                </span>
                {k.exposed && !k.leak && (
                  <span className="pill warn" title="Значение выдавалось агенту в открытом виде (reveal/env)">
                    раскрыт
                  </span>
                )}
              </span>
              <span className="small ellipsis" style={{ color: k.leak ? "var(--danger-fg)" : "var(--muted)" }}>
                {k.description || <i>без описания</i>}
              </span>
            </div>
            <span className="chip mono" style={{ justifySelf: "start" }}>
              {k.group}
            </span>
            <span style={{ justifySelf: "start" }}>
              <TierPill tier={k.tier} off={k.status === "disabled"} />
            </span>
            <ModeText mode={k.mode} sealed={k.tier === "sealed"} />
            <span className="muted small">{ago(k.lastUsedAt)}</span>
            <button className="btn icon ghost" aria-label={`Открыть ${k.name}`} onClick={(e) => (e.stopPropagation(), setEditing(k))}>
              {Icon.more()}
            </button>
          </div>
        ))}
      </div>
      <p className="muted small">
        Значения не показываются в таблице. Посмотреть или скопировать значение можно в карточке ключа после подтверждения паролем и кодом.
      </p>

      {editing && <KeyEditor keyMeta={editing === "new" ? null : editing} groups={groups} onClose={() => setEditing(null)} onSaved={reload} />}
      {descOpen && <DescriptionsModal keys={selected} onClose={() => setDescOpen(false)} onSaved={reload} />}
    </>
  );
}

function plural(n: number, one: string, few: string, many: string) {
  const m10 = n % 10;
  const m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
  return many;
}

function DescriptionsModal({ keys, onClose, onSaved }: { keys: SecretMeta[]; onClose: () => void; onSaved: () => void }) {
  const [vals, setVals] = useState<Record<string, string>>(() => Object.fromEntries(keys.map((k) => [k.id, k.description])));
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setBusy(true);
    for (const k of keys) {
      if (vals[k.id] !== k.description) await api.updateKeys([k.id], { description: vals[k.id] }).catch(() => {});
    }
    setBusy(false);
    onSaved();
    onClose();
  };
  return (
    <Modal
      wide
      title="Описания"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Отмена
          </button>
          <button className="btn primary" disabled={busy} onClick={save}>
            Сохранить
          </button>
        </>
      }
    >
      <p className="muted small">Описание видит агент в list_secrets. Пишите, для чего ключ и какие у него права.</p>
      {keys.map((k) => (
        <label key={k.id} className="field">
          <span className="mono">{k.name}</span>
          <input className="input" value={vals[k.id]} onChange={(e) => setVals((v) => ({ ...v, [k.id]: e.target.value }))} placeholder="Для чего этот ключ" />
        </label>
      ))}
    </Modal>
  );
}

function KeyEditor({ keyMeta, groups, onClose, onSaved }: { keyMeta: SecretMeta | null; groups: string[]; onClose: () => void; onSaved: () => void }) {
  const stepup = useStepUp();
  const isNew = keyMeta === null;
  const [name, setName] = useState(keyMeta?.name ?? "");
  const [group, setGroup] = useState(keyMeta?.group ?? "");
  const [value, setValue] = useState("");
  const [description, setDescription] = useState(keyMeta?.description ?? "");
  const [tags, setTags] = useState((keyMeta?.tags ?? []).join(", "));
  const [tier, setTier] = useState<Tier>(keyMeta?.tier ?? "soft");
  const [mode, setMode] = useState<Mode>(keyMeta?.mode ?? "reveal");
  const [envName, setEnvName] = useState(keyMeta?.envName ?? "");
  const [revealed, setRevealed] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  const tagList = tags.split(",").map((t) => t.trim().toLowerCase()).filter(Boolean);
  const env = envName.trim() || defaultEnvName(name.trim());

  const save = async () => {
    setBusy(true);
    setError("");
    try {
      if (isNew) {
        await api.addKey({ name: name.trim(), value, description, group: group.trim() || "default", tags: tagList, tier, mode, envName: env });
      } else {
        const r = await stepup(() =>
          api.updateKeys([keyMeta.id], {
            name: name.trim() !== keyMeta.name ? name.trim() : undefined,
            group: group.trim() || keyMeta.group,
            description,
            tags: tagList,
            tier,
            mode,
            envName: env,
          }),
        );
        if (!r) return;
        if (r.errors.length) throw new Error(r.errors.join("\n"));
        if (value) {
          const done = await stepup(() => api.replaceValue(keyMeta.id, value));
          if (!done) return;
        }
      }
      onSaved();
      onClose();
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const otpExposed = (tier === "otp" || tier === "pin") && MODE_INFO[mode].available && (mode === "reveal" || mode === "env");

  return (
    <Modal
      title={isNew ? "Новый ключ" : keyMeta.name}
      onClose={onClose}
      footer={
        <>
          {!isNew && (
            <button
              className="btn danger"
              style={{ marginRight: "auto" }}
              onClick={async () => {
                if (!confirm(`Удалить «${keyMeta.name}»?`)) return;
                try {
                  const r = await stepup(() => api.deleteKeys([keyMeta.id]));
                  if (r) {
                    onSaved();
                    onClose();
                  }
                } catch (e) {
                  setError(errText(e));
                }
              }}
            >
              Удалить
            </button>
          )}
          <button className="btn" onClick={onClose}>
            Отмена
          </button>
          <button className="btn primary" disabled={busy || !name.trim() || (isNew && !value)} onClick={save}>
            {busy ? "Сохраняю…" : "Сохранить"}
          </button>
        </>
      }
    >
      <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 12 }}>
        <label className="field">
          Имя
          <input className="input mono" value={name} placeholder="github/pipod-updates" onChange={(e) => setName(e.target.value.toLowerCase())} autoFocus={isNew} />
          {tier === "sealed" ? (
            <span className={`hint ${/[^\p{Ll}\p{Lo}0-9 ._/-]/u.test(name) ? "bad" : ""}`}>{"Любые строчные буквы, цифры, пробел и . _ / -"}</span>
          ) : (
            <span className={`hint ${/[^a-z0-9._/-]/.test(name) ? "bad" : ""}`}>
              {"Латиница, цифры и . _ / -, например personal/mail. Русские имена — у запечатанных ключей"}
            </span>
          )}
        </label>
        <label className="field">
          Группа
          <input className="input mono" list="kh-groups" value={group} placeholder="git" onChange={(e) => setGroup(e.target.value.toLowerCase())} />
          <datalist id="kh-groups">
            {groups.map((g) => (
              <option key={g} value={g} />
            ))}
          </datalist>
        </label>
      </div>
      <label className="field">
        {isNew ? "Значение" : "Новое значение (оставьте пустым, чтобы не менять)"}
        <textarea
          className="textarea mono"
          rows={Math.min(14, Math.max(3, value.split("\n").length + 1))}
          value={value}
          spellCheck={false}
          autoComplete="off"
          placeholder={isNew ? "Ключ, токен или любой текст — например, логин и пароль на отдельных строках" : "••••••••••••"}
          onChange={(e) => setValue(e.target.value)}
        />
        <span className="hint">
          Любой текст до 64 КБ, можно в несколько строк.
          {tier === "sealed" ? " Запечатанный ключ видите только вы — агенты его не получают." : " Если это запись только для вас, выберите ниже уровень «Запечатан»: агенты её не получат."}
        </span>
        {!isNew && keyMeta.leak && <span className="hint" style={{ color: "var(--danger-fg)" }}>Ключ помечен как слитый: замена значения снимет отметку.</span>}
      </label>
      {!isNew && (
        <div className="row wrap">
          <button
            className="btn sm outline"
            onClick={async () => {
              try {
                const v = await stepup(() => api.revealValue(keyMeta.id));
                if (v !== undefined) setRevealed(v);
              } catch (e) {
                setError(errText(e));
              }
            }}
          >
            {Icon.eye(15)} Показать значение
          </button>
          <button
            className="btn sm outline"
            onClick={async () => {
              try {
                const r = await stepup(() => api.copyValue(keyMeta.id).then(() => true));
                if (r) setNote("Скопировано. Буфер очистится через 30 секунд. Пока что его может прочитать любая программа.");
              } catch (e) {
                setError(errText(e));
              }
            }}
          >
            {Icon.copy(15)} Скопировать
          </button>
          <span className="muted small">
            Использован {keyMeta.useCount} раз · {ago(keyMeta.lastUsedAt)}
          </span>
        </div>
      )}
      {revealed !== null && (
        <div className="col" style={{ gap: 6 }}>
          <pre className="raw mono value">{revealed}</pre>
          <button className="link" style={{ alignSelf: "flex-start" }} onClick={() => setRevealed(null)}>
            Скрыть
          </button>
        </div>
      )}
      {note && <p className="muted small">{note}</p>}
      <label className="field">
        {tier === "sealed" ? "Описание (запечатанные ключи агенты не видят)" : "Описание — его видит агент в списке ключей"}
        <input className="input" value={description} placeholder="Для чего ключ и какие у него права" onChange={(e) => setDescription(e.target.value)} />
      </label>
      <label className="field">
        Теги (через запятую)
        <input className="input" value={tags} onChange={(e) => setTags(e.target.value)} />
      </label>
      <div className="col" style={{ gap: 8 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: "var(--ink-2)" }}>Подтверждение при запросе</span>
        <Segmented<Tier> label="Подтверждение" value={tier} onChange={setTier} options={TIERS.map((t) => ({ id: t, label: TIER_LABEL[t] }))} />
        <span className="hint">{TIER_HINT[tier]}</span>
      </div>
      {tier !== "sealed" && (
        <div className="col" style={{ gap: 8 }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: "var(--ink-2)" }}>Как агент получает ключ</span>
          <div role="radiogroup" aria-label="Режим выдачи" className="col" style={{ gap: 6 }}>
            {MODES.map((m) => (
              <button key={m} type="button" role="radio" className="radio-card" aria-checked={mode === m} disabled={!MODE_INFO[m].available} onClick={() => setMode(m)}>
                <span className="radio-dot" />
                <span className="col grow" style={{ gap: 2 }}>
                  <span style={{ fontWeight: 600 }}>
                    {MODE_INFO[m].title} <span className="mono muted small">{m}</span>
                    {!MODE_INFO[m].available && <span className="pill accent" style={{ marginLeft: 8 }}>скоро</span>}
                  </span>
                  <span className="small muted">{MODE_INFO[m].desc}</span>
                </span>
              </button>
            ))}
          </div>
          {mode === "env" && (
            <label className="field">
              Имя переменной окружения
              <input className="input mono" value={envName} placeholder={defaultEnvName(name || "key")} onChange={(e) => setEnvName(e.target.value.toUpperCase())} />
            </label>
          )}
          {otpExposed && (
            <p className="banner warn small" style={{ padding: "10px 14px" }}>
              Ключ с {tier === "pin" ? "PIN" : "OTP"} в режиме {mode}: после подтверждения значение окажется у агента. Режим «заглушка + прокси», где значение не покидает
              MCP Keyholder, появится в следующей версии.
            </p>
          )}
        </div>
      )}
      {error && <p className="error" style={{ whiteSpace: "pre-line" }}>{error}</p>}
    </Modal>
  );
}

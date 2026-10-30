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
      setNote(`${label}: ${r.ok} changed${r.errors.length ? `, ${r.errors.length} failed` : ""}`);
      if (r.errors.length) setError(r.errors.join("\n"));
      reload();
    } catch (e) {
      setError(errText(e));
    }
  };

  const remove = async () => {
    if (!confirm(`Delete ${sel.size} ${plural(sel.size, "key", "keys")}? This can't be undone.`)) return;
    try {
      const r = await stepup(() => api.deleteKeys([...sel]));
      if (!r) return;
      setSel(new Set());
      setNote(`Deleted: ${r.ok}`);
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
          <h1>Keys</h1>
          <p className="muted">
            {keys.length} {plural(keys.length, "key", "keys")} · {groups.length} {plural(groups.length, "group", "groups")} · values are encrypted
          </p>
        </div>
        <div className="row wrap">
          <button className="btn outline" onClick={goImport}>
            {Icon.download(16)} Import
          </button>
          <button className="btn primary" onClick={() => setEditing("new")}>
            {Icon.plus(16)} Add key
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
              <span className="mono">{k.name}</span> is marked as leaked — replace the value
            </span>
            <span className="small" style={{ color: "var(--ink-2)" }}>
              {k.leak!.kind === "reported" ? `reported by ${k.leak!.client}` : `found in text from ${k.leak!.client}`}, {ago(k.leak!.at)}
              {k.leak!.comment && <>: “{k.leak!.comment}”</>} <span className="muted">· according to the agent</span>
            </span>
          </div>
          <button className="btn primary sm" onClick={() => setEditing(k)}>
            Replace value
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
            Clear mark
          </button>
        </div>
      ))}

      <div className="row wrap" style={{ gap: 12 }}>
        <label className="search">
          {Icon.search(16)}
          <span className="sr-only">Search</span>
          <input type="search" placeholder="Search by name, description, group, tag" value={query} onChange={(e) => setQuery(e.target.value)} />
        </label>
        <Segmented<Filter>
          label="Filter"
          value={filter}
          onChange={setFilter}
          options={[
            { id: "all", label: "All", count: counts("all") },
            ...TIERS.map((t) => ({ id: t as Filter, label: TIER_LABEL[t], count: counts(t) })),
            { id: "leak", label: "Leaked", count: counts("leak") },
          ]}
        />
      </div>

      {sel.size > 0 && (
        <div className="toolbar" role="toolbar" aria-label="Actions on selected keys">
          <span style={{ fontWeight: 600, color: "var(--accent-soft-ink)", marginRight: 6 }}>Selected: {sel.size}</span>
          <select
            className="select"
            aria-label="Change group"
            value=""
            onChange={(e) => {
              let g = e.target.value;
              if (g === "__new") g = prompt("New group (Latin letters, digits, . _ / -)")?.trim().toLowerCase() ?? "";
              if (g) bulk({ group: g }, "Group");
            }}
          >
            <option value="">Group…</option>
            {groups.map((g) => (
              <option key={g} value={g}>
                {g}
              </option>
            ))}
            <option value="__new">New group…</option>
          </select>
          <select className="select" aria-label="Change approval level" value="" onChange={(e) => e.target.value && bulk({ tier: e.target.value as Tier }, "Approval")}>
            <option value="">Approval…</option>
            {TIERS.map((t) => (
              <option key={t} value={t}>
                {TIER_LABEL[t]}
              </option>
            ))}
          </select>
          <select className="select" aria-label="Change delivery mode" value="" onChange={(e) => e.target.value && bulk({ mode: e.target.value as Mode }, "Delivery mode")}>
            <option value="">Delivery mode…</option>
            {MODES.filter((m) => MODE_INFO[m].available).map((m) => (
              <option key={m} value={m}>
                {m} — {MODE_INFO[m].title}
              </option>
            ))}
          </select>
          <button
            className="btn sm outline"
            onClick={() => {
              const t = prompt("Add a tag to all selected keys")?.trim().toLowerCase();
              if (!t) return;
              (async () => {
                for (const k of selected) await api.updateKeys([k.id], { tags: [...k.tags, t] }).catch(() => {});
                reload();
              })();
            }}
          >
            Tag
          </button>
          <button className="btn sm outline" onClick={() => setDescOpen(true)}>
            Descriptions…
          </button>
          <button className="btn sm outline" onClick={() => bulk({ status: anyDisabled ? "active" : "disabled" }, anyDisabled ? "Enabled" : "Disabled")}>
            {anyDisabled ? "Enable" : "Disable"}
          </button>
          <button className="btn sm danger" onClick={remove}>
            Delete
          </button>
          <button className="link" style={{ marginLeft: "auto", color: "var(--accent-soft-ink)" }} onClick={() => setSel(new Set())}>
            Clear selection
          </button>
        </div>
      )}
      {note && <p className="muted small">{note}</p>}
      {error && <p className="error" style={{ whiteSpace: "pre-line" }}>{error}</p>}

      <div className="card table">
        <div className="tr th">
          <input
            type="checkbox"
            aria-label="Select all"
            checked={allChecked}
            onChange={() => setSel((s) => {
              const n = new Set(s);
              visible.forEach((k) => (allChecked ? n.delete(k.id) : n.add(k.id)));
              return n;
            })}
          />
          <span>Key</span>
          <span>Group</span>
          <span>Approval</span>
          <span>Mode</span>
          <span>Last used</span>
          <span />
        </div>
        {visible.length === 0 && (
          <div className="empty">
            {keys.length === 0 ? (
              <div className="col" style={{ alignItems: "center" }}>
                <span>The vault is empty.</span>
                <div className="row">
                  <button className="btn primary sm" onClick={() => setEditing("new")}>
                    Add your first key
                  </button>
                  <button className="btn outline sm" onClick={goImport}>
                    Import from files
                  </button>
                </div>
              </div>
            ) : (
              "Nothing found"
            )}
          </div>
        )}
        {visible.map((k) => (
          <div key={k.id} className={`tr clickable ${sel.has(k.id) ? "sel" : ""}`} onClick={() => setEditing(k)}>
            <input type="checkbox" aria-label={`Select ${k.name}`} checked={sel.has(k.id)} onClick={(e) => e.stopPropagation()} onChange={() => toggle(k.id)} />
            <div className="col" style={{ gap: 2, minWidth: 0 }}>
              <span className="row" style={{ gap: 8, minWidth: 0 }}>
                {k.leak && (
                  <span className="bang" role="img" aria-label="Marked as leaked">
                    !
                  </span>
                )}
                {k.quarantined && <span className="pill danger">integrity!</span>}
                <span className="mono ellipsis" style={{ fontWeight: 500, textDecoration: k.status === "disabled" ? "line-through" : undefined, color: k.status === "disabled" ? "var(--muted)" : undefined }}>
                  {k.name}
                </span>
                {k.exposed && !k.leak && (
                  <span className="pill warn" title="The value was given to an agent in plain form (reveal/env)">
                    exposed
                  </span>
                )}
              </span>
              <span className="small ellipsis" style={{ color: k.leak ? "var(--danger-fg)" : "var(--muted)" }}>
                {k.description || <i>no description</i>}
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
            <button className="btn icon ghost" aria-label={`Open ${k.name}`} onClick={(e) => (e.stopPropagation(), setEditing(k))}>
              {Icon.more()}
            </button>
          </div>
        ))}
      </div>
      <p className="muted small">
        Values aren't shown in the table. You can view or copy a value in the key's card after confirming with your password and code.
      </p>

      {editing && <KeyEditor keyMeta={editing === "new" ? null : editing} groups={groups} onClose={() => setEditing(null)} onSaved={reload} />}
      {descOpen && <DescriptionsModal keys={selected} onClose={() => setDescOpen(false)} onSaved={reload} />}
    </>
  );
}

function plural(n: number, one: string, many: string) {
  return n === 1 ? one : many;
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
      title="Descriptions"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary" disabled={busy} onClick={save}>
            Save
          </button>
        </>
      }
    >
      <p className="muted small">Agents see the description in list_secrets. Say what the key is for and what rights it has.</p>
      {keys.map((k) => (
        <label key={k.id} className="field">
          <span className="mono">{k.name}</span>
          <input className="input" value={vals[k.id]} onChange={(e) => setVals((v) => ({ ...v, [k.id]: e.target.value }))} placeholder="What this key is for" />
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
      title={isNew ? "New key" : keyMeta.name}
      onClose={onClose}
      footer={
        <>
          {!isNew && (
            <button
              className="btn danger"
              style={{ marginRight: "auto" }}
              onClick={async () => {
                if (!confirm(`Delete “${keyMeta.name}”?`)) return;
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
              Delete
            </button>
          )}
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary" disabled={busy || !name.trim() || (isNew && !value)} onClick={save}>
            {busy ? "Saving…" : "Save"}
          </button>
        </>
      }
    >
      <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 12 }}>
        <label className="field">
          Name
          <input className="input mono" value={name} placeholder="github/pipod-updates" onChange={(e) => setName(e.target.value.toLowerCase())} autoFocus={isNew} />
          {tier === "sealed" ? (
            <span className={`hint ${/[^\p{Ll}\p{Lo}0-9 ._/-]/u.test(name) ? "bad" : ""}`}>{"Any lowercase letters (any language), digits, space and . _ / -"}</span>
          ) : (
            <span className={`hint ${/[^a-z0-9._/-]/.test(name) ? "bad" : ""}`}>
              {"Latin letters, digits and . _ / -, e.g. personal/mail. Names in other alphabets are for sealed keys"}
            </span>
          )}
        </label>
        <label className="field">
          Group
          <input className="input mono" list="kh-groups" value={group} placeholder="git" onChange={(e) => setGroup(e.target.value.toLowerCase())} />
          <datalist id="kh-groups">
            {groups.map((g) => (
              <option key={g} value={g} />
            ))}
          </datalist>
        </label>
      </div>
      <label className="field">
        {isNew ? "Value" : "New value (leave empty to keep the current one)"}
        <textarea
          className="textarea mono"
          rows={Math.min(14, Math.max(3, value.split("\n").length + 1))}
          value={value}
          spellCheck={false}
          autoComplete="off"
          placeholder={isNew ? "A key, token or any text — e.g. a login and password on separate lines" : "••••••••••••"}
          onChange={(e) => setValue(e.target.value)}
        />
        <span className="hint">
          Any text up to 64 KB, multiple lines allowed.
          {tier === "sealed" ? " Only you can see a sealed key — agents never get it." : " If this entry is just for you, pick the “Sealed” level below: agents won't get it."}
        </span>
        {!isNew && keyMeta.leak && <span className="hint" style={{ color: "var(--danger-fg)" }}>The key is marked as leaked: replacing the value clears the mark.</span>}
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
            {Icon.eye(15)} Show value
          </button>
          <button
            className="btn sm outline"
            onClick={async () => {
              try {
                const r = await stepup(() => api.copyValue(keyMeta.id).then(() => true));
                if (r) setNote("Copied. The clipboard will be cleared in 30 seconds. Until then, any program can read it.");
              } catch (e) {
                setError(errText(e));
              }
            }}
          >
            {Icon.copy(15)} Copy
          </button>
          <span className="muted small">
            Used {keyMeta.useCount} {plural(keyMeta.useCount, "time", "times")} · {ago(keyMeta.lastUsedAt)}
          </span>
        </div>
      )}
      {revealed !== null && (
        <div className="col" style={{ gap: 6 }}>
          <pre className="raw mono value">{revealed}</pre>
          <button className="link" style={{ alignSelf: "flex-start" }} onClick={() => setRevealed(null)}>
            Hide
          </button>
        </div>
      )}
      {note && <p className="muted small">{note}</p>}
      <label className="field">
        {tier === "sealed" ? "Description (agents don't see sealed keys)" : "Description — agents see it in the key list"}
        <input className="input" value={description} placeholder="What the key is for and what rights it has" onChange={(e) => setDescription(e.target.value)} />
      </label>
      <label className="field">
        Tags (comma-separated)
        <input className="input" value={tags} onChange={(e) => setTags(e.target.value)} />
      </label>
      <div className="col" style={{ gap: 8 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: "var(--ink-2)" }}>Approval on request</span>
        <Segmented<Tier> label="Approval level" value={tier} onChange={setTier} options={TIERS.map((t) => ({ id: t, label: TIER_LABEL[t] }))} />
        <span className="hint">{TIER_HINT[tier]}</span>
      </div>
      {tier !== "sealed" && (
        <div className="col" style={{ gap: 8 }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: "var(--ink-2)" }}>How the agent gets the key</span>
          <div role="radiogroup" aria-label="Delivery mode" className="col" style={{ gap: 6 }}>
            {MODES.map((m) => (
              <button key={m} type="button" role="radio" className="radio-card" aria-checked={mode === m} disabled={!MODE_INFO[m].available} onClick={() => setMode(m)}>
                <span className="radio-dot" />
                <span className="col grow" style={{ gap: 2 }}>
                  <span style={{ fontWeight: 600 }}>
                    {MODE_INFO[m].title} <span className="mono muted small">{m}</span>
                    {!MODE_INFO[m].available && <span className="pill accent" style={{ marginLeft: 8 }}>soon</span>}
                  </span>
                  <span className="small muted">{MODE_INFO[m].desc}</span>
                </span>
              </button>
            ))}
          </div>
          {mode === "env" && (
            <label className="field">
              Environment variable name
              <input className="input mono" value={envName} placeholder={defaultEnvName(name || "key")} onChange={(e) => setEnvName(e.target.value.toUpperCase())} />
            </label>
          )}
          {otpExposed && (
            <p className="banner warn small" style={{ padding: "10px 14px" }}>
              A key with {tier === "pin" ? "PIN" : "OTP"} in {mode} mode: once approved, the agent will have the value. The “placeholder + proxy” mode, where the value never leaves
              MCP Keyholder, is coming in a later version.
            </p>
          )}
        </div>
      )}
      {error && <p className="error" style={{ whiteSpace: "pre-line" }}>{error}</p>}
    </Modal>
  );
}

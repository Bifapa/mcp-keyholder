import { open } from "@tauri-apps/plugin-dialog";
import { useMemo, useState } from "react";
import { api, errText, MODE_INFO, MODE_ROLES, TIER_LABEL, TIER_ROLES, type ImportFile, type Mode, type Tier } from "./api";
import { Icon, Roles, Segmented } from "./ui";

interface Draft {
  file: number;
  cand: number; // -1 = whole file
  name: string;
  value: string;
  description: string;
  group: string;
  tier: Tier;
  mode: Mode;
}

const TIERS: Tier[] = ["auto", "soft", "pin", "otp", "sealed"];
const KNOWN_DESC = new Set(["known", "pem"]);

function cleanName(s: string) {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9._/-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^[-/]+|[-/]+$/g, "")
    .slice(0, 64);
}

export function ImportPage({ existing, onDone }: { existing: string[]; onDone: () => void }) {
  const [files, setFiles] = useState<ImportFile[]>([]);
  const [cur, setCur] = useState(0);
  const [drafts, setDrafts] = useState<Draft[]>([]);
  /** The draft open in the form (index into drafts). */
  const [sel, setSel] = useState<number | null>(null);
  const [del, setDel] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ added: string[]; errors: string[]; deleted: number } | null>(null);
  const [error, setError] = useState("");

  const pick = async () => {
    setError("");
    const sel = await open({ multiple: true, directory: false, title: "Files with keys" });
    if (!sel) return;
    const paths = Array.isArray(sel) ? sel : [sel];
    try {
      const r = await api.importRead(paths);
      setFiles(r);
      setCur(0);
      setResult(null);
      // Pre-select recognised tokens and PEM blocks.
      const d: Draft[] = [];
      r.forEach((f, fi) =>
        f.candidates.forEach((c, ci) => {
          if (c.kind === "known" || c.kind === "pem" || c.kind === "whole" || f.candidates.length === 1) d.push(makeDraft(f, fi, ci, d));
        }),
      );
      setDrafts(d);
      setSel(d.findIndex((x) => x.file === 0) >= 0 ? d.findIndex((x) => x.file === 0) : null);
    } catch (e) {
      setError(errText(e));
    }
  };

  const makeDraft = (f: ImportFile, fi: number, ci: number, others: Draft[]): Draft => {
    const c = ci >= 0 ? f.candidates[ci] : null;
    const base = cleanName(c && f.candidates.length > 1 ? `${f.stem}/${c.suggested}` : f.stem) || "key";
    let name = base;
    let n = 2;
    const taken = new Set([...existing, ...others.map((x) => x.name)]);
    while (taken.has(name)) name = `${base}-${n++}`;
    return {
      file: fi,
      cand: ci,
      name,
      value: c ? c.value : f.text.trim(),
      description: c && KNOWN_DESC.has(c.kind) ? c.label : "",
      group: cleanName(f.stem.split(/[-_]/)[0] ?? "") || "default",
      tier: "soft",
      mode: "reveal",
    };
  };

  /** A click on a fragment (or "whole file") opens its draft, creating it with the text as the value. */
  const openFragment = (fi: number, ci: number) => {
    const i = drafts.findIndex((x) => x.file === fi && x.cand === ci);
    if (i >= 0) return setSel(i);
    const d = [...drafts, makeDraft(files[fi], fi, ci, drafts)];
    setDrafts(d);
    setSel(d.length - 1);
  };

  const removeDraft = (i: number) => {
    setDrafts((d) => d.filter((_, j) => j !== i));
    setSel(null);
  };

  const selectFile = (i: number) => {
    setCur(i);
    const first = drafts.findIndex((x) => x.file === i);
    setSel(first >= 0 ? first : null);
  };

  /** Takes a file off the list (nothing is deleted); its drafts go too. */
  const removeFile = (i: number) => {
    setFiles((fs) => fs.filter((_, j) => j !== i));
    setDrafts((d) => d.filter((x) => x.file !== i).map((x) => (x.file > i ? { ...x, file: x.file - 1 } : x)));
    setCur((c) => (c > i ? c - 1 : c === i ? Math.max(0, i - 1) : c));
    setSel(null);
  };

  const upd = (i: number, patch: Partial<Draft>) => setDrafts((d) => d.map((x, j) => (j === i ? { ...x, ...patch } : x)));
  const setAll = (patch: Partial<Draft>) => setDrafts((d) => d.map((x) => ({ ...x, ...patch })));

  const f = files[cur];
  const segments = useMemo(() => {
    if (!f) return [];
    const out: { text: string; ci: number | null }[] = [];
    let pos = 0;
    f.candidates.forEach((c, ci) => {
      if (c.start > pos) out.push({ text: f.text.slice(pos, c.start), ci: null });
      out.push({ text: f.text.slice(c.start, c.end), ci });
      pos = c.end;
    });
    if (pos < f.text.length) out.push({ text: f.text.slice(pos), ci: null });
    return out;
  }, [f]);

  const commit = async () => {
    setBusy(true);
    setError("");
    try {
      const usedFiles = [...new Set(drafts.map((d) => d.file))].map((i) => files[i].path);
      const r = await api.importCommit(
        drafts.map((d) => ({ name: d.name, value: d.value, description: d.description, group: d.group, tags: ["import"], tier: d.tier, mode: d.mode, envName: null })),
        del ? usedFiles : [],
      );
      setResult(r);
      if (r.errors.length === 0) {
        setFiles([]);
        setDrafts([]);
      } else {
        setDrafts((d) => d.filter((x) => !r.added.includes(x.name)));
      }
      setSel(null);
      onDone();
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const noDesc = drafts.filter((d) => !d.description.trim()).length;
  const fileDrafts = drafts.map((d, i) => ({ d, i })).filter(({ d }) => d.file === cur);
  const draft = sel !== null && drafts[sel]?.file === cur ? drafts[sel] : null;

  return (
    <>
      <div className="head">
        <div className="col" style={{ gap: 4 }}>
          <h1>Import from files</h1>
          <p className="muted">Pick old .txt files and click what should become a key. The text goes into a form where you can fix it and set how agents get the key.</p>
        </div>
        <button className="btn primary" onClick={pick}>
          {Icon.download(16)} Choose files
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      {result && (
        <div className={`banner ${result.errors.length ? "warn" : "info"}`}>
          <div className="col" style={{ gap: 4 }}>
            <span style={{ fontWeight: 600 }}>
              Imported: {result.added.length}
              {result.deleted ? ` · source files deleted: ${result.deleted}` : ""}
            </span>
            {result.errors.map((e) => (
              <span key={e} className="small error">
                {e}
              </span>
            ))}
          </div>
        </div>
      )}
      {files.length === 0 && !result && <div className="card empty">No files chosen. This is an extra feature: keys are usually added by hand.</div>}

      {files.length > 0 && (
        <div className="row" style={{ alignItems: "flex-start", gap: 16, flexWrap: "wrap" }}>
          <div className="file-panel">
            <span className="small muted" style={{ padding: "0 4px" }}>
              {files.length} {files.length === 1 ? "file" : "files"}
              {files.length > 10 ? " · scroll for more" : ""}
            </span>
            <div className="card file-list" role="list" aria-label="Files">
              {files.map((x, i) => {
                const n = drafts.filter((d) => d.file === i).length;
                return (
                  <div key={x.path} role="listitem" className={`file-row ${i === cur ? "on" : ""}`}>
                    <button className="file-pick" onClick={() => selectFile(i)}>
                      <span className="grow ellipsis" style={{ fontWeight: 500 }}>
                        {x.fileName}
                      </span>
                      <span className={`pill ${x.error ? "danger" : n ? "accent" : "warn"}`}>{x.error ? "error" : n ? n : "review"}</span>
                    </button>
                    <button className="file-remove" title="Remove from the list" aria-label={`Remove ${x.fileName} from the list`} onClick={() => removeFile(i)}>
                      {Icon.close(14)}
                    </button>
                  </div>
                );
              })}
            </div>
          </div>

          {f && (
            <div className="card pad col" style={{ flex: "1.4 1 300px", minWidth: 0 }}>
              <div className="row">
                <span className="grow" style={{ fontWeight: 600 }}>
                  {f.fileName}
                </span>
                <span className="small muted">Click a fragment to put it in the form</span>
              </div>
              {f.error ? (
                <p className="error">{f.error}</p>
              ) : (
                <pre className="raw mono">
                  {segments.map((s, i) =>
                    s.ci === null ? (
                      <span key={i} className="cut">
                        {s.text}
                      </span>
                    ) : (
                      <mark
                        key={i}
                        className={draft && draft.cand === s.ci ? "current" : drafts.some((d) => d.file === cur && d.cand === s.ci) ? "on" : ""}
                        title={f.candidates[s.ci].label}
                        onClick={() => openFragment(cur, s.ci!)}
                      >
                        {s.text}
                      </mark>
                    ),
                  )}
                </pre>
              )}
              <div className="row wrap small muted">
                <span>Highlighted — found keys · grey — will be cut out</span>
                {!f.error && (
                  <button className="link" onClick={() => openFragment(cur, -1)}>
                    Take the whole file
                  </button>
                )}
              </div>
            </div>
          )}

          <div className="card pad col" style={{ flex: "2 1 380px", minWidth: 0, gap: 12 }}>
            {fileDrafts.length > 0 && (
              <div className="draft-tabs" role="group" aria-label="Drafts from this file">
                {fileDrafts.map(({ d, i }) => (
                  <button key={`${d.file}:${d.cand}`} aria-pressed={i === sel} onClick={() => setSel(i)}>
                    {d.name || "untitled"}
                  </button>
                ))}
              </div>
            )}
            {!draft ? (
              <p className="muted small">Click a fragment in the file to make a key from it.</p>
            ) : (
              <>
                <label className="field">
                  Value — fix it if something extra got in
                  <textarea
                    className="textarea mono"
                    rows={Math.min(10, Math.max(3, draft.value.split("\n").length + 1))}
                    spellCheck={false}
                    value={draft.value}
                    onChange={(e) => upd(sel!, { value: e.target.value })}
                  />
                </label>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 12 }}>
                  <label className="field">
                    Name
                    <input className="input mono" value={draft.name} onChange={(e) => upd(sel!, { name: e.target.value.toLowerCase() })} />
                  </label>
                  <label className="field">
                    Group
                    <input className="input mono" value={draft.group} onChange={(e) => upd(sel!, { group: e.target.value.toLowerCase() })} />
                  </label>
                </div>
                <label className="field">
                  {draft.tier === "sealed" ? "Description (sealed keys are hidden from agents)" : "Description — the agent sees it in the key list"}
                  <input
                    className="input"
                    value={draft.description}
                    placeholder="What the key is for and what it can do"
                    style={!draft.description.trim() ? { borderColor: "var(--warn-line)", background: "var(--warn-surface)" } : undefined}
                    onChange={(e) => upd(sel!, { description: e.target.value })}
                  />
                </label>
                <div className="col" style={{ gap: 8 }}>
                  <span className="field-title">Approval when an agent asks</span>
                  <Segmented<Tier> label="Approval level" value={draft.tier} onChange={(t) => upd(sel!, { tier: t })} options={TIERS.map((t) => ({ id: t, label: TIER_LABEL[t] }))} />
                  <Roles rows={TIER_ROLES[draft.tier]} />
                </div>
                {draft.tier !== "sealed" && (
                  <div className="col" style={{ gap: 8 }}>
                    <span className="field-title">How the agent gets the key</span>
                    <Segmented<Mode>
                      label="Delivery mode"
                      value={draft.mode}
                      onChange={(m) => upd(sel!, { mode: m })}
                      options={(["reveal", "env"] as Mode[]).map((m) => ({ id: m, label: MODE_INFO[m].title }))}
                    />
                    <Roles rows={MODE_ROLES[draft.mode === "env" ? "env" : "reveal"]} />
                  </div>
                )}
                <button className="link" style={{ alignSelf: "flex-start", color: "var(--danger-fg)" }} onClick={() => removeDraft(sel!)}>
                  Remove this draft
                </button>
              </>
            )}
          </div>
        </div>
      )}

      {drafts.length > 0 && (
        <div className="card row wrap" style={{ padding: "12px 12px 12px 18px", gap: 12 }}>
          <span style={{ fontWeight: 600 }}>
            {drafts.length} {drafts.length === 1 ? "draft" : "drafts"}
          </span>
          {noDesc > 0 && <span className="pill warn">{noDesc} without description</span>}
          <span className="small muted">For all:</span>
          <select className="select" style={{ width: "auto" }} aria-label="Approval level for all" value="" onChange={(e) => e.target.value && setAll({ tier: e.target.value as Tier })}>
            <option value="">approval…</option>
            {TIERS.map((t) => (
              <option key={t} value={t}>
                {TIER_LABEL[t]}
              </option>
            ))}
          </select>
          <input
            className="input mono"
            style={{ width: 140 }}
            placeholder="group…"
            aria-label="Group for all"
            onKeyDown={(e) => {
              if (e.key === "Enter" && e.currentTarget.value.trim()) setAll({ group: e.currentTarget.value.trim().toLowerCase() });
            }}
          />
          <label className="row small" style={{ marginLeft: "auto" }}>
            <input type="checkbox" checked={del} onChange={(e) => setDel(e.target.checked)} />
            Delete the source files after import
          </label>
          <button className="btn primary" disabled={busy} onClick={commit}>
            {busy ? "Importing…" : "Import into vault"}
          </button>
        </div>
      )}
    </>
  );
}

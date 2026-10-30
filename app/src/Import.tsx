import { open } from "@tauri-apps/plugin-dialog";
import { useMemo, useState } from "react";
import { api, errText, TIER_LABEL, type ImportFile, type Mode, type Tier } from "./api";
import { Icon } from "./ui";

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
    } catch (e) {
      setError(errText(e));
    }
  };

  const makeDraft = (f: ImportFile, fi: number, ci: number, others: Draft[]): Draft => {
    const c = ci >= 0 ? f.candidates[ci] : null;
    const base = cleanName(c && f.candidates.length > 1 ? `${f.stem}/${c.suggested}` : f.stem) || "key";
    let name = base;
    let n = 2;
    const taken = new Set([...existing, ...others.map((x) => x.name), ...drafts.map((x) => x.name)]);
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

  const toggle = (fi: number, ci: number) => {
    setDrafts((d) => {
      const i = d.findIndex((x) => x.file === fi && x.cand === ci);
      if (i >= 0) return d.filter((_, j) => j !== i);
      return [...d, makeDraft(files[fi], fi, ci, d)];
    });
  };

  /** Takes a file off the list (nothing is deleted); its drafts go too. */
  const removeFile = (i: number) => {
    setFiles((fs) => fs.filter((_, j) => j !== i));
    setDrafts((d) => d.filter((x) => x.file !== i).map((x) => (x.file > i ? { ...x, file: x.file - 1 } : x)));
    setCur((c) => (c > i ? c - 1 : c === i ? Math.max(0, i - 1) : c));
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
      onDone();
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const noDesc = drafts.filter((d) => !d.description.trim()).length;

  return (
    <>
      <div className="head">
        <div className="col" style={{ gap: 4 }}>
          <h1>Import from files</h1>
          <p className="muted">Pick old .txt files — MCP Keyholder finds the keys in them. You choose what becomes a key; the rest is cut out.</p>
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
                  <button className="file-pick" onClick={() => setCur(i)}>
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
            <div className="card pad col" style={{ flex: "2 1 360px", minWidth: 0 }}>
              <div className="row">
                <span className="grow" style={{ fontWeight: 600 }}>
                  {f.fileName}
                </span>
                <span className="small muted">Click a fragment to make it a key</span>
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
                        className={drafts.some((d) => d.file === cur && d.cand === s.ci) ? "on" : ""}
                        title={f.candidates[s.ci].label}
                        onClick={() => toggle(cur, s.ci!)}
                      >
                        {s.text}
                      </mark>
                    ),
                  )}
                </pre>
              )}
              <div className="row wrap small muted">
                <span className="row" style={{ gap: 6 }}>
                  <mark className="on" style={{ width: 12, height: 12, borderRadius: 3, outline: "1.5px solid var(--accent)", background: "var(--accent-soft)" }} /> becomes a key
                </span>
                <span>· grey — will be cut out</span>
                {!f.error && (
                  <button className="link" onClick={() => toggle(cur, -1)}>
                    {drafts.some((d) => d.file === cur && d.cand === -1) ? "Remove “whole file”" : "Take the whole file"}
                  </button>
                )}
              </div>
            </div>
          )}

          <div className="col" style={{ flex: "1.4 1 300px", minWidth: 0 }}>
            <span className="small muted" style={{ fontWeight: 600 }}>
              Drafts from this file
            </span>
            {drafts.map((d, i) =>
              d.file !== cur ? null : (
                <div key={`${d.file}:${d.cand}`} className="card pad col" style={{ gap: 8 }}>
                  <label className="field">
                    Name
                    <input className="input mono" value={d.name} onChange={(e) => upd(i, { name: e.target.value.toLowerCase() })} />
                  </label>
                  <label className="field">
                    Description
                    <input
                      className="input"
                      value={d.description}
                      placeholder="Add a description — the agent will see it"
                      style={!d.description.trim() ? { borderColor: "var(--warn-line)", background: "var(--warn-surface)" } : undefined}
                      onChange={(e) => upd(i, { description: e.target.value })}
                    />
                  </label>
                  <div className="row">
                    <input className="input mono" aria-label="Group" value={d.group} onChange={(e) => upd(i, { group: e.target.value.toLowerCase() })} />
                    <select className="select" aria-label="Approval level" value={d.tier} onChange={(e) => upd(i, { tier: e.target.value as Tier })}>
                      {(["auto", "soft", "pin", "otp", "sealed"] as Tier[]).map((t) => (
                        <option key={t} value={t}>
                          {TIER_LABEL[t]}
                        </option>
                      ))}
                    </select>
                    <select className="select" aria-label="Delivery mode" value={d.mode} onChange={(e) => upd(i, { mode: e.target.value as Mode })}>
                      <option value="reveal">reveal</option>
                      <option value="env">env</option>
                    </select>
                  </div>
                </div>
              ),
            )}
            {!drafts.some((d) => d.file === cur) && <p className="muted small">Nothing selected.</p>}
          </div>
        </div>
      )}

      {drafts.length > 0 && (
        <div className="card row wrap" style={{ padding: "12px 12px 12px 18px", gap: 12 }}>
          <span style={{ fontWeight: 600 }}>{drafts.length} {drafts.length === 1 ? "draft" : "drafts"}</span>
          {noDesc > 0 && <span className="pill warn">{noDesc} without description</span>}
          <span className="small muted">For all:</span>
          <select className="select" style={{ width: "auto" }} aria-label="Approval level for all" value="" onChange={(e) => e.target.value && setAll({ tier: e.target.value as Tier })}>
            <option value="">approval…</option>
            {(["auto", "soft", "pin", "otp", "sealed"] as Tier[]).map((t) => (
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

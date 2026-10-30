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
    const sel = await open({ multiple: true, directory: false, title: "Файлы с ключами" });
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
          <h1>Импорт из файлов</h1>
          <p className="muted">Выберите старые .txt — MCP Keyholder найдёт в них ключи. Вы выбираете, что станет ключом; остальное вырезается.</p>
        </div>
        <button className="btn primary" onClick={pick}>
          {Icon.download(16)} Выбрать файлы
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      {result && (
        <div className={`banner ${result.errors.length ? "warn" : "info"}`}>
          <div className="col" style={{ gap: 4 }}>
            <span style={{ fontWeight: 600 }}>
              Перенесено: {result.added.length}
              {result.deleted ? ` · удалено исходных файлов: ${result.deleted}` : ""}
            </span>
            {result.errors.map((e) => (
              <span key={e} className="small error">
                {e}
              </span>
            ))}
          </div>
        </div>
      )}
      {files.length === 0 && !result && <div className="card empty">Файлы не выбраны. Это дополнительная функция: обычно ключи добавляются вручную.</div>}

      {files.length > 0 && (
        <div className="row" style={{ alignItems: "flex-start", gap: 16, flexWrap: "wrap" }}>
          <div className="card" role="list" aria-label="Файлы" style={{ flex: "1 1 220px", maxWidth: 260, padding: 6 }}>
            {files.map((x, i) => {
              const n = drafts.filter((d) => d.file === i).length;
              return (
                <button
                  key={x.path}
                  role="listitem"
                  className="row"
                  onClick={() => setCur(i)}
                  style={{ width: "100%", border: 0, cursor: "pointer", padding: "0 10px", minHeight: 42, borderRadius: 10, background: i === cur ? "var(--accent-row)" : "transparent", textAlign: "left" }}
                >
                  <span className="grow ellipsis" style={{ fontWeight: 500 }}>
                    {x.fileName}
                  </span>
                  <span className={`pill ${x.error ? "danger" : n ? "accent" : "warn"}`}>{x.error ? "ошибка" : n ? n : "разобрать"}</span>
                </button>
              );
            })}
          </div>

          {f && (
            <div className="card pad col" style={{ flex: "2 1 360px", minWidth: 0 }}>
              <div className="row">
                <span className="grow" style={{ fontWeight: 600 }}>
                  {f.fileName}
                </span>
                <span className="small muted">Нажмите на фрагмент, чтобы сделать его ключом</span>
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
                  <mark className="on" style={{ width: 12, height: 12, borderRadius: 3, outline: "1.5px solid var(--accent)", background: "var(--accent-soft)" }} /> станет ключом
                </span>
                <span>· серым — будет вырезано</span>
                {!f.error && (
                  <button className="link" onClick={() => toggle(cur, -1)}>
                    {drafts.some((d) => d.file === cur && d.cand === -1) ? "Убрать «весь файл»" : "Взять весь файл целиком"}
                  </button>
                )}
              </div>
            </div>
          )}

          <div className="col" style={{ flex: "1.4 1 300px", minWidth: 0 }}>
            <span className="small muted" style={{ fontWeight: 600 }}>
              Черновики из этого файла
            </span>
            {drafts.map((d, i) =>
              d.file !== cur ? null : (
                <div key={`${d.file}:${d.cand}`} className="card pad col" style={{ gap: 8 }}>
                  <label className="field">
                    Имя
                    <input className="input mono" value={d.name} onChange={(e) => upd(i, { name: e.target.value.toLowerCase() })} />
                  </label>
                  <label className="field">
                    Описание
                    <input
                      className="input"
                      value={d.description}
                      placeholder="Добавьте описание — его увидит агент"
                      style={!d.description.trim() ? { borderColor: "var(--warn-line)", background: "var(--warn-surface)" } : undefined}
                      onChange={(e) => upd(i, { description: e.target.value })}
                    />
                  </label>
                  <div className="row">
                    <input className="input mono" aria-label="Группа" value={d.group} onChange={(e) => upd(i, { group: e.target.value.toLowerCase() })} />
                    <select className="select" aria-label="Подтверждение" value={d.tier} onChange={(e) => upd(i, { tier: e.target.value as Tier })}>
                      {(["auto", "soft", "pin", "otp", "sealed"] as Tier[]).map((t) => (
                        <option key={t} value={t}>
                          {TIER_LABEL[t]}
                        </option>
                      ))}
                    </select>
                    <select className="select" aria-label="Режим" value={d.mode} onChange={(e) => upd(i, { mode: e.target.value as Mode })}>
                      <option value="reveal">reveal</option>
                      <option value="env">env</option>
                    </select>
                  </div>
                </div>
              ),
            )}
            {!drafts.some((d) => d.file === cur) && <p className="muted small">Ничего не выбрано.</p>}
          </div>
        </div>
      )}

      {drafts.length > 0 && (
        <div className="card row wrap" style={{ padding: "12px 12px 12px 18px", gap: 12 }}>
          <span style={{ fontWeight: 600 }}>{drafts.length} черновиков</span>
          {noDesc > 0 && <span className="pill warn">{noDesc} без описания</span>}
          <span className="small muted">Всем:</span>
          <select className="select" style={{ width: "auto" }} aria-label="Подтверждение для всех" value="" onChange={(e) => e.target.value && setAll({ tier: e.target.value as Tier })}>
            <option value="">подтверждение…</option>
            {(["auto", "soft", "pin", "otp", "sealed"] as Tier[]).map((t) => (
              <option key={t} value={t}>
                {TIER_LABEL[t]}
              </option>
            ))}
          </select>
          <input
            className="input mono"
            style={{ width: 140 }}
            placeholder="группа…"
            aria-label="Группа для всех"
            onKeyDown={(e) => {
              if (e.key === "Enter" && e.currentTarget.value.trim()) setAll({ group: e.currentTarget.value.trim().toLowerCase() });
            }}
          />
          <label className="row small" style={{ marginLeft: "auto" }}>
            <input type="checkbox" checked={del} onChange={(e) => setDel(e.target.checked)} />
            Удалить исходные файлы после переноса
          </label>
          <button className="btn primary" disabled={busy} onClick={commit}>
            {busy ? "Переношу…" : "Перенести в хранилище"}
          </button>
        </div>
      )}
    </>
  );
}

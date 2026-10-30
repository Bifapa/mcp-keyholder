import { useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import { api, DESKTOP_OFF, errText } from "./api";
import { PasswordInput } from "./ui";

const FILTER = { name: "MCP Keyholder vault", extensions: ["mcpkey"] };

type Run = <T>(fn: () => Promise<T>) => Promise<T | undefined>;
const direct: Run = async (fn) => fn();

/** Asks where to save and writes the whole vault there; returns the path, or null if cancelled. */
export async function exportVault(run: Run): Promise<{ path: string; size: number } | null> {
  const day = new Date().toISOString().slice(0, 10);
  let path = await save({ title: "Export vault", defaultPath: `mcp-keyholder-${day}.mcpkey`, filters: [FILTER] });
  if (!path) return null;
  if (!/\.mcpkey$/i.test(path)) path += ".mcpkey";
  const p = path;
  const size = await run(() => api.exportVaultFile(p));
  return size === undefined ? null : { path, size };
}

/**
 * Picks a `.mcpkey` file and loads it in place of the vault. The file's master password is
 * typed on the separate desktop; if that is off, a field appears here instead.
 */
export function VaultFileImport({ onDone, run = direct, label = "Choose a .mcpkey file" }: { onDone: (backup: string | null) => void; run?: Run; label?: string }) {
  const [path, setPath] = useState("");
  const [manual, setManual] = useState(false);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = async (p: string) => {
    setBusy(true);
    setError("");
    try {
      const r = await run(() => api.importVaultNative(p));
      if (r) onDone(r.backup);
    } catch (e) {
      if (errText(e) === DESKTOP_OFF) setManual(true);
      else setError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const pick = async () => {
    const sel = await open({ multiple: false, directory: false, title: "Vault file", filters: [FILTER] });
    if (typeof sel !== "string") return;
    setPath(sel);
    setPassword("");
    if (!manual) await load(sel);
  };

  const submit = async () => {
    setBusy(true);
    setError("");
    try {
      const r = await run(() => api.importVaultFile(path, password));
      if (r) {
        setPassword("");
        onDone(r.backup);
      }
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const name = path.split(/[\\/]/).pop() ?? "";
  return (
    <div className="col" style={{ gap: 10 }}>
      <div className="row wrap">
        <button className="btn" disabled={busy} onClick={pick}>
          {busy ? "Loading…" : path ? "Another file…" : label}
        </button>
        {path && <span className="mono small muted">{name}</span>}
        {path && !manual && error && (
          <button className="link" disabled={busy} onClick={() => load(path)}>
            Enter the password again
          </button>
        )}
      </div>
      {manual && path && (
        <>
          <label className="field">
            Master password of this file
            <PasswordInput
              autoFocus
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && password && submit()}
            />
          </label>
          <div className="row">
            <button className="btn primary" disabled={busy || !password} onClick={submit}>
              {busy ? "Opening…" : "Load"}
            </button>
          </div>
        </>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

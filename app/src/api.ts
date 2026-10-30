import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type Tier = "auto" | "soft" | "pin" | "otp" | "sealed";
export type Mode = "reveal" | "env" | "proxy" | "sign" | "recipe";
export type LoginMode = "password" | "nothing" | "pin" | "otp";

export interface LeakInfo {
  id: number;
  kind: "reported" | "found" | "exposed";
  client: string;
  comment: string;
  at: number;
}

export interface SecretMeta {
  id: string;
  name: string;
  description: string;
  group: string;
  tags: string[];
  tier: Tier;
  mode: Mode;
  envName: string;
  status: "active" | "disabled";
  createdAt: number;
  updatedAt: number;
  lastUsedAt: number | null;
  useCount: number;
  leak: LeakInfo | null;
  exposed: boolean;
  quarantined: boolean;
}

export interface NewSecret {
  name: string;
  value: string;
  description: string;
  group: string;
  tags: string[];
  tier: Tier;
  mode: Mode;
  envName: string | null;
}

export interface MetaPatch {
  name?: string;
  description?: string;
  group?: string;
  tags?: string[];
  tier?: Tier;
  mode?: Mode;
  envName?: string;
  status?: "active" | "disabled";
}

export interface Settings {
  autolockMinutes: number;
  defaultTtlMinutes: number;
  maxTtlMinutes: number;
  disableOnLeakReport: boolean;
  loginMode: LoginMode;
  fullLock: boolean;
  secureDesktop: boolean;
  anchorPath: string;
  /** Show the anti-phishing word as moving noise (off by default). */
  noiseWord: boolean;
  /** Its colours: 2 to 6 "#rrggbb" values. */
  noiseColors: string[];
}

export interface Preset {
  name: string;
  keys: string[];
  ttlMinutes: number;
  createdAt: number;
}

export interface Client {
  id: string;
  name: string;
  createdAt: number;
  lastSeenAt: number | null;
  revoked: boolean;
  blocked: boolean;
}

export interface LogEntry {
  seq: number;
  ts: number;
  client: string;
  session: string;
  action: string;
  target: string;
  outcome: string;
  detail: string;
}

export interface ChainStatus {
  ok: boolean;
  entries: number;
  firstBadSeq: number | null;
  message: string;
}

export interface GrantKey {
  id: string;
  name: string;
  mode: Mode;
  tier: Tier;
}

export interface Grant {
  id: string;
  session: string;
  client: string;
  process: string;
  keys: GrantKey[];
  reason: string;
  level: Tier;
  createdAt: number;
  expiresAt: number;
  uses: number;
}

export interface PendingView {
  id: string;
  session: string;
  client: string;
  claimedClient: string;
  process: string;
  reason: string;
  keys: GrantKey[];
  removed: { name: string; why: string }[];
  ttlMinutes: number;
  level: Tier;
  createdAt: number;
  shownAt: number | null;
  otpFailures: number;
}

export interface SessionInfo {
  id: string;
  purpose: string;
  clientId: string | null;
  client: string;
  claimedClient: string;
  process: string;
  connectedAt: number;
  blockedUntil: number;
}

export interface AppStatus {
  initialized: boolean;
  unlocked: boolean;
  version: string;
  pipeAlarm: string | null;
  otpLockedUntil: number | null;
  elevatedUntil: number;
  khPath: string;
  vaultPath: string;
  pending: number;
  hasPin: boolean;
  /** "portable" (core in this process) or "service" (core in the MCP Keyholder service). */
  runtime: "portable" | "service";
  uiLocked: boolean;
  dataDir: string;
  loginMode: LoginMode;
  serviceInstalled: boolean;
  desktopAvailable: boolean;
  /** Set when the service is installed but unreachable; nothing else works then. */
  error?: string;
}

export interface Candidate {
  start: number;
  end: number;
  value: string;
  label: string;
  kind: string;
  suggested: string;
}

export interface ImportFile {
  path: string;
  fileName: string;
  stem: string;
  text: string;
  candidates: Candidate[];
  error: string | null;
}

export const STEPUP_REQUIRED = "stepup_required";
/** The separate Windows desktop is off or unavailable; the window may ask for the code itself. */
export const DESKTOP_OFF = "desktop_off";

/** One call into the core: in-process in portable mode, over the interface channel in service mode. */
function call<T>(method: string, params: Record<string, unknown> = {}): Promise<T> {
  return invoke<T>("kh_call", { method, params });
}

export const api = {
  status: () => invoke<AppStatus>("status"),
  setupBegin: (password: string, word: string) =>
    invoke<{ qrSvg: string; recovery: string[] }>("setup_begin", { password, word }),
  setupSecretText: () => call<string>("setup_secret_text"),
  setupFinish: (code: string) => call<void>("setup_finish", { code }),
  unlock: (password: string) => call<void>("unlock", { password }),
  unlockNative: () => invoke<void>("unlock_native"),
  lock: () => call<void>("lock"),
  resetVault: (confirm: string) => call<{ backup: string }>("reset_vault", { confirm }),
  login: (credential: string) => call<void>("login", { credential }),
  loginNative: () => invoke<void>("login_native"),
  stepup: (password: string, code: string) => call<number>("stepup", { password, code }),
  stepupNative: () => invoke<number>("stepup_native"),
  /** Windows Hello availability; answered without showing any dialog. */
  helloAvailable: () => invoke<boolean>("hello_available"),
  stepupHello: (password: string) => invoke<number>("stepup_hello", { password }),
  // Direct Tauri commands take camelCase argument names (Rust `ttl_minutes` ↔ JS `ttlMinutes`).
  approvalHello: (args: { id: string; keep: string[]; ttl_minutes: number; block_session: boolean }) =>
    invoke<void>("approval_hello", { id: args.id, keep: args.keep, ttlMinutes: args.ttl_minutes, blockSession: args.block_session }),
  endStepup: () => call<void>("end_stepup"),
  setPin: (pin: string) => call<void>("set_pin", { pin }),

  listKeys: () => call<{ keys: SecretMeta[]; groups: string[] }>("list_keys"),
  addKey: (key: NewSecret) => call<SecretMeta>("add_key", { key }),
  updateKeys: (ids: string[], patch: MetaPatch) => call<{ ok: number; errors: string[] }>("update_keys", { ids, patch }),
  replaceValue: (id: string, value: string) => call<SecretMeta>("replace_value", { id, value }),
  deleteKeys: (ids: string[]) => call<{ ok: number; errors: string[] }>("delete_keys", { ids }),
  revealValue: (id: string) => call<string>("reveal_value", { id }),
  copyValue: (id: string) => invoke<void>("copy_value", { id }),
  dismissLeak: (id: string) => call<void>("dismiss_leak", { id }),

  listGrants: () => call<{ pending: PendingView[]; active: Grant[]; sessions: SessionInfo[] }>("list_grants"),
  revokeGrant: (id: string) => call<void>("revoke_grant", { id }),
  denyRequest: (id: string) => call<void>("deny_request", { id }),
  showApproval: () => call<void>("show_approval"),
  unblockSession: (id: string) => call<void>("unblock_session", { id }),

  listPresets: () => call<Preset[]>("list_presets"),
  savePreset: (name: string, keys: string[], ttlMinutes: number) =>
    call<Preset[]>("save_preset", { name, keys, ttl_minutes: ttlMinutes }),
  deletePreset: (name: string) => call<Preset[]>("delete_preset", { name }),

  listClients: () => call<Client[]>("list_clients"),
  addClient: (name: string) =>
    call<{ client: Client; token: string; configJson: string; claudeCommand: string }>("add_client", { name }),
  revokeClient: (id: string) => call<Client>("revoke_client", { id }),
  unblockClient: (id: string) => call<Client>("unblock_client", { id }),

  listLog: (limit: number, before: number | null) => call<LogEntry[]>("list_log", { limit, before }),
  verifyLog: () => call<ChainStatus>("verify_log"),
  anchorNow: () => call<void>("anchor_now"),

  importRead: (paths: string[]) => invoke<ImportFile[]>("import_read", { paths }),
  importCommit: (drafts: NewSecret[], deletePaths: string[]) =>
    invoke<{ added: string[]; errors: string[]; deleted: number }>("import_commit", { drafts, deletePaths }),

  getSettings: () => call<Settings>("get_settings"),
  setSettings: (settings: Settings) => call<void>("set_settings", { settings }),
  setLoginMode: (mode: LoginMode) => call<void>("set_login_mode", { mode }),
  // Password and code for these come from the step-up window, not from the page.
  changePassword: (newPassword: string) => call<void>("change_password", { new_password: newPassword }),
  changeAntiphish: (word: string) => call<void>("change_antiphish", { word }),
  reissueTotpBegin: () => call<{ otpauthUri: string; recovery: string[] }>("reissue_totp_begin"),
  reissueTotpFinish: (code: string) => call<{ recovery: string[] }>("reissue_totp_finish", { code }),
  reissueTotpCancel: () => call<void>("reissue_totp_cancel"),
  /** Whole vault as an encrypted `.mcpkey` file; returns its size in bytes. */
  exportVaultFile: (path: string) => invoke<number>("export_vault_file", { path }),
  /** Before a reset: the vault as it is, still encrypted with the old master password. */
  saveVaultBackup: (path: string) => invoke<number>("save_vault_backup", { path }),
  /** Replaces the vault with a `.mcpkey` file; the password is typed on the separate desktop. */
  importVaultNative: (path: string) => invoke<{ backup: string | null }>("import_vault_native", { path }),
  importVaultFile: (path: string, password: string) =>
    invoke<{ backup: string | null }>("import_vault_file", { path, password }),
  recoveryUsed: (password: string, code: string) =>
    call<{ otpauthUri: string }>("recovery_used", { password, code }),

  approvalCurrent: () =>
    call<{ request: PendingView | null; antiphish: string; queue: number; hasPin: boolean; noiseWord?: boolean; noiseColors?: string[] }>("approval_current"),
  approvalDecide: (args: {
    id: string;
    approve: boolean;
    keep: string[];
    ttl_minutes: number;
    code: string | null;
    block_session: boolean;
  }) => call<void>("approval_decide", args),
  /** Approve a `pin`/`otp` request on the separate Windows desktop. */
  approvalNative: (args: { id: string; keep: string[]; ttl_minutes: number; block_session: boolean }) =>
    invoke<void>("approval_native", { id: args.id, keep: args.keep, ttlMinutes: args.ttl_minutes, blockSession: args.block_session }),
  approvalClosed: () => invoke<void>("approval_closed"),

  qrSvg: (uri: string) => invoke<string>("qr_svg", { uri }),

  serviceStatus: () => invoke<{ installed: boolean; error: string | null }>("service_status"),
  installService: () => invoke<void>("install_service"),
  uninstallService: () => invoke<void>("uninstall_service"),
};

export function onChanged(cb: (what: string) => void): Promise<UnlistenFn> {
  return listen<string>("kh-changed", (e) => cb(e.payload));
}

export function errText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  if (e && typeof e === "object" && "message" in e) {
    const m: unknown = e.message;
    return typeof m === "string" ? m : String(e);
  }
  return String(e);
}

export const TIER_LABEL: Record<Tier, string> = {
  auto: "No window",
  soft: "Soft",
  pin: "PIN",
  otp: "OTP",
  sealed: "Sealed",
};

export const TIER_HINT: Record<Tier, string> = {
  auto: "Given out at once, only written to the log.",
  soft: "A window with an “Allow” button. Guards against accidents, not against the agent.",
  pin: "A window asking for your fixed 4–6 digit PIN. Simpler than OTP, but the code never changes.",
  otp: "A window asking for a code from your authenticator app. One code, one approval.",
  sealed: "Never given to agents. Only to you, in this window, after you confirm it's you.",
};

/** Who does what at each approval level. */
export const TIER_ROLES: Record<Tier, [string, string][]> = {
  auto: [
    ["Agent", "gets the key right away, no window"],
    ["You", "nothing to do; every use is written to the log"],
  ],
  soft: [
    ["Agent", "asks for access and waits"],
    ["You", "click Allow in the approval window — guards against accidents, not against a determined agent"],
  ],
  pin: [
    ["Agent", "asks for access and waits"],
    ["You", "type your 4–6 digit PIN on a separate Windows desktop"],
  ],
  otp: [
    ["Agent", "asks for access and waits"],
    ["You", "type a code from your authenticator app; one code approves one request"],
  ],
  sealed: [
    ["Agent", "never gets it, not even with a grant"],
    ["You", "view or copy it in MCP Keyholder after confirming with your password and code"],
  ],
};

/** Who does what in each delivery mode that works today. */
export const MODE_ROLES: Record<"reveal" | "env", [string, string][]> = {
  reveal: [
    ["Agent", "receives the value in the MCP reply and can use it anywhere"],
    ["Risk", "the value stays in the agent's chat history"],
  ],
  env: [
    ["Agent", "runs a command through kh run; the key goes into that process's environment"],
    ["Risk", "low — the agent sees only the command's output, never the value"],
  ],
};

export const MODE_INFO: Record<Mode, { title: string; desc: string; available: boolean }> = {
  reveal: { title: "Return the value", desc: "The agent gets the key in the MCP response. Convenient, but the value stays in the agent's history.", available: true },
  env: { title: "Environment variable", desc: "kh run puts the key into the process environment. The agent never sees the value in the chat.", available: true },
  proxy: { title: "Placeholder + proxy", desc: "The agent sees a fake; the real key is swapped in on the way to an allowed host.", available: false },
  sign: { title: "Signing only", desc: "For private keys: the agent gets signatures, the key never leaves.", available: false },
  recipe: { title: "Recipe", desc: "Only predefined commands that use this key.", available: false },
};

export const LOGIN_LABEL: Record<LoginMode, string> = {
  password: "Master password",
  nothing: "Nothing",
  pin: "PIN",
  otp: "OTP",
};

export function ago(ts: number | null | undefined): string {
  if (!ts) return "—";
  const d = Date.now() - ts;
  const m = Math.round(d / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} h ago`;
  const days = Math.round(h / 24);
  if (days === 1) return "yesterday";
  if (days < 7) return `${days} days ago`;
  return new Date(ts).toLocaleDateString("en-GB", { day: "numeric", month: "short" });
}

export function left(ts: number): string {
  const s = Math.max(0, Math.round((ts - Date.now()) / 1000));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (h > 0) return `${h} h ${m} min`;
  if (m > 0) return `${m} min ${s % 60} s`;
  return `${s} s`;
}

export function timeOf(ts: number): string {
  return new Date(ts).toLocaleString("en-GB", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function defaultEnvName(name: string): string {
  let s = name.replace(/[^a-zA-Z0-9]/g, "_").toUpperCase();
  if (!s || /^[0-9]/.test(s)) s = "_" + s;
  return s.slice(0, 64);
}

export type Theme = "system" | "light" | "dark";

export function getTheme(): Theme {
  try {
    const t = localStorage.getItem("kh-theme");
    if (t === "light" || t === "dark" || t === "system") return t;
  } catch {
    /* storage unavailable */
  }
  return "system";
}

export function applyTheme(t: Theme) {
  try {
    localStorage.setItem("kh-theme", t);
  } catch {
    /* storage unavailable */
  }
  const dark = t === "dark" || (t === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
}

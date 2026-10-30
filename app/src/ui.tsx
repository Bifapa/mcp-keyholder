import { Component, useEffect, useRef, useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode } from "react";
import { MODE_INFO, TIER_LABEL, type Mode, type Tier } from "./api";

const svg = (children: ReactNode, size = 18, width = 1.8) => (
  <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={width} strokeLinecap="round" strokeLinejoin="round">
    {children}
  </svg>
);

export const Icon = {
  key: (s?: number) => svg(<><circle cx="8" cy="15" r="4" /><path d="M11 12l9-9M17 6l3 3M15 8l2 2" /></>, s),
  shield: (s?: number) => svg(<><path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6l8-3z" /><path d="M9 12l2 2 4-4" /></>, s),
  monitor: (s?: number) => svg(<><rect x="3" y="4" width="18" height="12" rx="2" /><path d="M8 20h8M12 16v4" /></>, s),
  list: (s?: number) => svg(<path d="M9 6h11M9 12h11M9 18h11M4 6h.01M4 12h.01M4 18h.01" />, s),
  download: (s?: number) => svg(<><path d="M12 3v12M7 10l5 5 5-5" /><path d="M4 20h16" /></>, s),
  gear: (s?: number) => svg(<><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" /></>, s),
  lock: (s?: number) => svg(<><rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></>, s, 2),
  search: (s?: number) => svg(<><circle cx="11" cy="11" r="7" /><path d="M20 20l-3.5-3.5" /></>, s, 2),
  plus: (s?: number) => svg(<path d="M12 5v14M5 12h14" />, s, 2.2),
  close: (s?: number) => svg(<path d="M6 6l12 12M18 6L6 18" />, s, 2.2),
  eye: (s?: number) => svg(<><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" /><circle cx="12" cy="12" r="3" /></>, s, 2),
  eyeOff: (s?: number) => svg(<><path d="M10.6 5.1A10.7 10.7 0 0 1 12 5c6.5 0 10 7 10 7a17.6 17.6 0 0 1-3.2 4.2M6.6 6.6C3.8 8.4 2 12 2 12s3.5 7 10 7a9.7 9.7 0 0 0 5.4-1.6" /><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" /><path d="M3 3l18 18" /></>, s, 2),
  copy: (s?: number) => svg(<><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h10" /></>, s, 2),
  check: (s?: number) => svg(<path d="M5 12l5 5 9-10" />, s, 2.4),
  more: () => (
    <svg aria-hidden="true" width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
      <circle cx="5" cy="12" r="1.6" />
      <circle cx="12" cy="12" r="1.6" />
      <circle cx="19" cy="12" r="1.6" />
    </svg>
  ),
};

export function TierPill({ tier, off }: { tier: Tier; off?: boolean }) {
  if (off) return <span className="pill off">Отключён</span>;
  return <span className={`pill ${tier}`}>{TIER_LABEL[tier]}</span>;
}

export function ModeText({ mode, sealed }: { mode: Mode; sealed?: boolean }) {
  if (sealed) {
    return <span className="small muted">только UI</span>;
  }
  return (
    <span className="mono small" title={MODE_INFO[mode]?.title} style={{ color: "var(--ink-2)" }}>
      {mode}
    </span>
  );
}

/** Shows a readable error instead of a blank window if rendering fails. */
export class ErrorBoundary extends Component<{ children: ReactNode }, { error: string | null }> {
  state = { error: null as string | null };
  static getDerivedStateFromError(e: unknown) {
    return { error: e instanceof Error ? `${e.message}
${e.stack ?? ""}` : String(e) };
  }
  render() {
    if (this.state.error) {
      return (
        <div className="center-screen">
          <div className="auth-card">
            <h1 style={{ fontSize: 19 }}>Что-то пошло не так в интерфейсе</h1>
            <pre className="raw mono" style={{ lineHeight: 1.5 }}>{this.state.error}</pre>
            <button className="btn primary" onClick={() => location.reload()}>
              Перезагрузить окно
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

export function Modal({
  title,
  onClose,
  children,
  footer,
  wide,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    const first = ref.current?.querySelector<HTMLElement>("input, textarea, select, button");
    first?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      prev?.focus?.();
    };
  }, [onClose]);
  return (
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal ${wide ? "wide" : ""}`} role="dialog" aria-modal="true" aria-label={title} ref={ref}>
        <div className="modal-head">
          <h2 style={{ fontSize: 19 }}>{title}</h2>
          <button className="btn icon ghost" aria-label="Закрыть" onClick={onClose}>
            {Icon.close(16)}
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  );
}

export function Segmented<T extends string>({
  value,
  options,
  onChange,
  label,
}: {
  value: T;
  options: { id: T; label: string; count?: number }[];
  onChange: (v: T) => void;
  label: string;
}) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.id} type="button" aria-pressed={o.id === value} onClick={() => onChange(o.id)}>
          {o.label}
          {o.count !== undefined && <span className="count">{o.count}</span>}
        </button>
      ))}
    </div>
  );
}

/** A button whose action asks for the master password and code (step-up) when needed. */
export function LockedButton({ className, children, title, ...props }: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button {...props} className={`btn ${className ?? ""}`} title={title ?? "Спросит мастер-пароль и код из аутентификатора"}>
      {Icon.lock(14)}
      {children}
    </button>
  );
}

/** Seconds left until `until` (epoch ms), ticking once a second. */
export function useSecondsLeft(until: number): number {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    setNow(Date.now());
    if (until <= Date.now()) return;
    const t = setInterval(() => {
      setNow(Date.now());
      if (Date.now() >= until) clearInterval(t);
    }, 1000);
    return () => clearInterval(t);
  }, [until]);
  return Math.max(0, Math.ceil((until - now) / 1000));
}

/** A password field with an eye button to peek at what was typed. */
export function PasswordInput({ className, ...props }: Omit<InputHTMLAttributes<HTMLInputElement>, "type">) {
  const [show, setShow] = useState(false);
  return (
    <span className="pw-wrap">
      <input {...props} type={show ? "text" : "password"} className={`input pw-input ${className ?? ""}`} spellCheck={false} />
      <button
        type="button"
        className="pw-eye"
        aria-label={show ? "Скрыть пароль" : "Показать пароль"}
        aria-pressed={show}
        title={show ? "Скрыть пароль" : "Показать пароль"}
        onMouseDown={(e) => e.preventDefault()}
        onClick={() => setShow((v) => !v)}
      >
        {show ? Icon.eyeOff(17) : Icon.eye(17)}
      </button>
    </span>
  );
}

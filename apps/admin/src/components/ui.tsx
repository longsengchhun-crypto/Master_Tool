'use client';

import { useEffect, useRef, type ButtonHTMLAttributes, type ReactNode } from 'react';
import { Loader2, X } from 'lucide-react';

type V = 'primary' | 'secondary' | 'ghost' | 'danger';

export function Button({ variant = 'secondary', busy, className = '', children, disabled, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: V; busy?: boolean }) {
  const base = 'inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2.5 text-sm font-medium transition active:scale-[0.98] disabled:opacity-50 disabled:pointer-events-none';
  const s: Record<V, string> = {
    primary: 'bg-gradient-to-br from-accent to-accent2 text-accentink shadow-lg shadow-accent/20 hover:brightness-110',
    secondary: 'bg-solid border border-line text-ink hover:border-strong hover:bg-surface2',
    ghost: 'text-muted hover:text-ink hover:bg-surface2',
    danger: 'bg-dangerbg text-danger border border-danger/30 hover:bg-danger/20',
  };
  return (
    <button className={`${base} ${s[variant]} ${className}`} disabled={disabled || busy} {...rest}>
      {busy && <Loader2 className="size-4 animate-spin" aria-hidden />}
      {children}
    </button>
  );
}

export function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`glass rounded-2xl ${className}`}>{children}</div>;
}

export function Badge({ tone = 'muted', children }: { tone?: 'ok' | 'warn' | 'danger' | 'info' | 'muted'; children: ReactNode }) {
  const t = { ok: 'bg-okbg text-ok', warn: 'bg-warnbg text-warn', danger: 'bg-dangerbg text-danger', info: 'bg-infobg text-info', muted: 'bg-surface2 text-muted' }[tone];
  return <span className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium ${t}`}>{children}</span>;
}

export function Notice({ tone, title, children }: { tone: 'warn' | 'danger' | 'info' | 'ok'; title?: string; children: ReactNode }) {
  const t = { warn: 'bg-warnbg text-warn', danger: 'bg-dangerbg text-danger', info: 'bg-infobg text-info', ok: 'bg-okbg text-ok' }[tone];
  return (
    <div role={tone === 'danger' ? 'alert' : 'status'} className={`rounded-xl px-4 py-3 text-sm ${t}`}>
      {title && <div className="font-semibold">{title}</div>}
      <div className={title ? 'mt-0.5 opacity-90' : ''}>{children}</div>
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <header className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-ink">{title}</h1>
        {subtitle && <p className="mt-1 max-w-2xl text-sm text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-3">{actions}</div>}
    </header>
  );
}

export function Modal({ open, onClose, title, children, footer }: { open: boolean; onClose: () => void; title: string; children: ReactNode; footer?: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const prev = document.activeElement as HTMLElement | null;
    ref.current?.focus();
    const key = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', key);
    return () => {
      window.removeEventListener('keydown', key);
      prev?.focus();
    };
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/55 p-6 backdrop-blur-sm" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={ref} tabIndex={-1} role="dialog" aria-modal="true" aria-label={title} className="glass w-full max-w-lg rounded-2xl p-6 outline-none" style={{ background: 'var(--surface-solid)' }}>
        <div className="mb-4 flex items-start justify-between gap-4">
          <h2 className="text-lg font-semibold text-ink">{title}</h2>
          <button aria-label="Close" onClick={onClose} className="rounded-lg p-1 text-muted hover:bg-surface2 hover:text-ink">
            <X className="size-5" />
          </button>
        </div>
        <div className="text-sm text-muted">{children}</div>
        {footer && <div className="mt-6 flex justify-end gap-3">{footer}</div>}
      </div>
    </div>
  );
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="block text-sm">
      <span className="font-medium text-ink">{label}</span>
      <div className="mt-1.5">{children}</div>
      {hint && <span className="mt-1 block text-xs text-muted">{hint}</span>}
    </label>
  );
}

export const inputCls = 'w-full rounded-xl border border-line bg-solid px-3 py-2.5 text-sm text-ink placeholder:text-faint';

export function Table({ head, children, empty }: { head: string[]; children: ReactNode; empty?: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-line text-xs uppercase tracking-wide text-muted">
          <tr>{head.map((h) => <th key={h} className="px-4 py-3 font-medium">{h}</th>)}</tr>
        </thead>
        <tbody className="divide-y divide-line">{children}</tbody>
      </table>
      {empty}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="px-6 py-12 text-center text-sm text-muted">{children}</div>;
}

export function Logo({ size = 32 }: { size?: number }) {
  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img src="/icon.svg" width={size} height={size} alt="SENTRIX" />
  );
}

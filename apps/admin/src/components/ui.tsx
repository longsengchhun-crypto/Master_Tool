'use client';

import { useEffect, useRef, type ButtonHTMLAttributes, type ReactNode } from 'react';
import { Loader2, X } from 'lucide-react';

type V = 'primary' | 'secondary' | 'ghost' | 'danger';

export function Button({ variant = 'secondary', busy, className = '', children, disabled, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: V; busy?: boolean }) {
  const base = 'inline-flex h-8 select-none items-center justify-center gap-2 rounded px-3 text-sm font-semibold transition-colors disabled:pointer-events-none disabled:opacity-50';
  const s: Record<V, string> = {
    primary: 'bg-accent text-accentink hover:bg-accenthover',
    secondary: 'border border-strong bg-solid text-ink hover:bg-surface2',
    ghost: 'text-ink hover:bg-surface2',
    danger: 'border border-danger/60 bg-solid text-danger hover:bg-dangerbg',
  };
  return (
    <button className={`${base} ${s[variant]} ${className}`} disabled={disabled || busy} {...rest}>
      {busy && <Loader2 className="size-3.5 animate-spin" aria-hidden />}
      {children}
    </button>
  );
}

export function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`panel rounded-lg ${className}`}>{children}</div>;
}

/** A titled block: the standard way to group related facts on a page. */
export function Section({ title, aside, children, className = '' }: { title: string; aside?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`panel rounded-lg ${className}`}>
      <header className="flex min-h-11 items-center justify-between gap-4 border-b border-line px-4">
        <h2 className="text-sm font-semibold text-ink">{title}</h2>
        {aside}
      </header>
      {children}
    </section>
  );
}

export function Rows({ children }: { children: ReactNode }) {
  return <dl className="divide-y divide-line text-sm">{children}</dl>;
}

export function Row({ label, hint, children, tone }: { label: ReactNode; hint?: string; children: ReactNode; tone?: 'ok' | 'warn' | 'danger' | 'muted' }) {
  const c = tone === 'ok' ? 'text-ok' : tone === 'warn' ? 'text-warn' : tone === 'danger' ? 'text-danger' : tone === 'muted' ? 'text-muted' : 'text-ink';
  return (
    <div className="flex min-h-9 items-center justify-between gap-6 px-4 py-1.5">
      <dt className="text-muted" title={hint}>{label}</dt>
      <dd className={`min-w-0 text-right font-medium tabular-nums ${c}`}>{children}</dd>
    </div>
  );
}

export function Badge({ tone = 'muted', children }: { tone?: 'ok' | 'warn' | 'danger' | 'info' | 'muted'; children: ReactNode }) {
  const t = { ok: 'bg-okbg text-ok', warn: 'bg-warnbg text-warn', danger: 'bg-dangerbg text-danger', info: 'bg-infobg text-info', muted: 'bg-surface2 text-muted' }[tone];
  return <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold ${t}`}>{children}</span>;
}

export function Notice({ tone, title, children }: { tone: 'warn' | 'danger' | 'info' | 'ok'; title?: string; children: ReactNode }) {
  const t = { warn: 'border-warn bg-warnbg', danger: 'border-danger bg-dangerbg', info: 'border-info bg-infobg', ok: 'border-ok bg-okbg' }[tone];
  return (
    <div role={tone === 'danger' ? 'alert' : 'status'} className={`rounded border-l-[3px] px-4 py-2.5 text-sm text-ink ${t}`}>
      {title && <div className="font-semibold">{title}</div>}
      <div className={title ? 'mt-0.5 text-ink/85' : ''}>{children}</div>
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <header className="mb-5 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-xl font-semibold text-ink">{title}</h1>
        {subtitle && <p className="mt-1 max-w-2xl text-sm text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
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
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/40 p-6" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={ref} tabIndex={-1} role="dialog" aria-modal="true" aria-label={title} className="panel w-full max-w-lg rounded-lg p-5 shadow-2xl outline-none">
        <div className="mb-4 flex items-start justify-between gap-4">
          <h2 className="text-base font-semibold text-ink">{title}</h2>
          <button aria-label="Close" onClick={onClose} className="rounded p-1 text-muted hover:bg-surface2 hover:text-ink">
            <X className="size-4" />
          </button>
        </div>
        <div className="text-sm text-muted">{children}</div>
        {footer && <div className="mt-5 flex justify-end gap-2">{footer}</div>}
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

export const inputCls = 'h-8 w-full rounded border border-strong bg-solid px-2.5 text-sm text-ink placeholder:text-faint';

export function Table({ head, children, empty }: { head: string[]; children: ReactNode; empty?: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-line bg-bg text-xs text-muted">
          <tr>{head.map((h) => <th key={h} className="px-4 py-2 font-semibold">{h}</th>)}</tr>
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

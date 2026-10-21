import { useEffect, useId, useRef, type ButtonHTMLAttributes, type ReactNode } from 'react';
import { X, Loader2 } from 'lucide-react';
import type { Verdict } from '../lib/types';
import { VERDICT_LABEL } from '../lib/format';

type BtnVariant = 'primary' | 'secondary' | 'ghost' | 'danger';

export function Button({
  variant = 'secondary',
  busy,
  className = '',
  children,
  disabled,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: BtnVariant; busy?: boolean }) {
  const base =
    'inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2.5 text-sm font-medium transition active:scale-[0.98] disabled:opacity-50 disabled:pointer-events-none select-none';
  const styles: Record<BtnVariant, string> = {
    primary: 'bg-gradient-to-br from-accent to-accent2 text-accentink shadow-lg shadow-accent/20 hover:brightness-110',
    secondary: 'bg-solid border border-line text-ink hover:border-strong hover:bg-surface2',
    ghost: 'text-muted hover:text-ink hover:bg-surface2',
    danger: 'bg-dangerbg text-danger border border-danger/30 hover:bg-danger/20',
  };
  return (
    <button className={`${base} ${styles[variant]} ${className}`} disabled={disabled || busy} {...rest}>
      {busy && <Loader2 className="size-4 animate-spin" aria-hidden />}
      {children}
    </button>
  );
}

export function Card({ children, className = '', ...rest }: { children: ReactNode; className?: string } & React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={`glass rounded-2xl ${className}`} {...rest}>
      {children}
    </div>
  );
}

const VERDICT_STYLE: Record<Verdict, string> = {
  CLEAN: 'bg-okbg text-ok',
  SUSPICIOUS: 'bg-warnbg text-warn',
  MALICIOUS: 'bg-dangerbg text-danger',
  UNABLE_TO_VERIFY: 'bg-surface2 text-muted border border-line',
  PENDING: 'bg-infobg text-info',
};

export function VerdictBadge({ verdict, incomplete }: { verdict: Verdict; incomplete?: boolean }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ${VERDICT_STYLE[verdict]}`}>
      <span className="size-1.5 rounded-full bg-current" aria-hidden />
      {VERDICT_LABEL[verdict]}
      {incomplete && verdict !== 'UNABLE_TO_VERIFY' && <span className="font-normal opacity-80">· partial</span>}
    </span>
  );
}

export function Pill({ tone, children }: { tone: 'ok' | 'warn' | 'danger' | 'muted' | 'info'; children: ReactNode }) {
  const t = {
    ok: 'bg-okbg text-ok',
    warn: 'bg-warnbg text-warn',
    danger: 'bg-dangerbg text-danger',
    info: 'bg-infobg text-info',
    muted: 'bg-surface2 text-muted',
  }[tone];
  return <span className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium ${t}`}>{children}</span>;
}

export function Toggle({ checked, onChange, label, description, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; description?: string; disabled?: boolean }) {
  const id = useId();
  return (
    <div className="flex items-start justify-between gap-6 py-3">
      <div className="min-w-0">
        <label htmlFor={id} className="block text-sm font-medium text-ink">
          {label}
        </label>
        {description && <p className="mt-0.5 text-sm text-muted">{description}</p>}
      </div>
      <button
        id={id}
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={`relative mt-0.5 h-6 w-11 shrink-0 rounded-full border transition ${checked ? 'border-transparent bg-gradient-to-r from-accent to-accent2' : 'border-strong bg-surface2'} disabled:opacity-50`}
      >
        <span className={`absolute top-0.5 size-5 rounded-full bg-white shadow transition-all ${checked ? 'left-[22px]' : 'left-0.5'}`} />
      </button>
    </div>
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
      <div ref={ref} tabIndex={-1} role="dialog" aria-modal="true" aria-label={title} className="rise glass w-full max-w-lg rounded-2xl bg-solid p-6 outline-none" style={{ background: 'var(--surface-solid)' }}>
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

export function Empty({ icon, title, children }: { icon: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="grid place-items-center px-6 py-16 text-center">
      <div className="mb-4 grid size-14 place-items-center rounded-2xl bg-surface2 text-muted">{icon}</div>
      <h3 className="text-base font-semibold text-ink">{title}</h3>
      {children && <p className="mt-1 max-w-sm text-sm text-muted">{children}</p>}
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
      {actions && <div className="flex gap-3">{actions}</div>}
    </header>
  );
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

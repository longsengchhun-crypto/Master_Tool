import { useEffect, useId, useRef, type ButtonHTMLAttributes, type ReactNode } from 'react';
import { ChevronRight, X, Loader2 } from 'lucide-react';
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
  const base = 'inline-flex h-9 select-none items-center justify-center gap-2 rounded-lg px-4 text-sm font-semibold transition-colors disabled:pointer-events-none disabled:opacity-50';
  const styles: Record<BtnVariant, string> = {
    primary: 'bg-accent text-accentink hover:bg-accenthover',
    secondary: 'border border-strong bg-solid text-ink hover:bg-surface2',
    ghost: 'text-ink hover:bg-surface2',
    danger: 'border border-danger/60 bg-solid text-danger hover:bg-dangerbg',
  };
  return (
    <button className={`${base} ${styles[variant]} ${className}`} disabled={disabled || busy} {...rest}>
      {busy && <Loader2 className="size-3.5 animate-spin" aria-hidden />}
      {children}
    </button>
  );
}

export function Card({ children, className = '', ...rest }: { children: ReactNode; className?: string } & React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={`panel rounded-xl ${className}`} {...rest}>
      {children}
    </div>
  );
}

/** A titled block: the standard way to group related facts on a page. */
export function Section({ title, aside, children, className = '' }: { title: string; aside?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`panel rounded-xl ${className}`}>
      <header className="flex min-h-12 items-center justify-between gap-4 border-b border-line px-5">
        <h2 className="text-sm font-semibold text-ink">{title}</h2>
        {aside}
      </header>
      {children}
    </section>
  );
}

/** Label/value rows with hairline separators. Replaces ad-hoc grids of stat cards. */
export function Rows({ children }: { children: ReactNode }) {
  return <dl className="divide-y divide-line text-sm">{children}</dl>;
}

export function Row({ label, children, tone }: { label: ReactNode; children: ReactNode; tone?: 'ok' | 'warn' | 'danger' | 'muted' }) {
  const c = tone === 'ok' ? 'text-ok' : tone === 'warn' ? 'text-warn' : tone === 'danger' ? 'text-danger' : tone === 'muted' ? 'text-muted' : 'text-ink';
  return (
    <div className="flex min-h-10 items-center justify-between gap-6 px-5 py-2">
      <dt className="text-muted">{label}</dt>
      <dd className={`min-w-0 text-right ${c}`}>{children}</dd>
    </div>
  );
}

const VERDICT_STYLE: Record<Verdict, string> = {
  CLEAN: 'bg-okbg text-ok',
  SUSPICIOUS: 'bg-warnbg text-warn',
  MALICIOUS: 'bg-dangerbg text-danger',
  UNABLE_TO_VERIFY: 'bg-surface2 text-muted',
  PENDING: 'bg-infobg text-info',
};

export function VerdictBadge({ verdict, incomplete }: { verdict: Verdict; incomplete?: boolean }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-xs font-semibold ${VERDICT_STYLE[verdict]}`}>
      {VERDICT_LABEL[verdict]}
      {incomplete && verdict !== 'UNABLE_TO_VERIFY' && <span className="font-normal opacity-80">(partial)</span>}
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
  return <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold ${t}`}>{children}</span>;
}

export function Toggle({ checked, onChange, label, description, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; description?: string; disabled?: boolean }) {
  const id = useId();
  return (
    <div className="flex items-start justify-between gap-8 py-3">
      <div className="min-w-0">
        <label htmlFor={id} className="block text-sm font-semibold text-ink">
          {label}
        </label>
        {description && <p className="mt-0.5 max-w-xl text-sm text-muted">{description}</p>}
      </div>
      <button
        id={id}
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={`relative mt-0.5 h-6 w-11 shrink-0 rounded-full border transition-colors disabled:opacity-50 ${checked ? 'border-accent bg-accent' : 'border-strong bg-surface2'}`}
      >
        <span className={`absolute top-1/2 size-4 -translate-y-1/2 rounded-full shadow-sm transition-all ${checked ? 'left-[25px] bg-accentink' : 'left-[3px] bg-muted'}`} />
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
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/40 p-6" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={ref} tabIndex={-1} role="dialog" aria-modal="true" aria-label={title} className="panel w-full max-w-md rounded-xl shadow-2xl outline-none">
        <div className="flex items-center justify-between gap-4 px-5 pt-4">
          <h2 className="text-base font-semibold text-ink">{title}</h2>
          <button aria-label="Close" onClick={onClose} className="rounded p-1 text-muted hover:bg-surface2 hover:text-ink">
            <X className="size-4" />
          </button>
        </div>
        <div className="px-5 py-3 text-sm text-muted">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-line bg-bg px-5 py-3">{footer}</div>}
      </div>
    </div>
  );
}

export function Empty({ icon, title, children }: { icon?: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center px-6 py-14 text-center">
      {icon && <div className="mb-3 text-faint">{icon}</div>}
      <h3 className="text-sm font-semibold text-ink">{title}</h3>
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
      {actions && <div className="flex gap-2">{actions}</div>}
    </header>
  );
}

export function Notice({ tone, title, children }: { tone: 'warn' | 'danger' | 'info' | 'ok'; title?: string; children: ReactNode }) {
  const t = {
    warn: 'border-warn bg-warnbg',
    danger: 'border-danger bg-dangerbg',
    info: 'border-info bg-infobg',
    ok: 'border-ok bg-okbg',
  }[tone];
  return (
    <div role={tone === 'danger' ? 'alert' : 'status'} className={`rounded-lg border-l-[3px] px-4 py-3 text-sm text-ink ${t}`}>
      {title && <div className="font-semibold">{title}</div>}
      <div className={title ? 'mt-0.5 text-ink/85' : ''}>{children}</div>
    </div>
  );
}

/** Hides detail until the user asks for it. Closed by default so pages stay short. */
export function Disclosure({ title, hint, children, defaultOpen = false }: { title: string; hint?: string; children: ReactNode; defaultOpen?: boolean }) {
  return (
    <details open={defaultOpen} className="group panel rounded-xl">
      <summary className="flex cursor-pointer list-none items-center gap-3 px-5 py-3.5 [&::-webkit-details-marker]:hidden">
        <ChevronRight className="size-4 text-faint transition-transform group-open:rotate-90" aria-hidden />
        <span className="text-sm font-semibold text-ink">{title}</span>
        {hint && <span className="text-sm text-muted">{hint}</span>}
      </summary>
      <div className="border-t border-line">{children}</div>
    </details>
  );
}

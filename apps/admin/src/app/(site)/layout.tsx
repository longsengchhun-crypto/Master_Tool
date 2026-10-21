import Link from 'next/link';
import { Logo } from '@/components/ui';

const NAV = [
  ['/#features', 'Features'],
  ['/download', 'Download'],
  ['/docs', 'Documentation'],
  ['/releases', 'Release notes'],
  ['/support', 'Support'],
] as const;

export default function SiteLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="ambient flex min-h-screen flex-col">
      <header className="sticky top-0 z-30 border-b border-line backdrop-blur" style={{ background: 'color-mix(in srgb, var(--bg) 82%, transparent)' }}>
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between gap-6 px-6">
          <Link href="/" className="flex items-center gap-3" aria-label="SENTRIX home">
            <Logo size={32} />
            <span className="text-lg font-semibold tracking-tight text-ink">SENTRIX</span>
          </Link>
          <nav aria-label="Site" className="hidden items-center gap-1 md:flex">
            {NAV.map(([href, label]) => (
              <Link key={href} href={href} className="rounded-lg px-3 py-2 text-sm text-muted transition hover:bg-surface2 hover:text-ink">
                {label}
              </Link>
            ))}
          </nav>
          <div className="flex items-center gap-2">
            <Link href="/login" className="rounded-xl border border-line px-4 py-2 text-sm font-medium text-ink hover:border-strong hover:bg-surface2">
              Console sign-in
            </Link>
          </div>
        </div>
      </header>
      <div className="flex-1">{children}</div>
      <footer className="border-t border-line py-10">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-6 text-sm text-muted">
          <div>SENTRIX · Intelligent File Security · no scanner detects everything, and we say so.</div>
          <div className="flex gap-5">
            <Link href="/privacy" className="hover:text-ink">Privacy</Link>
            <Link href="/terms" className="hover:text-ink">Terms</Link>
            <Link href="/support" className="hover:text-ink">Support</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}

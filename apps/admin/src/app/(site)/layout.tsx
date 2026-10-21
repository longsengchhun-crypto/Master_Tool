import Link from 'next/link';
import { Logo } from '@/components/ui';

const NAV = [
  ['/download', 'Download'],
  ['/docs', 'Documentation'],
  ['/releases', 'Release notes'],
  ['/support', 'Support'],
] as const;

export default function SiteLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-line bg-solid">
        <div className="mx-auto flex h-14 max-w-5xl items-center justify-between gap-6 px-6">
          <Link href="/" className="flex items-center gap-2.5" aria-label="SENTRIX home">
            <Logo size={26} />
            <span className="text-[13px] font-semibold tracking-[0.12em] text-ink">SENTRIX</span>
          </Link>
          <nav aria-label="Site" className="flex items-center gap-1">
            {NAV.map(([href, label]) => (
              <Link key={href} href={href} className="rounded px-3 py-1.5 text-sm text-muted transition-colors hover:bg-surface2 hover:text-ink">
                {label}
              </Link>
            ))}
            <Link href="/login" className="ml-2 rounded border border-strong px-3 py-1.5 text-sm font-semibold text-ink hover:bg-surface2">
              Console
            </Link>
          </nav>
        </div>
      </header>
      <div className="flex-1">{children}</div>
      <footer className="border-t border-line bg-solid">
        <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-4 px-6 py-6 text-sm text-muted">
          <div>SENTRIX for Windows. No scanner detects everything, and the reports say so.</div>
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

import { Activity, FileText, HelpCircle, History as HistoryIcon, Home as HomeIcon, KeyRound, ScanSearch, Send, Settings as SettingsIcon, ShieldCheck, Archive, X } from 'lucide-react';
import { AppProvider, useApp, type Page } from './lib/app';
import { Logo } from './components/Logo';
import { Onboarding } from './components/Onboarding';
import { Button, Modal } from './components/ui';
import { Home } from './pages/Home';
import { Scan } from './pages/Scan';
import { Protection } from './pages/Protection';
import { Quarantine } from './pages/Quarantine';
import { History } from './pages/History';
import { Reports } from './pages/Reports';
import { Settings } from './pages/Settings';
import { Account } from './pages/Account';
import { Telegram } from './pages/Telegram';
import { Help } from './pages/Help';

const NAV: { id: Page; label: string; icon: typeof HomeIcon }[] = [
  { id: 'home', label: 'Overview', icon: HomeIcon },
  { id: 'scan', label: 'Scan', icon: ScanSearch },
  { id: 'protection', label: 'Real-Time Protection', icon: ShieldCheck },
  { id: 'telegram', label: 'Telegram Protection', icon: Send },
  { id: 'quarantine', label: 'Quarantine', icon: Archive },
  { id: 'history', label: 'Scan History', icon: HistoryIcon },
  { id: 'reports', label: 'Reports', icon: FileText },
  { id: 'settings', label: 'Settings', icon: SettingsIcon },
  { id: 'help', label: 'Help and Privacy', icon: HelpCircle },
  { id: 'account', label: 'Account and License', icon: KeyRound },
];

const PAGES: Record<Page, () => React.JSX.Element> = { home: Home, scan: Scan, protection: Protection, telegram: Telegram, quarantine: Quarantine, history: History, reports: Reports, settings: Settings, help: Help, account: Account };

function Shell() {
  const { status, statusError, page, go, scan, toasts, dismissToast, confirmFull, dismissFullScan, startFullScan } = useApp();
  const Page = PAGES[page];
  const level = status?.protection.level;
  const dot = level === 'protected' ? 'bg-ok' : level === 'attention' ? 'bg-warn' : 'bg-danger';

  if (!status && !statusError) {
    return (
      <div className="ambient grid h-full place-items-center">
        <Logo size={56} />
      </div>
    );
  }
  if (status && !status.settings.onboardingDone) return <Onboarding />;

  return (
    <div className="ambient flex h-full">
      <nav aria-label="Main" className="flex w-60 shrink-0 flex-col border-r border-line px-3 py-5" style={{ background: 'color-mix(in srgb, var(--bg-elev) 70%, transparent)' }}>
        <div className="mb-6 flex items-center gap-3 px-3">
          <Logo size={34} />
          <div>
            <div className="text-base font-semibold leading-tight tracking-tight text-ink">SENTRIX</div>
            <div className="text-[11px] text-muted">Intelligent File Security</div>
          </div>
        </div>
        <ul className="space-y-1">
          {NAV.map(({ id, label, icon: Icon }) => (
            <li key={id}>
              <button
                onClick={() => go(id)}
                aria-current={page === id ? 'page' : undefined}
                className={`flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition ${page === id ? 'bg-surface2 text-ink shadow-sm' : 'text-muted hover:bg-surface2/60 hover:text-ink'}`}
              >
                <Icon className={`size-[18px] ${page === id ? 'text-accent' : ''}`} strokeWidth={1.8} aria-hidden />
                {label}
                {id === 'scan' && scan.running && <Activity className="ml-auto size-4 animate-pulse text-accent" aria-label="Scan running" />}
              </button>
            </li>
          ))}
        </ul>
        <div className="mt-auto rounded-xl border border-line px-3 py-3 text-xs text-muted">
          <div className="flex items-center gap-2">
            <span className={`size-2 rounded-full ${dot}`} aria-hidden />
            <span className="font-medium text-ink">{status ? status.protection.headline : 'Status unavailable'}</span>
          </div>
          {status && <div className="mt-1">v{status.version}</div>}
        </div>
      </nav>

      <main className="min-w-0 flex-1 overflow-auto" id="main" tabIndex={-1}>
        {typeof window !== 'undefined' && window.__SENTRIX_MOCK__ && (
          <div role="status" className="sticky top-0 z-[70] bg-warn px-4 py-1.5 text-center text-xs font-semibold text-black">MOCK DATA: development preview ({window.__SENTRIX_MOCK__}). Nothing on this screen is real.</div>
        )}
        <div className="mx-auto max-w-[1180px] px-8 py-8">
          {statusError && !status && <div className="rounded-xl bg-dangerbg px-4 py-3 text-sm text-danger">SENTRIX could not start its security engine: {statusError}</div>}
          <Page key={page} />
        </div>
      </main>

      <Modal
        open={confirmFull}
        onClose={dismissFullScan}
        title="Start a full system scan?"
        footer={
          <>
            <Button onClick={dismissFullScan}>Not now</Button>
            <Button
              variant="primary"
              onClick={() => {
                dismissFullScan();
                void startFullScan();
              }}
            >
              Start full scan
            </Button>
          </>
        }
      >
        <p>SENTRIX will read every file on all fixed drives. On a typical computer this takes <span className="font-medium text-ink">from tens of minutes to several hours</span> and uses noticeable CPU and disk activity.</p>
        <p className="mt-2">You can keep using your computer and cancel at any time. Files that cannot be read are listed, never counted as clean.</p>
      </Modal>

      <div className="pointer-events-none fixed bottom-5 right-5 z-[60] flex w-96 flex-col gap-2" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} role={t.tone === 'danger' ? 'alert' : 'status'} className={`rise pointer-events-auto flex items-start gap-3 rounded-xl border px-4 py-3 text-sm shadow-xl backdrop-blur ${t.tone === 'danger' ? 'border-danger/40 bg-dangerbg text-danger' : t.tone === 'warn' ? 'border-warn/40 bg-warnbg text-warn' : t.tone === 'ok' ? 'border-ok/40 bg-okbg text-ok' : 'border-info/40 bg-infobg text-info'}`} style={{ backgroundColor: 'var(--surface-solid)' }}>
            <span className="flex-1 text-ink">{t.text}</span>
            <button aria-label="Dismiss" className="text-muted hover:text-ink" onClick={() => dismissToast(t.id)}>
              <X className="size-4" />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AppProvider>
      <Shell />
    </AppProvider>
  );
}

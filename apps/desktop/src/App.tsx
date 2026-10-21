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

const NAV: { title: string | null; items: { id: Page; label: string; icon: typeof HomeIcon }[] }[] = [
  {
    title: null,
    items: [
      { id: 'home', label: 'Overview', icon: HomeIcon },
      { id: 'scan', label: 'Scan', icon: ScanSearch },
    ],
  },
  {
    title: 'Protection',
    items: [
      { id: 'protection', label: 'Real-Time Protection', icon: ShieldCheck },
      { id: 'telegram', label: 'Telegram Protection', icon: Send },
      { id: 'quarantine', label: 'Quarantine', icon: Archive },
    ],
  },
  {
    title: 'Records',
    items: [
      { id: 'history', label: 'Scan History', icon: HistoryIcon },
      { id: 'reports', label: 'Reports', icon: FileText },
    ],
  },
  {
    title: 'Application',
    items: [
      { id: 'settings', label: 'Settings', icon: SettingsIcon },
      { id: 'account', label: 'Account and License', icon: KeyRound },
      { id: 'help', label: 'Help and Privacy', icon: HelpCircle },
    ],
  },
];

const PAGES: Record<Page, () => React.JSX.Element> = { home: Home, scan: Scan, protection: Protection, telegram: Telegram, quarantine: Quarantine, history: History, reports: Reports, settings: Settings, help: Help, account: Account };

function Shell() {
  const { status, statusError, page, go, scan, toasts, dismissToast, confirmFull, dismissFullScan, startFullScan } = useApp();
  const Page = PAGES[page];
  const level = status?.protection.level;
  const dot = level === 'protected' ? 'bg-ok' : level === 'attention' ? 'bg-warn' : 'bg-danger';

  if (!status && !statusError) {
    return (
      <div className="grid h-full place-items-center">
        <Logo size={56} />
      </div>
    );
  }
  if (status && !status.settings.onboardingDone) return <Onboarding />;

  return (
    <div className="flex h-full">
      <nav aria-label="Main" className="flex w-56 shrink-0 flex-col border-r border-line bg-elev">
        <div className="flex h-14 items-center gap-2.5 px-4">
          <Logo size={26} />
          <span className="text-[13px] font-semibold tracking-[0.12em] text-ink">SENTRIX</span>
        </div>
        <div className="flex-1 overflow-auto px-2 pb-3">
          {NAV.map((g, gi) => (
            <div key={g.title ?? gi} className={gi ? 'mt-4' : ''}>
              {g.title && <div className="px-3 pb-1 text-xs font-semibold text-faint">{g.title}</div>}
              <ul>
                {g.items.map(({ id, label, icon: Icon }) => (
                  <li key={id}>
                    <button
                      onClick={() => go(id)}
                      aria-current={page === id ? 'page' : undefined}
                      className={`relative flex h-8 w-full items-center gap-2.5 rounded px-3 text-sm transition-colors ${page === id ? 'bg-surface2 font-semibold text-ink' : 'text-muted hover:bg-surface2/70 hover:text-ink'}`}
                    >
                      {page === id && <span className="absolute inset-y-1.5 left-0 w-[3px] rounded-full bg-accent" aria-hidden />}
                      <Icon className="size-4" strokeWidth={1.6} aria-hidden />
                      {label}
                      {id === 'scan' && scan.running && <Activity className="ml-auto size-3.5 animate-pulse text-accent" aria-label="Scan running" />}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <div className="border-t border-line px-4 py-3 text-xs">
          <div className="flex items-center gap-2">
            <span className={`size-2 shrink-0 rounded-full ${dot}`} aria-hidden />
            <span className="truncate font-semibold text-ink">{status ? status.protection.headline : 'Status unavailable'}</span>
          </div>
          {status && <div className="mt-0.5 pl-4 text-faint">Version {status.version}</div>}
        </div>
      </nav>

      <main className="min-w-0 flex-1 overflow-auto" id="main" tabIndex={-1}>
        {typeof window !== 'undefined' && window.__SENTRIX_MOCK__ && (
          <div role="status" className="sticky top-0 z-[70] bg-warn px-4 py-1 text-center text-xs font-semibold text-black">MOCK DATA: development preview ({window.__SENTRIX_MOCK__}). Nothing on this screen is real.</div>
        )}
        <div className="mx-auto max-w-[1080px] px-8 py-6">
          {statusError && !status && <div className="rounded border-l-[3px] border-danger bg-dangerbg px-4 py-2.5 text-sm text-ink">SENTRIX could not start its security engine: {statusError}</div>}
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
          <div key={t.id} role={t.tone === 'danger' ? 'alert' : 'status'} className={`panel pointer-events-auto flex items-start gap-3 rounded border-l-[3px] px-4 py-2.5 text-sm shadow-lg ${t.tone === 'danger' ? 'border-l-danger' : t.tone === 'warn' ? 'border-l-warn' : t.tone === 'ok' ? 'border-l-ok' : 'border-l-info'}`}>
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

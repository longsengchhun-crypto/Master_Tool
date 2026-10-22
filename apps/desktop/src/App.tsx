import { Activity, History as HistoryIcon, Home as HomeIcon, ScanSearch, Send, Settings as SettingsIcon, ShieldCheck, Archive, X } from 'lucide-react';
import { AppProvider, useApp, type Page } from './lib/app';
import { Logo } from './components/Logo';
import { Onboarding } from './components/Onboarding';
import { Button, Modal } from './components/ui';
import { Home } from './pages/Home';
import { Scan } from './pages/Scan';
import { Protection } from './pages/Protection';
import { Quarantine } from './pages/Quarantine';
import { History } from './pages/History';
import { Settings } from './pages/Settings';
import { Telegram } from './pages/Telegram';

const NAV: { heading: string; items: { id: Page; label: string; icon: typeof HomeIcon }[] }[] = [
  {
    heading: 'Protect',
    items: [
      { id: 'home', label: 'Home', icon: HomeIcon },
      { id: 'scan', label: 'Scan', icon: ScanSearch },
      { id: 'protection', label: 'Protection', icon: ShieldCheck },
      { id: 'telegram', label: 'Telegram', icon: Send },
    ],
  },
  {
    heading: 'Review',
    items: [
      { id: 'history', label: 'History', icon: HistoryIcon },
      { id: 'quarantine', label: 'Quarantine', icon: Archive },
    ],
  },
  { heading: 'App', items: [{ id: 'settings', label: 'Settings', icon: SettingsIcon }] },
];

const PAGES: Record<Page, () => React.JSX.Element> = { home: Home, scan: Scan, history: History, quarantine: Quarantine, protection: Protection, telegram: Telegram, settings: Settings };

function Shell() {
  const { status, statusError, page, go, scan, danger, toasts, dismissToast, confirmFull, dismissFullScan, startFullScan } = useApp();
  const Page = PAGES[page];
  const needsAction = danger.length;
  const level = danger.length ? 'at_risk' : status?.protection.level;
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
      <nav aria-label="Main" className="flex w-56 shrink-0 flex-col bg-side">
        <div className="flex h-16 items-center gap-3 px-5">
          <Logo size={30} />
          <span className="font-display text-[1.05rem] font-semibold tracking-[0.12em] text-sidestrong">SENTRIX</span>
        </div>
        <div className="flex-1 space-y-5 overflow-auto px-3 py-3">
          {NAV.map((g) => (
            <div key={g.heading}>
              <h2 className="px-3 pb-1.5 text-[0.65rem] font-semibold uppercase tracking-[0.18em] text-sidetext/60">{g.heading}</h2>
              <ul className="space-y-0.5">
                {g.items.map(({ id, label, icon: Icon }) => (
                  <li key={id}>
                    <button
                      onClick={() => go(id)}
                      aria-current={page === id ? 'page' : undefined}
                      className={`relative flex h-10 w-full items-center gap-3 rounded-lg px-3 text-sm transition-colors ${page === id ? 'bg-sideactive font-semibold text-sidestrong' : 'text-sidetext hover:bg-sidehover hover:text-sidestrong'}`}
                    >
                      {page === id && <span className="absolute inset-y-2 left-0 w-[3px] rounded-full bg-sideaccent" aria-hidden />}
                      <Icon className="size-[18px]" strokeWidth={1.6} aria-hidden />
                      {label}
                      {id === 'scan' && scan.running && <Activity className="ml-auto size-4 animate-pulse text-sideaccent" aria-label="Scan running" />}
                      {id === 'history' && needsAction > 0 && <span className="ml-auto grid min-w-5 place-items-center rounded-full bg-danger px-1.5 text-[11px] font-semibold text-white" aria-label={`${needsAction} need action`}>{needsAction}</span>}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <div className="border-t border-sideline px-5 py-4 text-xs text-sidetext">
          <div className="flex items-center gap-2">
            <span className={`size-2 shrink-0 rounded-full ${dot} ${level === 'protected' ? 'breathe text-ok' : ''}`} aria-hidden />
            <span className="truncate font-semibold text-sidestrong">{!status ? 'Status unavailable' : danger.length ? 'Action needed' : status.protection.headline}</span>
          </div>
        </div>
      </nav>

      <main className="min-w-0 flex-1 overflow-auto" id="main" tabIndex={-1}>
        {typeof window !== 'undefined' && window.__SENTRIX_MOCK__ && (
          <div role="status" className="sticky top-0 z-[70] bg-warn px-4 py-1 text-center text-xs font-semibold text-black">MOCK DATA: development preview ({window.__SENTRIX_MOCK__}). Nothing on this screen is real.</div>
        )}
        <div className="mx-auto max-w-[960px] px-10 py-8">
          {statusError && !status && <div className="rounded border-l-[3px] border-danger bg-dangerbg px-4 py-2.5 text-sm text-ink">SENTRIX could not start its security engine: {statusError}</div>}
          <div key={page} className="fade-in"><Page /></div>
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

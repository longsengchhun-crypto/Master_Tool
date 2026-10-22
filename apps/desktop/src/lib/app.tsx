import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { listen } from '@tauri-apps/api/event';
import { getCurrentWebview } from '@tauri-apps/api/webview';
import { api, errText } from './api';
import type { AppStatus, BatchOut, Progress, ScanReport } from './types';

export type Page = 'home' | 'scan' | 'history' | 'quarantine' | 'protection' | 'telegram' | 'settings';

export interface Toast {
  id: number;
  tone: 'ok' | 'warn' | 'danger' | 'info';
  text: string;
}

interface ScanState {
  running: boolean;
  kind: 'paths' | 'full' | null;
  progress: Progress | null;
  result: BatchOut | null;
  error: string | null;
}

interface Ctx {
  status: AppStatus | null;
  statusError: string | null;
  refresh: () => Promise<void>;
  page: Page;
  go: (p: Page) => void;
  reportId: string | null;
  openReport: (id: string) => void;
  scan: ScanState;
  startScan: (paths: string[], force?: boolean) => Promise<void>;
  startFullScan: () => Promise<void>;
  /** Heavy action: opens a confirmation dialog first instead of starting immediately. */
  requestFullScan: () => void;
  confirmFull: boolean;
  dismissFullScan: () => void;
  cancelScan: () => Promise<void>;
  toast: (tone: Toast['tone'], text: string) => void;
  toasts: Toast[];
  dismissToast: (id: number) => void;
  realtimeFeed: ScanReport[];
  /** Confirmed-malicious files that have not been quarantined (one per distinct content hash). */
  danger: ScanReport[];
  reloadDanger: () => Promise<void>;
}

const AppCtx = createContext<Ctx | null>(null);
export const useApp = () => {
  const c = useContext(AppCtx);
  if (!c) throw new Error('useApp outside provider');
  return c;
};

export function AppProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [page, setPage] = useState<Page>('home');
  const [reportId, setReportId] = useState<string | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [realtimeFeed, setFeed] = useState<ScanReport[]>([]);
  const [danger, setDanger] = useState<ScanReport[]>([]);
  const [scan, setScan] = useState<ScanState>({ running: false, kind: null, progress: null, result: null, error: null });
  const [confirmFull, setConfirmFull] = useState(false);
  const toastId = useRef(0);
  const scanning = useRef(false);

  const refresh = useCallback(async () => {
    try {
      setStatus(await api.status());
      setStatusError(null);
    } catch (e) {
      setStatusError(errText(e));
    }
  }, []);

  const reloadDanger = useCallback(async () => {
    try {
      const h = await api.history(500);
      const seen = new Set<string>();
      const out: ScanReport[] = [];
      for (const r of h) {
        // Files received through Telegram groups or the bot are scanned from memory and removed: there is nothing on disk to act on.
        if (r.verdict !== 'MALICIOUS' || r.quarantined || r.file.path.startsWith('[')) continue;
        const k = r.file.sha256 || r.file.path;
        if (!seen.has(k)) {
          seen.add(k);
          out.push(r);
        }
      }
      setDanger(out);
    } catch {
      /* the badge simply stays as it was */
    }
  }, []);

  const toast = useCallback((tone: Toast['tone'], text: string) => {
    const id = ++toastId.current;
    setToasts((t) => [...t, { id, tone, text }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), tone === 'danger' ? 9000 : 5000);
  }, []);

  const dismissToast = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);

  const go = useCallback((p: Page) => setPage(p), []);
  const openReport = useCallback((id: string) => {
    setReportId(id);
    setPage('history');
  }, []);

  const runScan = useCallback(
    async (kind: 'paths' | 'full', job: () => Promise<BatchOut>) => {
      if (scanning.current) {
        toast('warn', 'A scan is already running.');
        return;
      }
      scanning.current = true;
      setScan({ running: true, kind, progress: null, result: null, error: null });
      setPage('scan');
      try {
        const result = await job();
        setScan({ running: false, kind, progress: null, result, error: null });
        const bad = result.reports.filter((r) => r.verdict === 'MALICIOUS').length;
        if (result.cancelled) toast('info', 'Scan cancelled. Results so far are saved.');
        else if (bad) toast('danger', `${bad} malicious file${bad > 1 ? 's' : ''} found.`);
      } catch (e) {
        setScan({ running: false, kind, progress: null, result: null, error: errText(e) });
      } finally {
        scanning.current = false;
        void refresh();
      }
    },
    [refresh, toast],
  );

  const startScan = useCallback((paths: string[], force = false) => runScan('paths', () => api.scanPaths(paths, force)), [runScan]);
  const startFullScan = useCallback(() => runScan('full', () => api.fullScan()), [runScan]);
  const requestFullScan = useCallback(() => setConfirmFull(true), []);
  const dismissFullScan = useCallback(() => setConfirmFull(false), []);
  const cancelScan = useCallback(async () => {
    await api.cancelScan();
  }, []);

  // Backend events.
  useEffect(() => {
    const subs = [
      listen<Progress>('scan-progress', (e) => setScan((s) => ({ ...s, progress: e.payload }))),
      listen<ScanReport>('realtime-report', (e) => {
        setFeed((f) => [e.payload, ...f].slice(0, 30));
        void refresh();
      }),
      listen('engine-state-changed', () => void refresh()),
      listen('protection-update', () => void refresh()),
      listen<string>('update-installing', (e) => toast('info', `Installing SENTRIX ${e.payload}. The app restarts in a moment.`)),
      listen<string>('navigate', (e) => setPage(e.payload as Page)),
    ];
    return () => {
      subs.forEach((p) => p.then((un) => un()));
    };
  }, [refresh]);

  // Drag and drop anywhere in the window starts a scan.
  useEffect(() => {
    const un = getCurrentWebview().onDragDropEvent((e) => {
      if (e.payload.type === 'drop' && e.payload.paths.length) void startScan(e.payload.paths);
    });
    return () => {
      void un.then((f) => f());
    };
  }, [startScan]);

  // Poll status so the dashboard reflects the engine's real state (it can stop or go stale on its own).
  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), 8000);
    return () => clearInterval(t);
  }, [refresh]);

  // Dangerous-file list follows scan activity.
  useEffect(() => {
    void reloadDanger();
  }, [reloadDanger, status?.stats.scansTotal, status?.stats.quarantined]);

  // Theme.
  useEffect(() => {
    const theme = status?.settings.theme ?? 'system';
    const apply = () => {
      const dark = theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
      document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
    };
    apply();
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    mq.addEventListener('change', apply);
    return () => mq.removeEventListener('change', apply);
  }, [status?.settings.theme]);

  const value = useMemo<Ctx>(
    () => ({ danger, reloadDanger, status, statusError, refresh, page, go, reportId, openReport, scan, startScan, startFullScan, requestFullScan, confirmFull, dismissFullScan, cancelScan, toast, toasts, dismissToast, realtimeFeed }),
    [danger, reloadDanger, status, statusError, refresh, page, go, reportId, openReport, scan, startScan, startFullScan, requestFullScan, confirmFull, dismissFullScan, cancelScan, toast, toasts, dismissToast, realtimeFeed],
  );
  return <AppCtx.Provider value={value}>{children}</AppCtx.Provider>;
}

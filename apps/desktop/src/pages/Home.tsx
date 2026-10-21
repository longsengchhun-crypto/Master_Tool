import { useEffect, useState } from 'react';
import { open } from '@tauri-apps/plugin-dialog';
import { AlertTriangle, ArrowRight, CheckCircle2, FileSearch, HardDrive, ShieldAlert } from 'lucide-react';
import { useApp } from '../lib/app';
import { api, errText } from '../lib/api';
import { ago, splitPath } from '../lib/format';
import { usePolled } from '../lib/hooks';
import type { ScanReport } from '../lib/types';
import { Button, Card, Empty, Notice, Section, VerdictBadge } from '../components/ui';

const TONE = {
  protected: { bar: 'bg-ok', tint: 'bg-okbg', icon: 'text-ok', Icon: CheckCircle2, title: "You're protected" },
  attention: { bar: 'bg-warn', tint: 'bg-warnbg', icon: 'text-warn', Icon: AlertTriangle, title: 'Needs a quick look' },
  at_risk: { bar: 'bg-danger', tint: 'bg-dangerbg', icon: 'text-danger', Icon: ShieldAlert, title: 'Not fully protected' },
} as const;

interface Item {
  key: string;
  tone: 'danger' | 'warn';
  text: string;
  action: string;
  run: () => void | Promise<void>;
}

export function Home() {
  const { status, statusError, startScan, requestFullScan, go, openReport, refresh, toast, scan, danger } = useApp();
  const health = usePolled(() => api.protectionHealth(), 6000);
  const tg = usePolled(() => api.tgStatus(), 10000);
  const [busy, setBusy] = useState<string | null>(null);

  if (!status) {
    return statusError ? <Notice tone="danger" title="SENTRIX could not read its status">{statusError}</Notice> : <div className="text-muted">Loading…</div>;
  }
  // A confirmed-malicious file that is still on disk outranks everything else.
  const lvl = danger.length ? 'at_risk' : status.protection.level;
  const T = danger.length ? { ...TONE.at_risk, title: 'Action needed' } : TONE[lvl];
  const eng = status.engine;
  const h = health.data;
  const t = tg.data;

  const pickFiles = async () => {
    const sel = await open({ multiple: true, title: 'Choose files to scan' });
    if (sel) void startScan(Array.isArray(sel) ? sel : [sel]);
  };

  const act = (key: string, fn: () => Promise<unknown>) => async () => {
    setBusy(key);
    try {
      await fn();
      await refresh();
    } catch (e) {
      toast('danger', errText(e));
    } finally {
      setBusy(null);
    }
  };

  // Only things the user can act on. Everything else lives on the page it belongs to.
  const items: Item[] = [];
  if (danger.length)
    items.push({ key: 'danger', tone: 'danger', text: `${danger.length} dangerous file${danger.length > 1 ? 's' : ''} found. Review and quarantine ${danger.length > 1 ? 'them' : 'it'}.`, action: 'Review', run: () => { openReport(danger[0].id); } });
  if (eng.state === 'unavailable' || eng.state === 'degraded' || !status.lastSignatureUpdate)
    items.push({ key: 'engine', tone: 'warn', text: eng.state === 'unavailable' ? 'Malware definitions are not installed, so files cannot be called safe.' : 'Malware definitions are out of date.', action: 'Update now', run: act('engine', async () => { const r = await api.updateProtection(); toast(r.ok ? 'ok' : 'danger', r.message); }) });
  if (!status.settings.realtimeMonitoring)
    items.push({ key: 'rt', tone: 'warn', text: 'Automatic scanning of new downloads is off.', action: 'Turn on', run: act('rt', () => api.setSettings({ ...status.settings, realtimeMonitoring: true })) });
  else if (h && !h.monitorRunning)
    items.push({ key: 'monitor', tone: 'danger', text: 'Automatic scanning is on but no folder is being watched.', action: 'Fix', run: () => go('protection') });
  if (h && h.queue.failed > 0)
    items.push({ key: 'failed', tone: 'warn', text: `${h.queue.failed} file${h.queue.failed > 1 ? 's' : ''} could not be checked. They are not known to be safe.`, action: 'See files', run: () => go('protection') });
  if (t && t.bot.configured && (t.bot.lastTestOk === false || t.bot.failed24h > 0))
    items.push({ key: 'tg', tone: 'warn', text: 'Telegram reports are not getting through.', action: 'Check', run: () => go('telegram') });

  return (
    <div className="space-y-6">
      <div className="panel flex flex-wrap items-center gap-6 overflow-hidden rounded-xl p-6">
        <span className={`grid size-16 shrink-0 place-items-center rounded-full ${T.tint}`}>
          <T.Icon className={`size-8 ${T.icon}`} strokeWidth={1.7} aria-hidden />
        </span>
        <div className="min-w-0 flex-1">
          <h1 className="text-2xl font-semibold tracking-tight text-ink">{T.title}</h1>
          <p className="mt-0.5 text-sm text-muted">{danger.length ? 'A dangerous file was found on this computer. Review it below.' : lvl === 'protected' ? 'Your files are being checked. No scanner is perfect, so stay careful with unknown files.' : status.protection.reasons[0] ?? status.protection.headline}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="primary" onClick={pickFiles} disabled={scan.running}>
            <FileSearch className="size-4" /> Scan files
          </Button>
          <Button onClick={requestFullScan} disabled={scan.running}>
            <HardDrive className="size-4" /> Full scan
          </Button>
        </div>
      </div>

      <section aria-label="Needs attention">
        <h2 className="mb-2 text-sm font-semibold text-ink">Needs attention</h2>
        {items.length === 0 ? (
          <Card className="flex items-center gap-3 px-5 py-4 text-sm text-muted">
            <CheckCircle2 className="size-5 text-ok" aria-hidden /> Nothing needs your attention.
          </Card>
        ) : (
          <Card className="divide-y divide-line">
            {items.map((i) => (
              <div key={i.key} className="flex items-center gap-4 px-5 py-3.5">
                <span className={`size-2 shrink-0 rounded-full ${i.tone === 'danger' ? 'bg-danger' : 'bg-warn'}`} aria-hidden />
                <span className="min-w-0 flex-1 text-sm text-ink">{i.text}</span>
                <Button variant={i.tone === 'danger' ? 'primary' : 'secondary'} busy={busy === i.key} onClick={i.run}>{i.action}</Button>
              </div>
            ))}
          </Card>
        )}
      </section>

      <Section title="Recent scans" aside={<Button variant="ghost" className="-mr-3 h-8" onClick={() => go('history')}>See all <ArrowRight className="size-3.5" /></Button>}>
        <RecentList onOpen={openReport} />
      </Section>
    </div>
  );
}

function RecentList({ onOpen }: { onOpen: (id: string) => void }) {
  const [rows, setRows] = useState<ScanReport[] | null>(null);
  const { status } = useApp();
  useEffect(() => {
    void api.history(5).then(setRows);
  }, [status?.stats.scansTotal]);
  if (rows === null) return <div className="px-5 py-4 text-sm text-muted">Loading…</div>;
  if (!rows.length) return <Empty title="No scans yet">Drop a file on this window, or press Scan files.</Empty>;
  return (
    <ul className="divide-y divide-line">
      {rows.map((r) => (
        <li key={r.id}>
          <button onClick={() => onOpen(r.id)} className="flex w-full items-center gap-4 px-5 py-3 text-left transition-colors hover:bg-surface2">
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm font-semibold text-ink">{r.file.name}</div>
              <div className="truncate text-xs text-muted">{r.origin ?? splitPath(r.file.path)[0]}</div>
            </div>
            <VerdictBadge verdict={r.verdict} incomplete={!r.complete} />
            <span className="w-20 text-right text-xs text-muted">{ago(r.finished_at)}</span>
          </button>
        </li>
      ))}
    </ul>
  );
}

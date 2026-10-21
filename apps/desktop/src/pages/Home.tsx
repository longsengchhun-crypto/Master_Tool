import { useEffect, useState } from 'react';
import { open } from '@tauri-apps/plugin-dialog';
import { ArrowRight, FileSearch, HardDrive, RefreshCw } from 'lucide-react';
import { useApp } from '../lib/app';
import { api, errText } from '../lib/api';
import { ago, agoMs, splitPath } from '../lib/format';
import { usePolled } from '../lib/hooks';
import type { ScanReport } from '../lib/types';
import { Button, Card, Empty, Notice, Row, Rows, Section, VerdictBadge } from '../components/ui';

const EDGE = { protected: 'border-l-ok', attention: 'border-l-warn', at_risk: 'border-l-danger' } as const;
const DOT = { protected: 'bg-ok', attention: 'bg-warn', at_risk: 'bg-danger' } as const;

function Count({ label, value, tone, onClick }: { label: string; value: number; tone?: 'danger' | 'warn'; onClick: () => void }) {
  const c = value > 0 && tone === 'danger' ? 'text-danger' : value > 0 && tone === 'warn' ? 'text-warn' : 'text-ink';
  return (
    <button onClick={onClick} className="px-4 py-3 text-left transition-colors hover:bg-surface2">
      <div className={`text-2xl font-semibold tabular-nums ${c}`}>{value}</div>
      <div className="text-xs text-muted">{label}</div>
    </button>
  );
}

export function Home() {
  const { status, statusError, startScan, requestFullScan, go, openReport, refresh, toast, scan } = useApp();
  const [updating, setUpdating] = useState(false);
  const health = usePolled(() => api.protectionHealth(), 5000);
  const tg = usePolled(() => api.tgStatus(), 8000);

  if (!status) {
    return statusError ? <Notice tone="danger" title="SENTRIX could not read its status">{statusError}</Notice> : <div className="text-muted">Loading…</div>;
  }
  const lvl = status.protection.level;
  const eng = status.engine;
  const h = health.data;
  const t = tg.data;

  const pickFiles = async () => {
    const sel = await open({ multiple: true, title: 'Choose files to scan' });
    if (sel) void startScan(Array.isArray(sel) ? sel : [sel]);
  };

  const update = async () => {
    setUpdating(true);
    try {
      const r = await api.updateProtection();
      toast(r.ok ? 'ok' : 'danger', r.message);
      await refresh();
    } catch (e) {
      toast('danger', errText(e));
    } finally {
      setUpdating(false);
    }
  };

  const botState = !t ? '…' : !t.bot.configured ? 'Not connected' : t.bot.lastTestOk === false ? 'Last test failed' : t.bot.connected ? `Connected${t.bot.username ? ` as @${t.bot.username}` : ''}` : 'Not verified';

  return (
    <div className="space-y-4">
      <Card className={`border-l-4 px-5 py-4 ${EDGE[lvl]}`}>
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className={`size-2.5 rounded-full ${DOT[lvl]}`} aria-hidden />
              <h1 className="text-lg font-semibold text-ink">{status.protection.headline}</h1>
            </div>
            {status.protection.reasons.length > 0 ? (
              <ul className="mt-1.5 space-y-0.5 text-sm text-muted">
                {status.protection.reasons.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            ) : (
              <p className="mt-1 text-sm text-muted">The engine is running with current signatures. No scanner finds everything, so stay careful with files from unknown sources.</p>
            )}
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant="primary" onClick={pickFiles} disabled={scan.running}>
              <FileSearch className="size-4" /> Scan files…
            </Button>
            <Button onClick={requestFullScan} disabled={scan.running}>
              <HardDrive className="size-4" /> Full system scan
            </Button>
            {(eng.state === 'unavailable' || eng.state === 'degraded' || !status.lastSignatureUpdate) && (
              <Button busy={updating} onClick={update}>
                <RefreshCw className="size-4" /> Update protection
              </Button>
            )}
          </div>
        </div>
      </Card>

      <Card className="grid grid-cols-2 divide-x divide-line overflow-hidden sm:grid-cols-4">
        <Count label="Malicious files found" value={status.stats.maliciousFiles} tone="danger" onClick={() => go('history')} />
        <Count label="Suspicious files" value={status.stats.suspiciousFiles} tone="warn" onClick={() => go('history')} />
        <Count label="In quarantine" value={status.stats.quarantined} onClick={() => go('quarantine')} />
        <Count label="Scans run" value={status.stats.scansTotal} onClick={() => go('history')} />
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Detection engine" aside={<Button variant="ghost" className="-mr-2 h-7" busy={updating} onClick={update}>Check for updates</Button>}>
          <Rows>
            <Row label="State" tone={eng.state === 'running' ? 'ok' : eng.state === 'unavailable' ? 'danger' : 'warn'}>
              {eng.state === 'running' ? 'Running' : eng.state === 'degraded' ? 'Signatures outdated' : eng.state === 'stopped' ? 'Stopped' : 'Unavailable'}
            </Row>
            <Row label="Engine">{eng.clamav_version ? eng.clamav_version.split('/')[0] : 'Not running'}</Row>
            <Row label="Signature database">{eng.clamav_version ? `v${eng.clamav_version.split('/')[1] ?? '?'}` : eng.clamav_database_present ? 'Installed' : 'Missing'}</Row>
            <Row label="Last signature update">{ago(status.lastSignatureUpdate)}</Row>
            <Row label="Last full scan">{ago(status.lastFullScan)}</Row>
          </Rows>
        </Section>

        <Section title="Automatic scanning" aside={<Button variant="ghost" className="-mr-2 h-7" onClick={() => go('protection')}>Details <ArrowRight className="size-3.5" /></Button>}>
          {h ? (
            <Rows>
              <Row label="Folder monitoring" tone={!h.realtimeEnabled ? 'muted' : h.monitorRunning ? 'ok' : 'danger'}>
                {!h.realtimeEnabled ? 'Off' : h.monitorRunning ? `Watching ${h.roots.filter((r) => r.watching).length} folder(s)` : 'Not working'}
              </Row>
              <Row label="Waiting to be scanned">{h.queue.queued + h.queue.scanning}</Row>
              <Row label="Could not be checked" tone={h.queue.failed ? 'danger' : undefined}>{h.queue.failed}</Row>
              <Row label="Results no longer current" tone={h.queue.staleResults ? 'warn' : undefined}>{h.queue.staleResults}</Row>
              <Row label="Last automatic scan">{agoMs(h.queue.lastScanAt)}</Row>
            </Rows>
          ) : (
            <p className="px-4 py-3 text-sm text-muted">{health.error ?? 'Loading…'}</p>
          )}
        </Section>

        <Section title="Telegram" aside={<Button variant="ghost" className="-mr-2 h-7" onClick={() => go('telegram')}>Manage <ArrowRight className="size-3.5" /></Button>}>
          {t ? (
            <Rows>
              <Row label="Your bot" tone={t.bot.connected && t.bot.lastTestOk !== false ? 'ok' : t.bot.configured ? 'warn' : 'muted'}>{botState}</Row>
              <Row label="Reports waiting / failed in 24 h">{t.bot.pending} / {t.bot.failed24h}</Row>
              <Row label="Last report delivered">{t.bot.lastDeliveryAt ? agoMs(t.bot.lastDeliveryAt) : 'None yet'}</Row>
              <Row label="Telegram Desktop folder">{t.desktop.watching ? 'Watching' : t.desktop.folder ? 'Not watching' : 'Not set up'}</Row>
              <Row label="Account monitoring" tone="muted">Not available in this build</Row>
            </Rows>
          ) : (
            <p className="px-4 py-3 text-sm text-muted">{tg.error ?? 'Loading…'}</p>
          )}
        </Section>

        <Section title="What SENTRIX does here">
          <Rows>
            <Row label="Scans files you choose" tone={status.capabilities.fileScanning ? 'ok' : 'muted'}>{status.capabilities.fileScanning ? 'Yes' : 'No'}</Row>
            <Row label="Scans new downloads" tone={status.capabilities.folderMonitoring && status.realtime.state === 'active' ? 'ok' : 'muted'}>
              {status.realtime.state === 'active' ? 'Yes' : status.capabilities.folderMonitoring ? 'Off' : 'Not on this platform'}
            </Row>
            <Row label="Quarantines on its own" tone="muted">{status.settings.autoQuarantine === 'malicious_only' ? 'Confirmed malware only' : 'No, you decide'}</Row>
            <Row label="Blocks confirmed malware from launching" tone={status.settings.executionGuard ? 'ok' : 'muted'}>{status.settings.executionGuard ? 'On' : 'Off'}</Row>
            <Row label="Stops downloads or other programs" tone="muted">Not possible without a driver</Row>
          </Rows>
        </Section>
      </div>

      <Section title="Recent scans" aside={<Button variant="ghost" className="-mr-2 h-7" onClick={() => go('history')}>All history <ArrowRight className="size-3.5" /></Button>}>
        <RecentList onOpen={openReport} />
      </Section>
    </div>
  );
}

function RecentList({ onOpen }: { onOpen: (id: string) => void }) {
  const [rows, setRows] = useState<ScanReport[] | null>(null);
  const { status } = useApp();
  useEffect(() => {
    void api.history(6).then(setRows);
  }, [status?.stats.scansTotal]);
  if (rows === null) return <div className="px-4 py-4 text-sm text-muted">Loading…</div>;
  if (!rows.length) return <Empty title="No scans yet">Scan a file, or drop one on this window, and the result appears here.</Empty>;
  return (
    <table className="w-full text-left text-sm">
      <tbody className="divide-y divide-line">
        {rows.map((r) => (
          <tr key={r.id} onClick={() => onOpen(r.id)} tabIndex={0} onKeyDown={(e) => e.key === 'Enter' && onOpen(r.id)} className="cursor-pointer hover:bg-surface2">
            <td className="max-w-[320px] px-4 py-2">
              <div className="truncate font-semibold text-ink">{r.file.name}</div>
              <div className="truncate text-xs text-muted">{splitPath(r.file.path)[0]}</div>
            </td>
            <td className="px-3 py-2 text-xs text-muted">{r.origin ?? 'Manual scan'}</td>
            <td className="px-3 py-2"><VerdictBadge verdict={r.verdict} incomplete={!r.complete} /></td>
            <td className="w-24 px-4 py-2 text-right text-xs text-muted">{ago(r.finished_at)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

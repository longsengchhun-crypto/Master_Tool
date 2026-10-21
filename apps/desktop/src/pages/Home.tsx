import { useEffect, useState } from 'react';
import { usePolled } from '../lib/hooks';
import { open } from '@tauri-apps/plugin-dialog';
import { Archive, ArrowRight, Check, FileSearch, HardDrive, Radar, RefreshCw, ShieldAlert, ShieldCheck, ShieldQuestion, X } from 'lucide-react';
import { useApp } from '../lib/app';
import { api, errText } from '../lib/api';
import { ago, agoMs, splitPath } from '../lib/format';
import type { ScanReport } from '../lib/types';
import { Button, Card, Empty, Notice, Pill, VerdictBadge } from '../components/ui';

const LEVEL = {
  protected: { icon: ShieldCheck, ring: 'from-ok/70 to-accent/60', text: 'text-ok', bg: 'bg-okbg' },
  attention: { icon: ShieldQuestion, ring: 'from-warn/80 to-warn/30', text: 'text-warn', bg: 'bg-warnbg' },
  at_risk: { icon: ShieldAlert, ring: 'from-danger/80 to-danger/30', text: 'text-danger', bg: 'bg-dangerbg' },
} as const;

function Stat({ label, value, tone, onClick }: { label: string; value: number | string; tone?: 'danger' | 'warn'; onClick?: () => void }) {
  return (
    <button onClick={onClick} className="glass rounded-2xl p-4 text-left transition hover:border-strong">
      <div className={`text-3xl font-semibold tabular-nums tracking-tight ${tone === 'danger' && Number(value) > 0 ? 'text-danger' : tone === 'warn' && Number(value) > 0 ? 'text-warn' : 'text-ink'}`}>{value}</div>
      <div className="mt-1 text-sm text-muted">{label}</div>
    </button>
  );
}

function Capability({ ok, label, detail, offLabel = 'Not available in this build' }: { ok: boolean; label: string; detail: string; offLabel?: string }) {
  return (
    <li className="flex items-start gap-3 py-2.5">
      <span className={`mt-0.5 grid size-5 shrink-0 place-items-center rounded-full ${ok ? 'bg-okbg text-ok' : 'bg-surface2 text-faint'}`}>{ok ? <Check className="size-3.5" /> : <X className="size-3.5" />}</span>
      <div>
        <div className="text-sm font-medium text-ink">
          {label} <span className="font-normal text-muted">· {ok ? 'Available' : offLabel}</span>
        </div>
        <div className="text-xs text-muted">{detail}</div>
      </div>
    </li>
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
  const L = LEVEL[status.protection.level];
  const Icon = L.icon;
  const eng = status.engine;

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

  return (
    <div className="space-y-6">
      <Card className="rise relative overflow-hidden p-8">
        <div className="pointer-events-none absolute -right-24 -top-24 size-80 rounded-full opacity-40 blur-3xl" style={{ background: `radial-gradient(closest-side, var(--glow), transparent)` }} />
        <div className="relative flex flex-wrap items-center gap-8">
          <div className={`relative grid size-28 shrink-0 place-items-center rounded-full bg-gradient-to-br ${L.ring} p-[3px]`}>
            <div className="grid size-full place-items-center rounded-full bg-elev">
              <Icon className={`size-12 ${L.text}`} strokeWidth={1.6} aria-hidden />
            </div>
          </div>
          <div className="min-w-0 flex-1">
            <div className={`text-sm font-medium ${L.text}`}>{status.protection.level === 'protected' ? 'All systems operating' : status.protection.level === 'attention' ? 'Action recommended' : 'Immediate attention'}</div>
            <h1 className="mt-1 text-3xl font-semibold tracking-tight text-ink">{status.protection.headline}</h1>
            {status.protection.reasons.length > 0 ? (
              <ul className="mt-3 space-y-1 text-sm text-muted">
                {status.protection.reasons.map((r, i) => (
                  <li key={i}>• {r}</li>
                ))}
              </ul>
            ) : (
              <p className="mt-3 text-sm text-muted">Detection engine is running with current signatures and new downloads are being scanned. No scanner finds everything, so stay cautious with files from unknown sources.</p>
            )}
            <div className="mt-6 flex flex-wrap gap-3">
              <Button variant="primary" className="px-6 py-3 text-base" onClick={pickFiles} disabled={scan.running}>
                <FileSearch className="size-5" /> Scan a File
              </Button>
              <Button className="px-6 py-3 text-base" onClick={requestFullScan} disabled={scan.running}>
                <HardDrive className="size-5" /> Full System Scan
              </Button>
              {(eng.state === 'unavailable' || eng.state === 'degraded' || !status.lastSignatureUpdate) && (
                <Button busy={updating} onClick={update} className="px-6 py-3 text-base">
                  <RefreshCw className="size-5" /> Update protection
                </Button>
              )}
            </div>
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Malicious files found" value={status.stats.maliciousFiles} tone="danger" onClick={() => go('history')} />
        <Stat label="Suspicious files" value={status.stats.suspiciousFiles} tone="warn" onClick={() => go('history')} />
        <Stat label="In quarantine" value={status.stats.quarantined} onClick={() => go('quarantine')} />
        <Stat label="Scans run" value={status.stats.scansTotal} onClick={() => go('history')} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-5">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-ink">Detection engine</h2>
            <Pill tone={eng.state === 'running' ? 'ok' : eng.state === 'unavailable' ? 'danger' : 'warn'}>{eng.state === 'running' ? 'Running' : eng.state === 'degraded' ? 'Signatures outdated' : eng.state === 'stopped' ? 'Stopped' : 'Unavailable'}</Pill>
          </div>
          <p className="text-sm text-muted">{eng.detail}</p>
          <dl className="mt-4 grid grid-cols-2 gap-y-2 text-sm">
            <dt className="text-muted">Engine</dt>
            <dd className="text-right text-ink">{eng.clamav_version ? eng.clamav_version.split('/')[0] : 'Not running'}</dd>
            <dt className="text-muted">Signature database</dt>
            <dd className="text-right text-ink">{eng.clamav_version ? `v${eng.clamav_version.split('/')[1] ?? '?'}` : eng.clamav_database_present ? 'Installed' : 'Missing'}</dd>
            <dt className="text-muted">Last protection update</dt>
            <dd className="text-right text-ink">{ago(status.lastSignatureUpdate)}</dd>
            <dt className="text-muted">Last full scan</dt>
            <dd className="text-right text-ink">{ago(status.lastFullScan)}</dd>
          </dl>
          <div className="mt-4">
            <Button busy={updating} onClick={update}>
              <RefreshCw className="size-4" /> Check for protection updates
            </Button>
          </div>
        </Card>

        <Card className="p-5">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-ink">What SENTRIX does on this device</h2>
            <button className="text-sm text-accent hover:underline" onClick={() => go('protection')}>
              Manage <ArrowRight className="inline size-3.5" />
            </button>
          </div>
          <ul className="divide-y divide-line">
            <Capability ok={status.capabilities.fileScanning} label="Scans files you choose" detail="Signatures, structure and heuristic checks, run locally." />
            <Capability ok={status.capabilities.folderMonitoring && status.realtime.state === 'active'} label="Scans new downloads" offLabel={status.capabilities.folderMonitoring ? 'Currently off' : 'Not available on this platform'} detail={status.realtime.state === 'active' ? `Watching ${status.realtime.watching.length} folder(s).` : 'Real-time protection is off or not running.'} />
            <Capability ok={status.capabilities.fileScanning} label="Warns and quarantines" detail="You decide what happens unless you enable automatic quarantine." />
            <Capability ok={status.capabilities.executionGuard && status.settings.executionGuard} label="Blocks confirmed-malicious files from launching" offLabel={status.capabilities.executionGuard ? 'Turned off' : 'Not available'} detail="A reversible Windows permission on files a malware engine confirmed. SENTRIX has no kernel driver, so it cannot stop other programs or a download." />
          </ul>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-5">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-ink">Automatic scanning</h2>
            <button className="text-sm text-accent hover:underline" onClick={() => go('protection')}>
              Details <ArrowRight className="inline size-3.5" />
            </button>
          </div>
          {health.data ? (
            <dl className="grid grid-cols-2 gap-y-2 text-sm">
              <dt className="text-muted">Monitoring</dt>
              <dd className={`text-right ${!health.data.realtimeEnabled ? 'text-muted' : health.data.monitorRunning ? 'text-ok' : 'text-danger'}`}>{!health.data.realtimeEnabled ? 'Off' : health.data.monitorRunning ? 'Active' : 'Not working'}</dd>
              <dt className="text-muted">Waiting to be scanned</dt>
              <dd className="text-right text-ink">{health.data.queue.queued + health.data.queue.scanning}</dd>
              <dt className="text-muted">Could not be checked</dt>
              <dd className={`text-right ${health.data.queue.failed ? 'text-danger' : 'text-ink'}`}>{health.data.queue.failed}</dd>
              <dt className="text-muted">Results no longer current</dt>
              <dd className={`text-right ${health.data.queue.staleResults ? 'text-warn' : 'text-ink'}`}>{health.data.queue.staleResults}</dd>
              <dt className="text-muted">Last automatic scan</dt>
              <dd className="text-right text-ink">{agoMs(health.data.queue.lastScanAt)}</dd>
            </dl>
          ) : (
            <p className="text-sm text-muted">{health.error ?? 'Loading…'}</p>
          )}
        </Card>

        <Card className="p-5">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-ink">Telegram</h2>
            <button className="text-sm text-accent hover:underline" onClick={() => go('telegram')}>
              Manage <ArrowRight className="inline size-3.5" />
            </button>
          </div>
          {tg.data ? (
            <dl className="grid grid-cols-2 gap-y-2 text-sm">
              <dt className="text-muted">Your bot</dt>
              <dd className={`text-right ${tg.data.bot.connected && tg.data.bot.lastTestOk !== false ? 'text-ok' : tg.data.bot.configured ? 'text-warn' : 'text-muted'}`}>{!tg.data.bot.configured ? 'Not connected' : tg.data.bot.lastTestOk === false ? 'Last test failed' : tg.data.bot.connected ? `Connected${tg.data.bot.username ? ` (@${tg.data.bot.username})` : ''}` : 'Not verified'}</dd>
              <dt className="text-muted">Reports waiting / failed (24 h)</dt>
              <dd className="text-right text-ink">{tg.data.bot.pending} / {tg.data.bot.failed24h}</dd>
              <dt className="text-muted">Last report delivered</dt>
              <dd className="text-right text-ink">{tg.data.bot.lastDeliveryAt ? agoMs(tg.data.bot.lastDeliveryAt) : 'None yet'}</dd>
              <dt className="text-muted">Telegram Desktop folder</dt>
              <dd className="text-right text-ink">{tg.data.desktop.watching ? 'Watching' : tg.data.desktop.folder ? 'Not watching' : 'Not set up'}</dd>
              <dt className="text-muted">Account monitoring</dt>
              <dd className="text-right text-muted">Not available in this build</dd>
            </dl>
          ) : (
            <p className="text-sm text-muted">{tg.error ?? 'Loading…'}</p>
          )}
        </Card>
      </div>

      <Card className="p-5">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-ink">Recent activity</h2>
          <button className="text-sm text-accent hover:underline" onClick={() => go('history')}>
            View history <ArrowRight className="inline size-3.5" />
          </button>
        </div>
        <RecentList onOpen={openReport} />
      </Card>
    </div>
  );
}

function RecentList({ onOpen }: { onOpen: (id: string) => void }) {
  const [rows, setRows] = useState<ScanReport[] | null>(null);
  const { status } = useApp();
  useEffect(() => {
    void api.history(6).then(setRows);
  }, [status?.stats.scansTotal]);
  if (rows === null) return <div className="py-6 text-sm text-muted">Loading…</div>;
  if (!rows.length) return <Empty icon={<Radar className="size-6" />} title="No scans yet">Scan a file or drop one onto this window to see results here.</Empty>;
  return (
    <ul className="divide-y divide-line">
      {rows.map((r) => (
        <li key={r.id}>
          <button onClick={() => onOpen(r.id)} className="flex w-full items-center gap-4 py-3 text-left hover:bg-surface2/60">
            <Archive className="size-5 shrink-0 text-faint" aria-hidden />
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm font-medium text-ink">{r.file.name}</div>
              <div className="truncate text-xs text-muted">{splitPath(r.file.path)[0]}</div>
            </div>
            <VerdictBadge verdict={r.verdict} incomplete={!r.complete} />
            <span className="w-20 text-right text-xs text-muted">{ago(r.finished_at)}</span>
          </button>
        </li>
      ))}
    </ul>
  );
}

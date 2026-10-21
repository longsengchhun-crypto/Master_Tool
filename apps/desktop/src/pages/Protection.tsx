import { useState } from 'react';
import { open } from '@tauri-apps/plugin-dialog';
import { AlertTriangle, FolderPlus, RefreshCw, Trash2 } from 'lucide-react';
import { api, errText } from '../lib/api';
import { useApp } from '../lib/app';
import { agoMs, splitPath, whenMs } from '../lib/format';
import { usePolled } from '../lib/hooks';
import type { Settings } from '../lib/types';
import { Button, Card, Empty, Notice, PageHeader, Pill, Toggle } from '../components/ui';

const FOLDERS: [string, string, string][] = [
  ['downloads', 'Downloads', 'Where browsers save files by default.'],
  ['desktop', 'Desktop', 'Files saved or dropped on your desktop.'],
  ['documents', 'Documents', 'Your Documents folder.'],
  ['removable', 'Removable drives', 'USB drives and similar, while they are connected.'],
];

function Tile({ label, value, tone, hint }: { label: string; value: string | number; tone?: 'ok' | 'warn' | 'danger'; hint?: string }) {
  const c = tone === 'danger' ? 'text-danger' : tone === 'warn' ? 'text-warn' : tone === 'ok' ? 'text-ok' : 'text-ink';
  return (
    <Card className="p-4">
      <div className={`text-2xl font-semibold tabular-nums tracking-tight ${c}`}>{value}</div>
      <div className="mt-1 text-sm text-ink">{label}</div>
      {hint && <div className="mt-0.5 text-xs text-muted">{hint}</div>}
    </Card>
  );
}

export function Protection() {
  const { status, refresh, toast, go } = useApp();
  const health = usePolled(() => api.protectionHealth(), 4000);
  const [saving, setSaving] = useState(false);
  const [updating, setUpdating] = useState(false);
  if (!status) return <div className="text-muted">Loading…</div>;
  const s = status.settings;
  const eng = status.engine;
  const h = health.data;
  const managed = !!status.managedBy;
  const lock = saving || managed;

  const save = async (patch: Partial<Settings>) => {
    setSaving(true);
    try {
      await api.setSettings({ ...s, ...patch });
      await refresh();
      await health.reload();
    } catch (e) {
      toast('danger', errText(e));
    } finally {
      setSaving(false);
    }
  };

  const toggleFolder = (k: string) => {
    const set = new Set(s.monitoredFolders);
    set.has(k) ? set.delete(k) : set.add(k);
    void save({ monitoredFolders: [...set] });
  };

  const addCustom = async () => {
    const sel = await open({ directory: true, title: 'Choose a folder to watch' });
    if (typeof sel === 'string' && !s.customFolders.includes(sel)) void save({ customFolders: [...s.customFolders, sel] });
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

  const retry = async (id?: string) => {
    try {
      const n = await api.retryFailedJobs(id);
      toast(n ? 'ok' : 'warn', n ? `${n} file(s) queued to be checked again.` : 'Nothing could be queued (it may already be waiting).');
      await health.reload();
    } catch (e) {
      toast('danger', errText(e));
    }
  };

  const rtOn = s.realtimeMonitoring;
  const running = !!h?.monitorRunning;

  return (
    <div className="space-y-6">
      <PageHeader title="Real-Time Protection" subtitle="What SENTRIX is watching right now, what it could not check, and what it may do on its own. Scanning, warning and blocking are different things, so each is described separately." />

      {managed && (
        <Notice tone="info" title={`These settings are managed by ${status.managedBy}`}>
          Your organization controls real-time protection, watched folders, automatic quarantine and scan limits. You can see them here but not change them. To control them yourself, leave management under Account and License.
        </Notice>
      )}

      {health.error && <Notice tone="danger" title="Protection status is unavailable">{health.error}</Notice>}

      {h && (
        <>
          {rtOn && !running && (
            <Notice tone="danger" title="Real-time protection is on but nothing is being watched">
              {h.roots.length === 0 ? 'No folder is selected below.' : 'None of the selected folders could be watched. See "Watched folders" for the reason.'} New files are NOT being scanned automatically.
            </Notice>
          )}
          {rtOn && !h.resumesAfterRestart && (
            <Notice tone="warn" title="Protection will not restart by itself after you restart your computer">
              SENTRIX runs as an app in your system tray, not as a Windows service. It only starts after a restart if you turn on <button className="underline" onClick={() => go('settings')}>"Start SENTRIX when I sign in"</button> in Settings. Files that arrive while SENTRIX is closed are scanned the next time it starts.
            </Notice>
          )}
          {h.queue.stuck > 0 && <Notice tone="danger" title={`${h.queue.stuck} scan(s) appear to be stuck`}>They are recovered automatically, but if this keeps happening restart SENTRIX.</Notice>}

          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Tile label="Real-time monitoring" value={!rtOn ? 'Off' : running ? 'On' : 'Not working'} tone={!rtOn ? undefined : running ? 'ok' : 'danger'} hint={running ? `Last file event ${agoMs(h.lastFileEventAt)}` : undefined} />
            <Tile label="Scanner engine" value={h.engine.state === 'running' ? 'Healthy' : h.engine.state === 'degraded' ? 'Outdated' : h.engine.state === 'stopped' ? 'Stopped' : 'Unavailable'} tone={h.engine.state === 'running' ? 'ok' : h.engine.state === 'unavailable' ? 'danger' : 'warn'} hint={h.engine.clamav_version?.split('/')[0]} />
            <Tile label="Waiting to be scanned" value={h.queue.queued + h.queue.scanning} tone={h.queue.queued > 50 ? 'warn' : undefined} hint={h.queue.oldestQueuedSeconds != null ? `Oldest waiting ${h.queue.oldestQueuedSeconds}s` : 'Nothing waiting'} />
            <Tile label="Could not be checked" value={h.queue.failed} tone={h.queue.failed > 0 ? 'danger' : undefined} hint="Never counted as safe" />
            <Tile label="Files checked on this device" value={h.queue.filesScanned.toLocaleString()} hint={`Last successful scan ${agoMs(h.queue.lastScanAt)}`} />
            <Tile label="Results no longer current" value={h.queue.staleResults} tone={h.queue.staleResults > 0 ? 'warn' : undefined} hint="File changed after it was scanned" />
            <Tile label="Notifications waiting" value={h.outbox.pending} tone={h.outbox.pending > 0 ? 'warn' : undefined} hint={h.outbox.failed24h ? `${h.outbox.failed24h} failed in 24 h` : undefined} />
            <Tile label="Folder check" value={agoMs(h.lastReconcileAt)} hint="Catches files that arrived while SENTRIX was closed" />
          </div>
        </>
      )}

      <Card className="p-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-ink">Real-time protection</h2>
            <p className="mt-1 text-sm text-muted">Scans new files in the folders below shortly after they finish downloading. It scans after a file arrives: it does not stop a download or a program from running.</p>
          </div>
          <Pill tone={!rtOn ? 'muted' : running ? 'ok' : 'danger'}>{!rtOn ? 'Off' : running ? 'Active' : 'Problem'}</Pill>
        </div>
        <div className="mt-2 divide-y divide-line">
          <Toggle checked={rtOn} disabled={lock} onChange={(v) => save({ realtimeMonitoring: v })} label="Watch folders for new files" description={status.realtime.detail} />
        </div>
        <fieldset className="mt-4 grid gap-3 sm:grid-cols-2" disabled={!rtOn || lock}>
          <legend className="sr-only">Folders to watch</legend>
          {FOLDERS.map(([k, label, desc]) => (
            <label key={k} className={`flex cursor-pointer items-start gap-3 rounded-xl border p-3 transition ${s.monitoredFolders.includes(k) ? 'border-accent/50 bg-accent/5' : 'border-line'} ${!rtOn ? 'opacity-50' : ''}`}>
              <input type="checkbox" className="mt-1 size-4 accent-[var(--accent)]" checked={s.monitoredFolders.includes(k)} onChange={() => toggleFolder(k)} />
              <span>
                <span className="block text-sm font-medium text-ink">{label}</span>
                <span className="block text-xs text-muted">{desc}</span>
              </span>
            </label>
          ))}
        </fieldset>
        <div className="mt-4">
          {s.customFolders.map((f) => (
            <div key={f} className="mb-2 flex items-center justify-between gap-3 rounded-xl border border-line px-3 py-2 text-sm">
              <span className="truncate font-mono text-xs text-ink">{f}</span>
              <button aria-label={`Stop watching ${f}`} className="rounded-lg p-1.5 text-muted hover:bg-surface2 hover:text-danger" disabled={managed} onClick={() => save({ customFolders: s.customFolders.filter((x) => x !== f) })}>
                <Trash2 className="size-4" />
              </button>
            </div>
          ))}
          <Button onClick={addCustom} disabled={!rtOn || managed}>
            <FolderPlus className="size-4" /> Add a folder
          </Button>
        </div>
        <p className="mt-4 text-xs text-muted">Telegram Desktop's folder is set up on the Telegram Protection page. SENTRIX watches folders, not programs: it does not hook into browsers or email apps.</p>
      </Card>

      <Card className="overflow-hidden">
        <div className="border-b border-line px-6 py-4">
          <h2 className="text-base font-semibold text-ink">Watched folders</h2>
          <p className="mt-0.5 text-sm text-muted">The real state of each folder, not just what is selected.</p>
        </div>
        {!h ? (
          <div className="p-6 text-sm text-muted">Loading…</div>
        ) : h.roots.length === 0 ? (
          <Empty icon={<AlertTriangle className="size-6" />} title="No folders are selected">Choose folders above to have new files scanned automatically.</Empty>
        ) : (
          <ul className="divide-y divide-line">
            {h.roots.map((r) => (
              <li key={r.path} className="flex items-center justify-between gap-4 px-6 py-3">
                <div className="min-w-0">
                  <div className="text-sm font-medium text-ink">{r.label}</div>
                  <div className="truncate font-mono text-xs text-muted" title={r.path}>{r.path}</div>
                  {r.error && <div className="mt-0.5 text-xs text-warn">{r.error}</div>}
                </div>
                <Pill tone={r.watching ? 'ok' : r.exists ? 'warn' : 'danger'}>{r.watching ? 'Watching' : !rtOn ? 'Not watched (off)' : r.exists ? 'Not watched' : 'Not available'}</Pill>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card className="overflow-hidden">
        <div className="flex items-center justify-between border-b border-line px-6 py-4">
          <div>
            <h2 className="text-base font-semibold text-ink">Files that could not be checked</h2>
            <p className="mt-0.5 text-sm text-muted">SENTRIX tried several times. These are <strong className="text-ink">not</strong> known to be safe.</p>
          </div>
          {!!h?.couldNotCheck.length && <Button onClick={() => retry()}>Try all again</Button>}
        </div>
        {!h?.couldNotCheck.length ? (
          <div className="px-6 py-5 text-sm text-muted">Nothing is waiting. Every file SENTRIX noticed was either checked or is still being retried.</div>
        ) : (
          <ul className="divide-y divide-line">
            {h.couldNotCheck.map((j) => (
              <li key={j.id} className="flex items-start justify-between gap-4 px-6 py-3">
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium text-ink" title={j.path}>{splitPath(j.path)[1]}</div>
                  <div className="truncate text-xs text-muted">{splitPath(j.path)[0]} · {j.source} · {j.attempts} attempts · {agoMs(j.updatedAt)}</div>
                  {j.lastError && <div className="mt-0.5 text-xs text-warn">{j.lastError}</div>}
                </div>
                <Button onClick={() => retry(j.id)}>Try again</Button>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card className="p-6">
        <h2 className="text-base font-semibold text-ink">What SENTRIX may do on its own</h2>
        <div className="mt-3 space-y-2">
          {([
            ['off', 'Warn me only', 'Show a notification and let me decide. Nothing is moved or deleted automatically.'],
            ['malicious_only', 'Quarantine confirmed malware', 'Move a file to quarantine only when a malware-signature engine identifies it as malicious. Suspicious files are never touched automatically, and nothing is ever deleted without your confirmation.'],
          ] as const).map(([v, label, desc]) => (
            <label key={v} className={`flex cursor-pointer items-start gap-3 rounded-xl border p-4 transition ${s.autoQuarantine === v ? 'border-accent/50 bg-accent/5' : 'border-line'}`}>
              <input type="radio" name="aq" disabled={managed} className="mt-1 size-4 accent-[var(--accent)]" checked={s.autoQuarantine === v} onChange={() => save({ autoQuarantine: v })} />
              <span>
                <span className="block text-sm font-medium text-ink">{label}</span>
                <span className="block text-sm text-muted">{desc}</span>
              </span>
            </label>
          ))}
        </div>
        <div className="mt-3 divide-y divide-line">
          <Toggle
            checked={s.executionGuard}
            disabled={lock}
            onChange={(v) => save({ executionGuard: v })}
            label="Block confirmed-malicious programs from being launched"
            description="When a file is confirmed malicious and is not quarantined, Windows is told to refuse to run it (a reversible permission on that one file). It does not stop scripts from being read, documents from being opened, or anything that was already running, and it cannot stop a download. You can undo it for any file."
          />
          <Toggle checked={s.allowRestoreSuspicious} disabled={managed} onChange={(v) => save({ allowRestoreSuspicious: v })} label="Let me restore or dismiss suspicious files" description="Restoring a file identified as malicious always needs an extra confirmation." />
        </div>
      </Card>

      <Card className="p-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-ink">Detection engine</h2>
            <p className="mt-1 text-sm text-muted">{eng.detail}</p>
          </div>
          <Pill tone={eng.state === 'running' ? 'ok' : eng.state === 'unavailable' ? 'danger' : 'warn'}>{eng.state}</Pill>
        </div>
        <dl className="mt-4 grid max-w-xl grid-cols-2 gap-y-2 text-sm">
          <dt className="text-muted">Malware engine</dt>
          <dd className="text-ink">{eng.clamav_version ?? (eng.clamav_installed ? 'Installed, not running' : 'Not installed')}</dd>
          <dt className="text-muted">Signature age</dt>
          <dd className="text-ink">{eng.database_age_hours == null ? 'No database' : `${eng.database_age_hours} h`}</dd>
          <dt className="text-muted">SENTRIX analysis core</dt>
          <dd className="text-ink">{eng.core_version}</dd>
        </dl>
        <div className="mt-4 flex gap-3">
          <Button variant="primary" busy={updating} onClick={update}>
            <RefreshCw className="size-4" /> Update protection
          </Button>
          <Button onClick={() => api.startEngine().then(() => refresh()).catch((e) => toast('danger', errText(e)))}>Restart engine</Button>
        </div>
        <p className="mt-3 text-xs text-muted">Updating downloads malware signatures from ClamAV's public servers. Those requests contain no information about your files.</p>
      </Card>

      <Card className="overflow-hidden">
        <div className="border-b border-line px-6 py-4">
          <h2 className="text-base font-semibold text-ink">Recent protection events</h2>
        </div>
        {!h?.recentEvents.length ? (
          <div className="px-6 py-5 text-sm text-muted">No events yet.</div>
        ) : (
          <ul className="max-h-96 divide-y divide-line overflow-auto">
            {h.recentEvents.map((e) => (
              <li key={e.id} className="flex items-start gap-3 px-6 py-2.5 text-sm">
                <span className={`mt-1.5 size-2 shrink-0 rounded-full ${e.severity === 'critical' ? 'bg-danger' : e.severity === 'warning' ? 'bg-warn' : 'bg-faint'}`} aria-label={e.severity} />
                <span className="min-w-0 flex-1 text-ink">{e.message}</span>
                <span className="shrink-0 text-xs text-muted" title={whenMs(e.ts)}>{agoMs(e.ts)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card className="p-6">
        <h2 className="text-base font-semibold text-ink">Limits of this build</h2>
        <ul className="mt-3 list-disc space-y-1.5 pl-5 text-sm text-muted">
          <li>SENTRIX scans a file after it appears. It cannot intercept a download, and it cannot stop a program you start unless the execution guard has marked that file.</li>
          <li>No scanner detects everything. A clean result is not a guarantee.</li>
          <li>Windows Security (Defender) and SmartScreen keep running. SENTRIX adds checks and does not replace them.</li>
          <li>Files over the size limit, encrypted archives and unsupported formats are reported as partly checked, never as clean.</li>
        </ul>
      </Card>
    </div>
  );
}

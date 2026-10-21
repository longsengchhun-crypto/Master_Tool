import { useState } from 'react';
import { open } from '@tauri-apps/plugin-dialog';
import { FolderPlus, RefreshCw, X } from 'lucide-react';
import { api, errText } from '../lib/api';
import { useApp } from '../lib/app';
import { agoMs, ago, splitPath, whenMs } from '../lib/format';
import { usePolled } from '../lib/hooks';
import type { Settings } from '../lib/types';
import { Button, Card, Disclosure, Notice, PageHeader, Row, Rows, Toggle } from '../components/ui';

const FOLDERS: [string, string][] = [
  ['downloads', 'Downloads'],
  ['desktop', 'Desktop'],
  ['documents', 'Documents'],
  ['removable', 'USB drives'],
];

export function Protection() {
  const { status, refresh, toast, go } = useApp();
  const health = usePolled(() => api.protectionHealth(), 4000);
  const [saving, setSaving] = useState(false);
  const [updating, setUpdating] = useState(false);
  if (!status) return <div className="text-muted">Loading…</div>;
  const s = status.settings;
  const h = health.data;
  const managed = !!status.managedBy;
  const lock = saving || managed;
  const rtOn = s.realtimeMonitoring;
  const running = !!h?.monitorRunning;

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
      toast(n ? 'ok' : 'warn', n ? `${n} file(s) will be checked again.` : 'Nothing could be queued (it may already be waiting).');
      await health.reload();
    } catch (e) {
      toast('danger', errText(e));
    }
  };

  const unwatched = h?.roots.filter((r) => !r.watching) ?? [];
  const stateText = !rtOn ? 'Off' : running ? `Watching ${h?.roots.filter((r) => r.watching).length ?? 0} folder(s)` : 'Not working';

  return (
    <div className="space-y-5">
      <PageHeader title="Protection" />

      {managed && <Notice tone="info">These settings are managed by {status.managedBy}. You can look but not change them.</Notice>}
      {rtOn && h && !running && <Notice tone="danger" title="Nothing is being watched">New files are not being scanned. {h.roots.length === 0 ? 'Pick a folder below.' : 'See the folders listed under Problems.'}</Notice>}
      {rtOn && h && !h.resumesAfterRestart && (
        <Notice tone="warn">
          SENTRIX only protects you while it is running. To start it with Windows, turn on <button className="font-semibold underline" onClick={() => go('settings')}>Start when I sign in</button>.
        </Notice>
      )}

      <Card className="px-5 py-1">
        <Toggle checked={rtOn} disabled={lock} onChange={(v) => save({ realtimeMonitoring: v })} label="Scan new files automatically" description={stateText} />
        <div className="border-t border-line py-4">
          <div className="flex flex-wrap gap-2" role="group" aria-label="Folders to watch">
            {FOLDERS.map(([k, label]) => {
              const on = s.monitoredFolders.includes(k);
              return (
                <button key={k} aria-pressed={on} disabled={!rtOn || lock} onClick={() => toggleFolder(k)} className={`h-9 rounded-full border px-4 text-sm font-semibold transition-colors disabled:opacity-50 ${on ? 'border-accent bg-select text-ink' : 'border-strong bg-solid text-muted hover:text-ink'}`}>
                  {label}
                </button>
              );
            })}
            {s.customFolders.map((f) => (
              <span key={f} className="inline-flex h-9 items-center gap-1.5 rounded-full border border-accent bg-select pl-4 pr-2 text-sm font-semibold text-ink" title={f}>
                {splitPath(f)[1] || f}
                <button aria-label={`Stop watching ${f}`} disabled={managed} onClick={() => save({ customFolders: s.customFolders.filter((x) => x !== f) })} className="rounded-full p-1 text-muted hover:bg-surface2 hover:text-danger disabled:opacity-40">
                  <X className="size-3.5" />
                </button>
              </span>
            ))}
            <Button variant="ghost" onClick={addCustom} disabled={!rtOn || managed}>
              <FolderPlus className="size-4" /> Add folder
            </Button>
          </div>
          <p className="mt-3 text-xs text-muted">Telegram Desktop downloads are set up on the Telegram page.</p>
        </div>
      </Card>

      <Card className="divide-y divide-line px-5 py-1">
        <Toggle
          checked={s.autoQuarantine === 'malicious_only'}
          disabled={lock}
          onChange={(v) => save({ autoQuarantine: v ? 'malicious_only' : 'off' })}
          label="Quarantine confirmed malware automatically"
          description="Only files a malware engine positively identifies. Suspicious files are never touched, and nothing is deleted without asking you."
        />
        <Toggle
          checked={s.executionGuard}
          disabled={lock}
          onChange={(v) => save({ executionGuard: v })}
          label="Stop confirmed malware from running"
          description="Adds a Windows permission that blocks launching that one file. You can undo it. It cannot stop downloads or other programs."
        />
      </Card>

      {h && (h.couldNotCheck.length > 0 || unwatched.length > 0) && (
        <Card className="overflow-hidden">
          <div className="flex items-center justify-between border-b border-line px-5 py-3">
            <h2 className="text-sm font-semibold text-ink">Problems</h2>
            {h.couldNotCheck.length > 1 && <Button onClick={() => retry()}>Try all again</Button>}
          </div>
          <ul className="divide-y divide-line">
            {unwatched.map((r) => (
              <li key={r.path} className="px-5 py-3 text-sm">
                <span className="font-semibold text-ink">{r.label}</span> is not being watched. <span className="text-muted">{r.error ?? (r.exists ? 'Unknown reason.' : 'The folder is not available.')}</span>
              </li>
            ))}
            {h.couldNotCheck.map((j) => (
              <li key={j.id} className="flex items-center justify-between gap-4 px-5 py-3">
                <div className="min-w-0">
                  <div className="truncate text-sm font-semibold text-ink" title={j.path}>{splitPath(j.path)[1]}</div>
                  <div className="truncate text-xs text-muted">Could not be checked{j.lastError ? `: ${j.lastError}` : ''}. Not known to be safe.</div>
                </div>
                <Button onClick={() => retry(j.id)}>Try again</Button>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <Disclosure title="Technical details" hint="engine, queue, recent events">
        <Rows>
          <Row label="Detection engine" tone={status.engine.state === 'running' ? 'ok' : status.engine.state === 'unavailable' ? 'danger' : 'warn'}>
            {status.engine.clamav_version ? status.engine.clamav_version.split('/')[0] : status.engine.state}
          </Row>
          <Row label="Last definitions update">{ago(status.lastSignatureUpdate)}</Row>
          {h && (
            <>
              <Row label="Waiting to be scanned">{h.queue.queued + h.queue.scanning}</Row>
              <Row label="Files checked on this device">{h.queue.filesScanned.toLocaleString()}</Row>
              <Row label="Last automatic scan">{agoMs(h.queue.lastScanAt)}</Row>
              <Row label="Results no longer current" tone={h.queue.staleResults ? 'warn' : undefined}>{h.queue.staleResults}</Row>
            </>
          )}
        </Rows>
        <div className="flex flex-wrap gap-2 border-t border-line px-5 py-3">
          <Button busy={updating} onClick={update}>
            <RefreshCw className="size-4" /> Update definitions
          </Button>
          <Button onClick={() => api.startEngine().then(() => refresh()).catch((e) => toast('danger', errText(e)))}>Restart engine</Button>
        </div>
        {h && h.recentEvents.length > 0 && (
          <ul className="max-h-64 divide-y divide-line overflow-auto border-t border-line">
            {h.recentEvents.slice(0, 12).map((e) => (
              <li key={e.id} className="flex items-start gap-3 px-5 py-2 text-sm">
                <span className={`mt-1.5 size-2 shrink-0 rounded-full ${e.severity === 'critical' ? 'bg-danger' : e.severity === 'warning' ? 'bg-warn' : 'bg-faint'}`} aria-label={e.severity} />
                <span className="min-w-0 flex-1 text-ink">{e.message}</span>
                <span className="shrink-0 text-xs text-muted" title={whenMs(e.ts)}>{agoMs(e.ts)}</span>
              </li>
            ))}
          </ul>
        )}
        <p className="border-t border-line px-5 py-3 text-xs text-muted">SENTRIX scans files after they appear. No scanner finds everything, and Windows Security keeps running alongside it.</p>
      </Disclosure>
    </div>
  );
}

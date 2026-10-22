import { useEffect, useState } from 'react';
import { open } from '@tauri-apps/plugin-dialog';
import { ArrowRight, FileSearch, HardDrive } from 'lucide-react';
import { useApp } from '../lib/app';
import { api, errText } from '../lib/api';
import { ago, splitPath } from '../lib/format';
import { usePolled } from '../lib/hooks';
import type { ScanReport, Verdict } from '../lib/types';
import { Button, Notice } from '../components/ui';
import { Orb } from '../components/Orb';

interface Item {
  key: string;
  tone: 'danger' | 'warn';
  text: string;
  action: string;
  run: () => void | Promise<void>;
}

const DOT: Record<Verdict, string> = { MALICIOUS: 'bg-danger', SUSPICIOUS: 'bg-warn', CLEAN: 'bg-ok', UNABLE_TO_VERIFY: 'bg-strong', PENDING: 'bg-strong' };
const WORD: Record<Verdict, string> = { MALICIOUS: 'was dangerous', SUSPICIOUS: 'looks suspicious', CLEAN: 'came back clean', UNABLE_TO_VERIFY: 'could not be fully checked', PENDING: 'is being checked' };

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
  const eng = status.engine;
  const h = health.data;
  const t = tg.data;
  const today = new Date().toLocaleDateString(undefined, { weekday: 'long', day: 'numeric', month: 'long' });

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

  // Only things the person can act on. Everything else lives on the page it belongs to.
  const items: Item[] = [];
  if (danger.length)
    items.push({ key: 'danger', tone: 'danger', text: `${danger.length} dangerous file${danger.length > 1 ? 's' : ''} found. Review and quarantine ${danger.length > 1 ? 'them' : 'it'}.`, action: 'Review', run: () => { openReport(danger[0].id); } });
  if (eng.state === 'unavailable' || eng.state === 'degraded' || !status.lastSignatureUpdate)
    items.push({ key: 'engine', tone: 'warn', text: eng.state === 'unavailable' ? 'The malware definitions are not installed, so files cannot be called safe.' : 'The malware definitions are out of date.', action: 'Update now', run: act('engine', async () => { const r = await api.updateProtection(); toast(r.ok ? 'ok' : 'danger', r.message); }) });
  if (!status.settings.realtimeMonitoring)
    items.push({ key: 'rt', tone: 'warn', text: 'New downloads are not being scanned automatically.', action: 'Turn on', run: act('rt', () => api.setSettings({ ...status.settings, realtimeMonitoring: true })) });
  else if (h && !h.monitorRunning)
    items.push({ key: 'monitor', tone: 'danger', text: 'Automatic scanning is on, but no folder is being watched.', action: 'Fix', run: () => go('protection') });
  if (h && h.queue.failed > 0)
    items.push({ key: 'failed', tone: 'warn', text: `${h.queue.failed} file${h.queue.failed > 1 ? 's' : ''} could not be checked and ${h.queue.failed > 1 ? 'are' : 'is'} not known to be safe.`, action: 'See files', run: () => go('protection') });
  if (t && (t.bot.configured && (t.bot.lastTestOk === false || t.bot.failed24h > 0)))
    items.push({ key: 'tg', tone: 'warn', text: 'Telegram results are not getting through.', action: 'Check', run: () => go('telegram') });
  if (t && t.relay.linked && (t.relay.reachable === false || t.relay.error))
    items.push({ key: 'relay', tone: 'warn', text: 'The SENTRIX bot cannot reach you in Telegram, so results are not arriving.', action: 'Fix', run: () => go('telegram') });
  if (t && t.account.state === 'expired')
    items.push({ key: 'acct', tone: 'warn', text: 'Telegram ended the session, so files sent to your account are not being checked.', action: 'Sign in again', run: () => go('telegram') });

  const headline = danger.length ? 'A dangerous file needs you.' : lvl === 'protected' ? 'Everything is being checked.' : lvl === 'attention' ? 'Protection has a gap.' : 'Files cannot be called safe right now.';
  const sub = danger.length
    ? `${danger.length} file${danger.length > 1 ? 's' : ''} on this computer ${danger.length > 1 ? 'were' : 'was'} identified as malware. Nothing was deleted without asking you.`
    : lvl === 'protected'
      ? 'New files in your watched folders are scanned as they arrive. No scanner is perfect, so stay careful with files you do not know.'
      : (status.protection.reasons[0] ?? status.protection.headline);

  const acctOn = !!t && t.account.state === 'connected';
  const reportsLinked = !!t && (acctOn || t.relay.linked || t.bot.configured);
  const watching = h ? h.roots.filter((r) => r.watching).length : null;
  const sigAge = eng.database_age_hours;

  return (
    <div className="grid gap-x-10 gap-y-8 lg:grid-cols-[minmax(0,1fr)_17rem]">
      <div className="stagger min-w-0 space-y-8">
        <header className="flex flex-wrap items-center gap-7 rounded-3xl border border-line bg-surface px-7 py-6 shadow-[var(--shadow)]">
          <Orb level={lvl} scanning={scan.running} size={124} />
          <div className="min-w-0 flex-1">
            <p className="text-[0.7rem] font-semibold uppercase tracking-[0.16em] text-accent">{today}</p>
            <h1 className="mt-1 font-display text-[2.1rem] font-semibold leading-[1.1] text-ink">{scan.running ? 'Checking your files now.' : headline}</h1>
            <p className="mt-2 max-w-xl text-sm text-muted">{scan.running ? 'You can keep working. Results appear below as each file is checked.' : sub}</p>
            <div className="mt-4 flex flex-wrap items-center gap-2">
              <Button variant="primary" onClick={pickFiles} disabled={scan.running}>
                <FileSearch className="size-4" /> Scan files
              </Button>
              <Button variant="ghost" onClick={requestFullScan} disabled={scan.running}>
                <HardDrive className="size-4" /> Scan the whole computer
              </Button>
            </div>
          </div>
        </header>

        {items.length > 0 && (
          <section aria-label="What needs you">
            <h2 className="text-xs font-semibold uppercase tracking-[0.12em] text-muted">What needs you</h2>
            <ul className="mt-3 divide-y divide-line border-y border-line">
              {items.map((i) => (
                <li key={i.key} className="flex items-center gap-4 py-3">
                  <span className={`size-2 shrink-0 rounded-full ${i.tone === 'danger' ? 'bg-danger' : 'bg-warn'}`} aria-hidden />
                  <span className="min-w-0 flex-1 text-sm text-ink">{i.text}</span>
                  <Button variant={i.tone === 'danger' ? 'primary' : 'secondary'} busy={busy === i.key} onClick={i.run}>{i.action}</Button>
                </li>
              ))}
            </ul>
          </section>
        )}

        <section aria-label="Recent activity">
          <div className="flex items-baseline justify-between">
            <h2 className="text-xs font-semibold uppercase tracking-[0.12em] text-muted">Recent activity</h2>
            <button className="inline-flex items-center gap-1 text-sm text-muted hover:text-ink" onClick={() => go('history')}>All history <ArrowRight className="size-3.5" aria-hidden /></button>
          </div>
          <Timeline onOpen={openReport} />
        </section>
      </div>

      <aside aria-label="At a glance" className="space-y-6 lg:pt-1">
        <div>
          <h2 className="text-xs font-semibold uppercase tracking-[0.12em] text-muted">At a glance</h2>
          <dl className="mt-3 space-y-3.5 text-sm">
            <Fact k="Scanner" v={{ running: 'Running', degraded: 'Running, definitions old', stopped: 'Stopped', unavailable: 'Not available' }[eng.state]} tone={eng.state === 'running' ? undefined : eng.state === 'unavailable' ? 'danger' : 'warn'} />
            <Fact k="Definitions" v={sigAge === null ? 'Not installed' : sigAge < 1 ? 'Updated within the hour' : sigAge < 48 ? `${Math.floor(sigAge)} hours old` : `${Math.floor(sigAge / 24)} days old`} tone={sigAge === null ? 'danger' : sigAge >= 48 ? 'warn' : undefined} />
            <Fact k="Watching" v={watching === null ? '…' : status.settings.realtimeMonitoring ? `${watching} folder${watching === 1 ? '' : 's'}` : 'Switched off'} tone={status.settings.realtimeMonitoring && watching === 0 ? 'danger' : !status.settings.realtimeMonitoring ? 'warn' : undefined} />
            <Fact k="Files checked" v={status.stats.scansTotal.toLocaleString()} />
            <Fact k="Quarantined" v={String(status.stats.quarantined)} />
          </dl>
        </div>

        <div className="border-t border-line pt-5">
          <h2 className="text-xs font-semibold uppercase tracking-[0.12em] text-muted">Telegram</h2>
          {!t ? (
            <p className="mt-3 text-sm text-muted">…</p>
          ) : reportsLinked ? (
            <p className="mt-3 text-sm text-ink">
              {acctOn
                ? `Your account is protected${t.account.groups.length ? ` and ${t.account.groups.length} group${t.account.groups.length === 1 ? ' is' : 's are'} watched` : ''}. Results go to ${t.account.rooms.length ? 'your Scan History group' + (t.account.rooms.length > 1 ? 's' : '') : 'your Saved Messages'}.`
                : `Results go to your chat with ${t.relay.linked && t.relay.botUsername ? `@${t.relay.botUsername}` : t.bot.username ? `@${t.bot.username}` : 'your bot'}.`}
              <button className="mt-1 block text-muted hover:text-ink" onClick={() => go('telegram')}>Manage Telegram</button>
            </p>
          ) : (
            <div className="mt-3 text-sm">
              <p className="text-muted">Sign in to Telegram once and SENTRIX checks the files and groups you are in, on this computer, with the results posted in your own Scan History group.</p>
              <Button className="mt-3" onClick={() => go('telegram')}>Connect Telegram</Button>
            </div>
          )}
        </div>
      </aside>
    </div>
  );
}

function Fact({ k, v, tone }: { k: string; v: string; tone?: 'danger' | 'warn' }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <dt className="text-muted">{k}</dt>
      <dd className={`text-right font-medium ${tone === 'danger' ? 'text-danger' : tone === 'warn' ? 'text-warn' : 'text-ink'}`}>{v}</dd>
    </div>
  );
}

function Timeline({ onOpen }: { onOpen: (id: string) => void }) {
  const [rows, setRows] = useState<ScanReport[] | null>(null);
  const { status } = useApp();
  useEffect(() => {
    void api.history(6).then(setRows);
  }, [status?.stats.scansTotal]);
  if (rows === null) return <p className="mt-3 text-sm text-muted">Loading…</p>;
  if (!rows.length) return <p className="mt-3 max-w-md text-sm text-muted">Nothing has been checked yet. Drop a file on this window, or press Scan files, and the result will show up here.</p>;
  return (
    <ol className="relative mt-4 ml-1.5 space-y-0 border-l border-line">
      {rows.map((r) => (
        <li key={r.id} className="relative pb-5 pl-6 last:pb-0">
          <span className={`absolute -left-[5px] top-1.5 size-2.5 rounded-full ring-4 ring-[var(--bg)] ${DOT[r.verdict]}`} aria-hidden />
          <button onClick={() => onOpen(r.id)} className="group block w-full text-left">
            <span className="text-sm text-ink">
              <span className="font-semibold group-hover:underline">{r.file.name}</span> {WORD[r.verdict]}{!r.complete && r.verdict !== 'UNABLE_TO_VERIFY' ? ' (partly checked)' : ''}
            </span>
            <span className="mt-0.5 block text-xs text-muted">{ago(r.finished_at)} · {r.origin ?? splitPath(r.file.path)[0]}</span>
          </button>
        </li>
      ))}
    </ol>
  );
}

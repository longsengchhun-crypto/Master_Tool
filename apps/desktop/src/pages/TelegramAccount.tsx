import { useState } from 'react';
import { Check, Loader2, Minus } from 'lucide-react';
import { api, errText } from '../lib/api';
import { useApp } from '../lib/app';
import { agoMs } from '../lib/format';
import type { AccountOptions, AccountRecent, TgAccount } from '../lib/types';
import { Button, Card, Modal, Notice, Pill, Toggle } from '../components/ui';

const CAN = [
  'Files sent to you in private chats and posted in the groups you are in. Channels only if you switch them on below.',
  'The file name, size and type of each attachment. Message text is never read or kept.',
  'A private copy of each file, which it checks and then deletes.',
  'It posts each result from your own account into your Scan History group, or your Saved Messages.',
];

const CANNOT = [
  'Secret chats, which Telegram does not deliver to other devices.',
  'Chats where Telegram blocks saving (protected content). Those files are listed as not checked.',
  'Anything before it has arrived: a file is checked after it downloads, never before.',
  'Files over 200 MB, and accounts that use a two-step password.',
  'Anything while this computer is off or offline: it runs here, on your computer, and nowhere else.',
];

export function connectionText(c: TgAccount['connection']): string {
  return { ready: 'Connected to Telegram', connecting: 'Connecting to Telegram…', waiting_for_network: 'Waiting for the network', updating: 'Catching up with Telegram…', unknown: 'Starting…' }[c];
}

const VERDICT_TONE: Record<string, 'ok' | 'warn' | 'danger' | 'muted'> = { CLEAN: 'ok', SUSPICIOUS: 'warn', MALICIOUS: 'danger', 'UNABLE TO VERIFY': 'muted', PENDING: 'muted' };
const VERDICT_TEXT: Record<string, string> = { CLEAN: 'Clean', SUSPICIOUS: 'Suspicious', MALICIOUS: 'Malicious', 'UNABLE TO VERIFY': 'Not checked', PENDING: 'Pending' };
const WHERE: Record<AccountRecent['kind'], string> = { private: 'Private chat', group: 'Group', channel: 'Channel' };

export function TelegramAccount({ a, reload, setData }: { a: TgAccount; reload: () => Promise<void>; setData: (v: TgAccount) => void }) {
  const { toast } = useApp();
  const [agree, setAgree] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [confirmOff, setConfirmOff] = useState(false);

  const run = async (key: string, fn: () => Promise<TgAccount>, okText?: string) => {
    setBusy(key);
    try {
      setData(await fn());
      if (okText) toast('ok', okText);
    } catch (e) {
      toast('danger', errText(e));
      await reload();
    } finally {
      setBusy(null);
    }
  };
  const setOpt = (patch: Partial<AccountOptions>) => run('opts', () => api.tgAccountSetOptions({ ...a.options, ...patch }));

  if (a.state === 'unconfigured') {
    return (
      <Card className="p-6">
        <h2 className="text-base font-semibold text-ink">Account protection is not available</h2>
        <p className="mt-1 max-w-2xl text-sm text-muted">{a.detail}</p>
        <p className="mt-3 max-w-2xl text-sm text-muted">Your bot, group protection and the Telegram Desktop folder watch are not affected.</p>
      </Card>
    );
  }

  if (!a.allowed) {
    return <Notice tone="info">Your organization has turned off Telegram account protection for this computer.</Notice>;
  }

  if (a.state === 'waiting_for_scan' || a.state === 'starting') {
    return (
      <Card className="p-6">
        <div className="flex flex-wrap gap-8">
          <div className="grid size-[232px] shrink-0 place-items-center rounded-lg border border-line bg-white p-2" aria-live="polite">
            {a.qrSvg ? <img alt="Telegram login QR code" className="size-full" src={`data:image/svg+xml;utf8,${encodeURIComponent(a.qrSvg)}`} /> : <Loader2 className="size-6 animate-spin text-muted" aria-label="Waiting for Telegram" />}
          </div>
          <div className="min-w-0 max-w-md flex-1">
            <h2 className="text-base font-semibold text-ink">Approve SENTRIX on your phone</h2>
            <ol className="mt-3 space-y-2 text-sm text-muted">
              <li><span className="font-semibold text-ink">1.</span> Open Telegram on your phone.</li>
              <li><span className="font-semibold text-ink">2.</span> Go to <span className="font-semibold text-ink">Settings → Devices → Link Desktop Device</span>.</li>
              <li><span className="font-semibold text-ink">3.</span> Point the camera at this code and confirm.</li>
            </ol>
            <p className="mt-4 text-xs text-muted">The code changes about every 30 seconds by itself. SENTRIX never asks for your phone number, login code or password, and nothing you approve here is sent to SENTRIX or any server of ours.</p>
            <div className="mt-5">
              <Button busy={busy === 'cancel'} onClick={() => run('cancel', () => api.tgAccountDisconnect())}>Cancel</Button>
            </div>
          </div>
        </div>
      </Card>
    );
  }

  if (a.state === 'connected') {
    const online = a.connection === 'ready';
    const paused = !a.options.enabled;
    return (
      <div className="space-y-5">
        <Card className="p-5">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="min-w-0">
              <div className="flex items-center gap-2.5">
                <span className={`size-2.5 rounded-full ${paused ? 'bg-warn' : online ? 'bg-ok' : 'bg-warn'}`} aria-hidden />
                <h2 className="truncate text-base font-semibold text-ink">{a.display ? `Signed in as ${a.display}` : 'Signed in'}</h2>
                <Pill tone={paused ? 'warn' : online ? 'ok' : 'warn'}>{paused ? 'Paused' : online ? 'Monitoring' : 'Not monitoring right now'}</Pill>
              </div>
              <p className="mt-1 text-sm text-muted">
                {connectionText(a.connection)}
                {a.lastSyncAt ? ` · in touch with Telegram ${agoMs(a.lastSyncAt)}` : ''}
                {a.lastScanAt ? ` · last file checked ${agoMs(a.lastScanAt)}` : ' · no file checked yet'}
              </p>
            </div>
            <Button variant="danger" onClick={() => setConfirmOff(true)}>Disconnect</Button>
          </div>
          {!online && !paused && <div className="mt-3"><Notice tone="warn">Files that arrive while SENTRIX cannot reach Telegram may not be checked. {a.connection === 'waiting_for_network' ? 'Check this computer’s internet connection.' : ''}</Notice></div>}
          {paused && <div className="mt-3"><Notice tone="warn">Monitoring is paused. Files sent to you are not being checked.</Notice></div>}
        </Card>

        <Card>
          <dl className="grid grid-cols-5 divide-x divide-line text-sm">
            {([
              ['Checked', a.counts.scanned, ''],
              ['Threats', a.counts.threats, a.counts.threats ? 'text-danger' : ''],
              ['Not checked', a.counts.inaccessible, a.counts.inaccessible ? 'text-warn' : ''],
              ['Skipped', a.counts.skipped, ''],
              ['Waiting', a.pending, ''],
            ] as const).map(([k, v, c]) => (
              <div key={k} className="px-5 py-3.5">
                <dt className="text-xs text-muted">{k}</dt>
                <dd className={`mt-0.5 text-xl font-semibold tabular-nums ${c || 'text-ink'}`}>{v}</dd>
              </div>
            ))}
          </dl>
        </Card>

        <Card className="divide-y divide-line px-5 py-1">
          <Toggle checked={a.options.enabled} disabled={busy === 'opts'} onChange={(v) => setOpt({ enabled: v })} label="Check files sent to me" description="Turn this off to pause without signing out." />
          <Toggle checked={a.options.localReports} disabled={busy === 'opts' || paused} onChange={(v) => setOpt({ localReports: v })} label="Post results in Telegram" description="Each result is posted from your account into your Scan History group. With no such group, only dangerous or suspicious results go to your Saved Messages. Off: results appear only in this app." />
          <Toggle checked={a.options.privateChats} disabled={busy === 'opts' || paused} onChange={(v) => setOpt({ privateChats: v })} label="Private chats" description="Files people send you directly. This is where most unwanted files arrive." />
          <Toggle checked={a.options.groups} disabled={busy === 'opts' || paused} onChange={(v) => setOpt({ groups: v })} label="Groups" description="Files posted in any group you are a member of, administrator or not. Busy groups can mean many downloads." />
          <Toggle checked={a.options.channels} disabled={busy === 'opts' || paused} onChange={(v) => setOpt({ channels: v })} label="Channels" description="Files posted in channels you follow." />
          <Toggle checked={a.options.media} disabled={busy === 'opts' || paused} onChange={(v) => setOpt({ media: v })} label="Photos, videos and voice messages" description="Off by default. Programs and scripts arrive as files, not as media, so most people do not need this." />
        </Card>

        <Card className="overflow-hidden">
          <header className="flex min-h-12 items-center justify-between border-b border-line px-5">
            <h3 className="text-sm font-semibold text-ink">Scan History</h3>
            {a.rooms.length > 0 && <Pill tone="ok">{a.rooms.length === 1 ? 'Found' : `${a.rooms.length} found`}</Pill>}
          </header>
          {a.rooms.length === 0 ? (
            <div className="space-y-2 px-5 py-4 text-sm text-muted">
              <p>Results need somewhere to go. In Telegram, <span className="font-medium text-ink">make a new group called Scan History</span>. You can add other people to it: everyone in it can read the results.</p>
              <p>SENTRIX notices the group by itself, usually within a minute, and starts posting there. Until then, only dangerous or suspicious results are saved to your Saved Messages.</p>
            </div>
          ) : (
            <div className="px-5 py-3 text-sm text-muted">
              <p>
                {a.rooms.map((r) => `Scan History #${r.num}`).join(', ')}. Results are posted there from your account. You can make as many as you like; each one is numbered because they share a name. Everyone in a Scan History group can read the results, so add only people who should.
              </p>
            </div>
          )}
        </Card>

        {a.groups.length > 0 && (
          <Card className="overflow-hidden">
            <header className="flex min-h-12 items-center justify-between border-b border-line px-5">
              <h3 className="text-sm font-semibold text-ink">Your groups</h3>
              <span className="text-xs text-muted">{a.groups.length} group{a.groups.length === 1 ? '' : 's'} watched</span>
            </header>
            <ul className="max-h-80 divide-y divide-line overflow-y-auto">
              {a.groups.map((g) => (
                <li key={g.chatId} className="flex items-center justify-between gap-4 px-5 py-2.5 text-sm">
                  <span className="min-w-0 truncate font-semibold text-ink">{g.title || 'Unnamed group'}</span>
                  {a.rooms.length > 1 ? (
                    <select
                      aria-label={`Where results for ${g.title} go`}
                      value={g.route ?? 'all'}
                      disabled={busy === `r${g.chatId}`}
                      onChange={(e) => run(`r${g.chatId}`, () => api.tgAccountSetRoute(g.chatId, e.target.value === 'all' ? null : Number(e.target.value)))}
                      className="h-9 shrink-0 rounded-lg border border-strong bg-solid px-2 text-sm text-ink"
                    >
                      <option value="all">All Scan History groups</option>
                      {a.rooms.map((r) => (
                        <option key={r.chatId} value={r.chatId}>Scan History #{r.num}</option>
                      ))}
                    </select>
                  ) : (
                    <span className="shrink-0 text-xs text-muted">{a.rooms.length === 1 ? `Scan History #${a.rooms[0].num}` : 'Saved Messages (threats only)'}</span>
                  )}
                </li>
              ))}
            </ul>
            <p className="border-t border-line px-5 py-3 text-xs text-muted">Any group you are in is checked while Groups is on, whether or not you are its administrator. Several groups can report to the same Scan History group, or each can have its own.</p>
          </Card>
        )}

        <Card className="overflow-hidden">
          <header className="flex min-h-12 items-center border-b border-line px-5">
            <h3 className="text-sm font-semibold text-ink">Recent files</h3>
          </header>
          {a.recent.length === 0 ? (
            <p className="px-5 py-5 text-sm text-muted">Nothing has arrived since you signed in. When someone sends you a file, the result appears here.</p>
          ) : (
            <ul className="divide-y divide-line">
              {a.recent.slice(0, 8).map((r, i) => (
                <li key={`${r.at}-${i}`} className="flex items-center justify-between gap-4 px-5 py-2.5 text-sm">
                  <div className="min-w-0">
                    <div className="truncate font-semibold text-ink">{r.name}</div>
                    <div className="truncate text-xs text-muted">{WHERE[r.kind]} · {agoMs(r.at)}{r.verdict === 'UNABLE TO VERIFY' ? ` · ${r.note.replace(/^Not checked: /, '')}` : ''}</div>
                  </div>
                  <Pill tone={VERDICT_TONE[r.verdict] ?? 'muted'}>{VERDICT_TEXT[r.verdict] ?? r.verdict}</Pill>
                </li>
              ))}
            </ul>
          )}
          <p className="border-t border-line px-5 py-3 text-xs text-muted">This list is kept in memory and empties when SENTRIX closes. Each result is also recorded in History like any other scan. “Not checked” never means safe.</p>
        </Card>

        <Modal
          open={confirmOff}
          onClose={() => setConfirmOff(false)}
          title="Disconnect your Telegram account?"
          footer={
            <>
              <Button onClick={() => setConfirmOff(false)}>Cancel</Button>
              <Button variant="danger" busy={busy === 'off'} onClick={async () => { await run('off', () => api.tgAccountDisconnect(), 'Disconnected. The session was removed from this computer.'); setConfirmOff(false); }}>Disconnect</Button>
            </>
          }
        >
          <p>SENTRIX signs out at Telegram and erases the saved session from this computer. Files sent to you are no longer checked.</p>
          <p className="mt-2">You can confirm it in Telegram under <span className="font-medium text-ink">Settings → Devices</span>. If SENTRIX cannot reach Telegram, it still erases its own copy, and you should end the session there yourself.</p>
        </Modal>
      </div>
    );
  }

  // Not signed in: disconnected, expired, failed, or an unsupported account.
  const problem =
    a.state === 'expired' ? { tone: 'warn' as const, title: 'The Telegram session ended', text: 'Telegram ended SENTRIX’s session, or you removed it from Settings → Devices. Files sent to you are not being checked. Sign in again to resume.' }
    : a.state === 'two_step_unsupported' ? { tone: 'info' as const, title: 'This account uses a two-step password', text: 'SENTRIX does not ask for your Telegram password, so it cannot connect an account that has one. Nothing was stored and the sign-in attempt was ended. Your bot and group protection still work.' }
    : a.state === 'failed' ? { tone: 'danger' as const, title: 'Sign-in did not complete', text: a.detail }
    : null;

  return (
    <Card className="p-6">
      {problem && <div className="mb-5"><Notice tone={problem.tone} title={problem.title}>{problem.text}</Notice></div>}
      <h2 className="text-base font-semibold text-ink">Check files that reach your Telegram account</h2>
      <p className="mt-1 max-w-2xl text-sm text-muted">Sign in once with a QR code. When someone sends you a file, SENTRIX downloads its own copy, checks it with the security engine, posts the result in your own Scan History group (or your Saved Messages) from your account, and deletes the copy. No bot and no server of ours is involved.</p>

      <div className="mt-5 grid gap-x-10 gap-y-5 md:grid-cols-2">
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">What SENTRIX can access</h3>
          <ul className="mt-2 space-y-2 text-sm text-ink">
            {CAN.map((t) => (
              <li key={t} className="flex gap-2.5"><Check className="mt-0.5 size-4 shrink-0 text-ok" aria-hidden />{t}</li>
            ))}
          </ul>
        </div>
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">What it cannot cover</h3>
          <ul className="mt-2 space-y-2 text-sm text-ink">
            {CANNOT.map((t) => (
              <li key={t} className="flex gap-2.5"><Minus className="mt-0.5 size-4 shrink-0 text-faint" aria-hidden />{t}</li>
            ))}
          </ul>
        </div>
      </div>

      <div className="mt-5 rounded-lg bg-surface2 px-4 py-3 text-xs text-muted">
        SENTRIX signs in as an extra device on your account using Telegram’s own client library. The session is encrypted for your Windows user and never leaves this computer. Telegram’s rules note that accounts using apps other than its official ones may be watched more closely. You can see the session, and remove it, under Settings → Devices in Telegram. No protection is complete: this lowers the chance of opening a bad file, it does not remove it.
      </div>

      <label className="mt-5 flex cursor-pointer items-start gap-3 text-sm text-ink">
        <input type="checkbox" checked={agree} onChange={(e) => setAgree(e.target.checked)} className="mt-0.5 size-4 accent-[var(--accent)]" />
        <span>I understand what SENTRIX can access and I allow it to check files sent to my Telegram account.</span>
      </label>
      <div className="mt-4">
        <Button variant="primary" busy={busy === 'connect'} disabled={!agree} onClick={() => run('connect', () => api.tgAccountConnect())}>{a.state === 'expired' ? 'Sign in again' : a.state === 'two_step_unsupported' ? 'Try another account' : 'Connect with QR code'}</Button>
      </div>
    </Card>
  );
}

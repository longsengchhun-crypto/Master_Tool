import { useState } from 'react';
import { open } from '@tauri-apps/plugin-dialog';
import { CheckCircle2, Eye, EyeOff, FolderOpen, Send } from 'lucide-react';
import { api, errText } from '../lib/api';
import { useApp } from '../lib/app';
import { agoMs } from '../lib/format';
import { usePolled } from '../lib/hooks';
import type { NotifyPrefs, TelegramStatus } from '../lib/types';
import { Button, Card, Disclosure, Modal, Notice, PageHeader, Pill, Toggle } from '../components/ui';

const MORE: [keyof NotifyPrefs, string][] = [
  ['quarantined', 'When a file is quarantined automatically'],
  ['unableToVerify', 'Files that could not be fully checked (can be frequent)'],
  ['cleanScans', 'Every clean result (very frequent)'],
  ['accountEvents', 'Bot connected or disconnected'],
  ['includeHash', 'Include the file fingerprint (SHA-256) in reports'],
];

export function Telegram() {
  const { toast, refresh } = useApp();
  const st = usePolled(() => api.tgStatus(), 5000);
  const [token, setToken] = useState('');
  const [show, setShow] = useState(false);
  const [chats, setChats] = useState<number[] | null>(null);
  const [manual, setManual] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [confirmOff, setConfirmOff] = useState(false);
  const t = st.data;

  if (!t) return st.error ? <Notice tone="danger" title="Telegram status is unavailable">{st.error}</Notice> : <div className="text-muted">Loading…</div>;

  const run = async <T,>(key: string, fn: () => Promise<T>, onOk?: (v: T) => void) => {
    setBusy(key);
    try {
      const v = await fn();
      onOk?.(v);
      await st.reload();
      void refresh();
    } catch (e) {
      toast('danger', errText(e));
    } finally {
      setBusy(null);
    }
  };

  const set = (s: TelegramStatus) => st.setData(s);
  const savePrefs = (patch: Partial<NotifyPrefs>) => run('opts', () => api.tgSetOptions({ ...t.notify, ...patch }, t.acceptSubmissions), set);

  const done = (s: TelegramStatus) => {
    set(s);
    setToken('');
    setChats(null);
    setManual('');
    toast('ok', 'Connected. Telegram accepted a test message.');
  };

  // One button: find the chat that messaged the bot, then connect. Only asks questions when it has to.
  const connect = () =>
    run('connect', async () => {
      const ids = manual ? [Number(manual)] : await api.tgDetectChat(token);
      if (ids.length === 0) {
        toast('warn', 'Open your bot in Telegram, press Start, then try again.');
        return null;
      }
      if (ids.length > 1) {
        setChats(ids);
        return null;
      }
      return api.tgConnect(token, ids[0]);
    }, (s) => s && done(s));

  const connectTo = (id: number) => run('connect', () => api.tgConnect(token, id), done);

  const pickFolder = async () => {
    const sel = await open({ directory: true, title: 'Choose your Telegram Desktop download folder' });
    if (typeof sel === 'string') await run('folder', () => api.tgSetDesktopFolder(sel), set);
  };

  const bot = t.bot;
  const tokenOk = /^\d{5,}:[A-Za-z0-9_-]{30,}$/.test(token.trim());
  const d = t.desktop;
  const candidate = d.detection.candidates.find((c) => c.exists);
  const problems = t.notify.engineProblems && t.notify.protectionStopped;
  const healthy = bot.connected && bot.lastTestOk !== false;

  return (
    <div className="space-y-5">
      <PageHeader title="Telegram" />

      {!t.allowed && <Notice tone="info">Your organization does not allow Telegram on this device.</Notice>}

      {!bot.configured ? (
        <Card className="p-6">
          <h2 className="text-base font-semibold text-ink">Get results in your own Telegram bot</h2>
          <p className="mt-1 text-sm text-muted">Reports go to a private bot that only you control. SENTRIX never asks for your Telegram password or login code.</p>
          <ol className="mt-4 space-y-1.5 text-sm text-muted">
            <li><span className="font-semibold text-ink">1.</span> In Telegram, message <span className="font-semibold text-ink">@BotFather</span> and send <span className="font-mono">/newbot</span>. Copy the token it gives you.</li>
            <li><span className="font-semibold text-ink">2.</span> Open your new bot and press <span className="font-semibold text-ink">Start</span>.</li>
            <li><span className="font-semibold text-ink">3.</span> Paste the token here and press Connect.</li>
          </ol>
          <div className="mt-4 flex max-w-xl gap-2">
            <input
              type={show ? 'text' : 'password'}
              value={token}
              onChange={(e) => { setToken(e.target.value); setChats(null); }}
              autoComplete="off"
              spellCheck={false}
              placeholder="Bot token, like 123456789:AA…"
              aria-label="Bot token"
              disabled={!t.allowed}
              className="h-9 min-w-0 flex-1 rounded-lg border border-strong bg-solid px-3 font-mono text-sm text-ink"
            />
            <Button aria-label={show ? 'Hide token' : 'Show token'} onClick={() => setShow((v) => !v)}>{show ? <EyeOff className="size-4" /> : <Eye className="size-4" />}</Button>
            <Button variant="primary" busy={busy === 'connect'} disabled={!tokenOk || !t.allowed} onClick={connect}>Connect</Button>
          </div>
          {token && !tokenOk && <p className="mt-1.5 text-xs text-warn">That does not look like a bot token.</p>}
          {chats && (
            <div className="mt-3 text-sm text-muted">
              Several chats have messaged this bot. Which one is yours?{' '}
              {chats.map((id) => (
                <button key={id} className="mr-2 rounded-lg border border-strong px-2.5 py-1 font-mono text-xs text-ink hover:bg-surface2" onClick={() => connectTo(id)}>{id}</button>
              ))}
            </div>
          )}
          <details className="mt-3 text-sm">
            <summary className="cursor-pointer text-muted hover:text-ink">The chat cannot be found automatically</summary>
            <label className="mt-2 flex items-center gap-2 text-muted">
              Chat ID
              <input inputMode="numeric" value={manual} onChange={(e) => setManual(e.target.value.replace(/[^\d-]/g, ''))} className="h-9 w-44 rounded-lg border border-strong bg-solid px-3 font-mono text-sm text-ink" />
            </label>
          </details>
          <p className="mt-4 text-xs text-muted">The token is stored encrypted for your Windows user and is only ever sent to Telegram. Telegram can read the reports it receives.</p>
        </Card>
      ) : (
        <>
          <Card className="p-5">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <CheckCircle2 className={`size-6 ${healthy ? 'text-ok' : 'text-warn'}`} aria-hidden />
                <div>
                  <div className="text-sm font-semibold text-ink">{healthy ? 'Connected' : 'Connection problem'}{bot.username ? ` as @${bot.username}` : ''}</div>
                  <div className="text-xs text-muted">
                    {bot.lastDeliveryAt ? `Last report ${agoMs(bot.lastDeliveryAt)}` : 'No report sent yet'}
                    {bot.pending > 0 ? ` · ${bot.pending} waiting` : ''}
                  </div>
                </div>
              </div>
              <div className="flex gap-2">
                <Button busy={busy === 'test'} disabled={!t.allowed} onClick={() => run('test', () => api.tgTest(), (s) => { set(s); toast(s.bot.lastTestOk ? 'ok' : 'danger', s.bot.lastTestOk ? 'Telegram accepted the test message.' : s.bot.lastTestError ?? 'The test failed.'); })}>
                  <Send className="size-4" /> Send test
                </Button>
                <Button variant="danger" onClick={() => setConfirmOff(true)}>Disconnect</Button>
              </div>
            </div>
            {bot.lastTestOk === false && bot.lastTestError && <div className="mt-3"><Notice tone="danger">{bot.lastTestError}</Notice></div>}
            {bot.lastDeliveryError && <div className="mt-3"><Notice tone="warn">Some reports could not be delivered and will be retried. {bot.lastDeliveryError}</Notice></div>}
          </Card>

          <Card className="divide-y divide-line px-5 py-1">
            <Toggle checked={t.notify.malicious} disabled={busy === 'opts' || !t.allowed} onChange={(v) => savePrefs({ malicious: v })} label="Dangerous files" description="A malware engine identified a file as malicious." />
            <Toggle checked={t.notify.suspicious} disabled={busy === 'opts' || !t.allowed} onChange={(v) => savePrefs({ suspicious: v })} label="Suspicious files" description="Signs that deserve a closer look. Not proof of malware." />
            <Toggle checked={problems} disabled={busy === 'opts' || !t.allowed} onChange={(v) => savePrefs({ engineProblems: v, protectionStopped: v })} label="Problems with SENTRIX" description="The scanner stopped, definitions are out of date, or a watched folder stopped working." />
            <Toggle
              checked={t.acceptSubmissions}
              disabled={busy === 'opts' || !t.allowed}
              onChange={(v) => run('opts', () => api.tgSetOptions(t.notify, v), set)}
              label="Scan files I send to my bot"
              description="Send a file to your bot and get the result back. Only your own chat is accepted, files up to 20 MB, and this computer must be on."
            />
          </Card>

          <Card className="overflow-hidden">
            <div className="px-5 py-1">
              <Toggle
                checked={t.groups.shield}
                disabled={busy === 'groups' || !t.allowed || !t.groups.allowed}
                onChange={(v) => run('groups', () => api.tgSetGroupShield(v), set)}
                label="Protect Telegram groups"
                description={t.groups.allowed ? 'Add your bot to a group. A group administrator then sends /setup on there. Files posted as documents (up to 20 MB) are scanned on this computer, so it must be on.' : 'Your organization does not allow this.'}
              />
            </div>
            {t.groups.shield && t.groups.privacyBlocks && (
              <div className="border-t border-line px-5 py-3">
                <Notice tone="warn" title="Telegram is hiding group files from your bot">
                  Privacy mode is on for your bot, so it only sees commands in groups. Make the bot a group administrator, or in @BotFather send /setprivacy, pick your bot and choose Disable, then add the bot to the group again.
                </Notice>
              </div>
            )}
            {t.groups.shield && (
              <div className="border-t border-line">
                {t.groups.list.length === 0 ? (
                  <p className="px-5 py-4 text-sm text-muted">No groups yet. Add your bot to a group, then a group administrator sends <span className="font-mono">/setup on</span>.</p>
                ) : (
                  <ul className="divide-y divide-line">
                    {t.groups.list.map((g) => (
                      <li key={g.id} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3">
                        <div className="min-w-0">
                          <div className="truncate text-sm font-semibold text-ink">{g.title || 'Unnamed group'}</div>
                          <div className="text-xs text-muted">
                            {g.enabled ? 'Protected' : 'Waiting for a group administrator to send /setup on'}
                            {g.enabled && g.autoDelete ? ' · deletes malicious files' : ''}
                            {g.enabled ? ` · ${g.stats.scans} scanned today, ${g.stats.threats} threat${g.stats.threats === 1 ? '' : 's'}${g.stats.errors + g.stats.skipped > 0 ? `, ${g.stats.errors + g.stats.skipped} not checked` : ''}` : ''}
                          </div>
                        </div>
                        <div className="flex gap-2">
                          {g.enabled && <Button disabled={busy === `g${g.id}`} onClick={() => run(`g${g.id}`, () => api.tgGroupDisable(g.id), set)}>Stop</Button>}
                          <Button variant="danger" disabled={busy === `g${g.id}`} onClick={() => run(`g${g.id}`, () => api.tgGroupLeave(g.id), (s) => { set(s); toast('ok', 'The bot left the group and its local history was removed.'); })}>Leave</Button>
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
                <p className="border-t border-line px-5 py-3 text-xs text-muted">Photos, videos and files over 20 MB cannot be scanned and are said so in the group. Only a group administrator confirmed by Telegram can change a group's settings, and only that same administrator can agree to automatic deletion.</p>
              </div>
            )}
          </Card>
        </>
      )}

      <Card className="p-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-ink">Telegram Desktop downloads</h2>
            <p className="mt-0.5 text-sm text-muted">
              {d.folder ? (d.watching ? `Watching ${d.folder}` : d.exists ? 'Not being watched right now.' : 'That folder no longer exists.') : d.detection.installed ? 'Scan files Telegram saves to this computer.' : 'Telegram Desktop was not found on this computer.'}
            </p>
            {d.folder && <p className="mt-0.5 text-xs text-muted">{d.scanned} scanned, {d.threats} flagged</p>}
          </div>
          <div className="flex gap-2">
            {d.folder ? (
              <Button onClick={() => run('folder', () => api.tgSetDesktopFolder(null), set)}>Stop</Button>
            ) : (
              candidate && <Button variant="primary" busy={busy === 'folder'} onClick={() => run('folder', () => api.tgSetDesktopFolder(candidate.path), set)}>Watch it</Button>
            )}
            <Button onClick={pickFolder}><FolderOpen className="size-4" /> {d.folder ? 'Change' : 'Choose folder'}</Button>
          </div>
        </div>
        {d.error && <div className="mt-3"><Notice tone="warn">{d.error}</Notice></div>}
        {!d.folder && candidate && <p className="mt-2 text-xs text-muted">Found {candidate.path}. Check it matches Telegram, Settings, Advanced, Download path.</p>}
      </Card>

      {bot.configured && (
        <Disclosure title="More options">
          <div className="divide-y divide-line px-5 py-1">
            {MORE.map(([k, label]) => (
              <Toggle key={k} checked={t.notify[k]} disabled={busy === 'opts' || !t.allowed} onChange={(v) => savePrefs({ [k]: v })} label={label} />
            ))}
          </div>
          {t.recentNotifications.length > 0 && (
            <ul className="divide-y divide-line border-t border-line">
              {t.recentNotifications.slice(0, 8).map((n) => (
                <li key={n.id} className="flex items-center justify-between gap-4 px-5 py-2.5 text-sm">
                  <span className="text-ink">{n.kind.replace(/_/g, ' ')} <span className="text-xs text-muted">{agoMs(n.createdAt)}</span></span>
                  <Pill tone={n.state === 'sent' ? 'ok' : n.state === 'dead' ? 'danger' : 'warn'}>{n.state === 'sent' ? 'Delivered' : n.state === 'dead' ? 'Gave up' : 'Waiting'}</Pill>
                </li>
              ))}
            </ul>
          )}
          <p className="border-t border-line px-5 py-3 text-xs text-muted">Scanning your whole Telegram account (chats, groups, channels) is not available in this version. It only covers Telegram Desktop downloads and files you send to your bot.</p>
        </Disclosure>
      )}

      <Modal
        open={confirmOff}
        onClose={() => setConfirmOff(false)}
        title="Disconnect your bot?"
        footer={
          <>
            <Button onClick={() => setConfirmOff(false)}>Cancel</Button>
            <Button variant="danger" busy={busy === 'off'} onClick={async () => { await run('off', () => api.tgDisconnect(), (s) => { set(s); toast('ok', 'Disconnected. The token was removed from this computer.'); }); setConfirmOff(false); }}>Disconnect</Button>
          </>
        }
      >
        <p>The saved token is erased from this computer and reports stop. To make the old token useless everywhere, also send /revoke to @BotFather.</p>
      </Modal>
    </div>
  );
}

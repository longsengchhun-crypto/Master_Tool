import { useState } from 'react';
import { open } from '@tauri-apps/plugin-dialog';
import { Eye, EyeOff, FolderOpen, Send, Unplug } from 'lucide-react';
import { api, errText } from '../lib/api';
import { useApp } from '../lib/app';
import { agoMs, whenMs } from '../lib/format';
import { usePolled } from '../lib/hooks';
import type { NotifyPrefs, TelegramStatus } from '../lib/types';
import { Button, Card, Modal, Notice, PageHeader, Pill, Toggle } from '../components/ui';

const PREFS: [keyof NotifyPrefs, string, string][] = [
  ['malicious', 'Malicious files', 'A malware engine identified a file as malicious.'],
  ['suspicious', 'Suspicious files', 'Indicators were found that deserve a closer look.'],
  ['quarantined', 'Files quarantined automatically', 'SENTRIX moved a file to quarantine.'],
  ['unableToVerify', 'Files that could not be verified', 'Can be noisy if the engine is unavailable. Off by default.'],
  ['cleanScans', 'Clean results', 'One message per clean file. Off by default; usually too frequent.'],
  ['engineProblems', 'Engine problems', 'The detection engine stopped, or its signatures are out of date.'],
  ['protectionStopped', 'Protection stopped', 'A watched folder stopped working or real-time protection was turned off.'],
  ['accountEvents', 'Account and connection events', 'Bot connected or disconnected, delivery problems.'],
  ['includeHash', 'Include the SHA-256 in reports', 'The hash identifies a file without revealing its contents. File names are always included.'],
];

export function Telegram() {
  const { toast, refresh } = useApp();
  const st = usePolled(() => api.tgStatus(), 5000);
  const [token, setToken] = useState('');
  const [show, setShow] = useState(false);
  const [chat, setChat] = useState('');
  const [found, setFound] = useState<number[] | null>(null);
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
  const savePref = (k: keyof NotifyPrefs, v: boolean) => run('opts', () => api.tgSetOptions({ ...t.notify, [k]: v }, t.acceptSubmissions), set);

  const detect = () =>
    run('detect', () => api.tgDetectChat(token), (ids) => {
      setFound(ids);
      if (ids.length === 1) setChat(String(ids[0]));
      if (!ids.length) toast('warn', 'The token works, but no one has messaged this bot yet. Open your bot in Telegram, press Start, then try again.');
    });

  const connect = () =>
    run('connect', () => api.tgConnect(token, Number(chat)), (s) => {
      set(s);
      setToken('');
      setShow(false);
      setFound(null);
      setChat('');
      toast('ok', 'Telegram confirmed the token and delivered a test message. The bot is connected.');
    });

  const pickFolder = async () => {
    const sel = await open({ directory: true, title: 'Choose your Telegram Desktop download folder' });
    if (typeof sel === 'string') await run('folder', () => api.tgSetDesktopFolder(sel), set);
  };

  const bot = t.bot;
  const tokenLooksRight = /^\d{5,}:[A-Za-z0-9_-]{30,}$/.test(token.trim());
  const d = t.desktop;

  return (
    <div className="space-y-6">
      <PageHeader title="Telegram Protection" subtitle="Get scan results in your own Telegram bot, and scan files that arrive through Telegram Desktop. SENTRIX uses Telegram's official Bot API and never asks for your Telegram password or login codes." />

      {!t.allowed && <Notice tone="info" title="Turned off by your organization">Your organization does not allow Telegram notifications on this device. Nothing on this page will connect.</Notice>}

      <Card className="p-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-ink">Your personal bot</h2>
            <p className="mt-1 text-sm text-muted">Reports are sent from a bot that <strong className="text-ink">you</strong> create with Telegram's @BotFather, to a chat that only you can read. SENTRIX does not operate any shared bot and has no access to yours.</p>
          </div>
          <Pill tone={bot.connected ? (bot.lastTestOk === false ? 'warn' : 'ok') : 'muted'}>{bot.connected ? (bot.lastTestOk === false ? 'Problem' : 'Connected') : bot.configured ? 'Not verified' : 'Not connected'}</Pill>
        </div>

        {bot.configured ? (
          <div className="mt-4 space-y-4">
            <dl className="grid max-w-xl grid-cols-[12rem_1fr] gap-y-2 text-sm">
              <dt className="text-muted">Bot</dt>
              <dd className="text-ink">{bot.username ? `@${bot.username}` : 'Unknown'}</dd>
              <dt className="text-muted">Chat</dt>
              <dd className="font-mono text-ink">{bot.chatHint ?? '—'}</dd>
              <dt className="text-muted">Token</dt>
              <dd className="text-ink">Stored encrypted for this Windows user. Never shown.</dd>
              <dt className="text-muted">Last connection test</dt>
              <dd className="text-ink">{bot.lastTestAt ? `${agoMs(bot.lastTestAt)} · ${bot.lastTestOk ? 'Telegram accepted it' : 'Failed'}` : 'Never'}</dd>
              <dt className="text-muted">Last report delivered</dt>
              <dd className="text-ink">{bot.lastDeliveryAt ? agoMs(bot.lastDeliveryAt) : 'None yet'}</dd>
              <dt className="text-muted">Waiting to be sent</dt>
              <dd className="text-ink">{bot.pending}</dd>
              <dt className="text-muted">Failed in the last 24 h</dt>
              <dd className={bot.failed24h ? 'text-warn' : 'text-ink'}>{bot.failed24h}{bot.dead ? ` · ${bot.dead} gave up` : ''}</dd>
            </dl>
            {bot.lastTestOk === false && bot.lastTestError && <Notice tone="danger" title="The last test failed">{bot.lastTestError}</Notice>}
            {bot.lastDeliveryError && <Notice tone="warn" title="A report could not be delivered">{bot.lastDeliveryError} SENTRIX keeps retrying. A delivery problem never changes a scan result.</Notice>}
            <div className="flex flex-wrap gap-3">
              <Button variant="primary" busy={busy === 'test'} disabled={!t.allowed} onClick={() => run('test', () => api.tgTest(), (s) => { set(s); toast(s.bot.lastTestOk ? 'ok' : 'danger', s.bot.lastTestOk ? 'Telegram accepted the test message.' : s.bot.lastTestError ?? 'The test failed.'); })}>
                <Send className="size-4" /> Send a test message
              </Button>
              <Button variant="danger" onClick={() => setConfirmOff(true)}>
                <Unplug className="size-4" /> Disconnect and remove token
              </Button>
            </div>
          </div>
        ) : (
          <div className="mt-4 space-y-4">
            <ol className="list-decimal space-y-1 pl-5 text-sm text-muted">
              <li>In Telegram, open <span className="font-medium text-ink">@BotFather</span>, send <span className="font-mono">/newbot</span> and follow the steps. Copy the token it gives you.</li>
              <li>Open your new bot and press <span className="font-medium text-ink">Start</span>, so the bot is allowed to message you.</li>
              <li>Paste the token below and find your chat. SENTRIX only saves it after Telegram confirms the token and delivers a test message.</li>
            </ol>
            <label className="block text-sm">
              <span className="font-medium text-ink">Bot token</span>
              <div className="mt-2 flex max-w-xl gap-2">
                <input
                  type={show ? 'text' : 'password'}
                  value={token}
                  onChange={(e) => { setToken(e.target.value); setFound(null); }}
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="123456789:AA…"
                  disabled={!t.allowed}
                  className="w-full rounded border border-line bg-solid px-3 py-2 font-mono text-sm text-ink"
                />
                <Button aria-label={show ? 'Hide token' : 'Show token'} onClick={() => setShow((v) => !v)}>{show ? <EyeOff className="size-4" /> : <Eye className="size-4" />}</Button>
              </div>
              {token && !tokenLooksRight && <span className="mt-1 block text-xs text-warn">That does not look like a bot token (it should look like 123456789:ABC…).</span>}
            </label>
            <div className="flex flex-wrap items-end gap-3">
              <Button busy={busy === 'detect'} disabled={!tokenLooksRight || !t.allowed} onClick={detect}>Find my chat</Button>
              <label className="block text-sm">
                <span className="font-medium text-ink">Chat ID</span>
                <input inputMode="numeric" value={chat} onChange={(e) => setChat(e.target.value.replace(/[^\d-]/g, ''))} placeholder="Found automatically" disabled={!t.allowed} className="mt-2 block w-48 rounded border border-line bg-solid px-3 py-2 font-mono text-sm text-ink" />
              </label>
              <Button variant="primary" busy={busy === 'connect'} disabled={!tokenLooksRight || !Number(chat) || !t.allowed} onClick={connect}>Connect and send test</Button>
            </div>
            {found && found.length > 1 && (
              <p className="text-sm text-muted">
                Several chats have messaged this bot. Choose yours:{' '}
                {found.map((id) => (
                  <button key={id} className="mr-2 rounded-lg border border-line px-2 py-0.5 font-mono text-xs text-ink hover:border-strong" onClick={() => setChat(String(id))}>{id}</button>
                ))}
              </p>
            )}
            <p className="text-xs text-muted">The token is sent only to Telegram (api.telegram.org). It is stored encrypted with Windows data protection for your user account, never in a settings file, log, URL, or in any SENTRIX service.</p>
          </div>
        )}
      </Card>

      {bot.configured && (
        <>
          <Card className="px-5 py-3">
            <h2 className="text-sm font-semibold text-ink">What to send me</h2>
            <p className="mt-1 text-sm text-muted">Reports contain the file name, verdict, source and checks completed. File contents are never sent.</p>
            <div className="mt-2 divide-y divide-line">
              {PREFS.map(([k, label, desc]) => (
                <Toggle key={k} checked={t.notify[k]} disabled={busy === 'opts' || !t.allowed} onChange={(v) => savePref(k, v)} label={label} description={desc} />
              ))}
            </div>
          </Card>

          <Card className="px-5 py-3">
            <h2 className="text-sm font-semibold text-ink">Scan files I send to the bot</h2>
            <div className="divide-y divide-line">
              <Toggle
                checked={t.acceptSubmissions}
                disabled={busy === 'opts' || !t.allowed}
                onChange={(v) => run('opts', () => api.tgSetOptions(t.notify, v), set)}
                label="Accept files sent to my bot"
                description="Send a file to your bot in Telegram and SENTRIX scans it on this computer and replies with the result. Only messages from the chat you connected are accepted; anything else is ignored and counted. Files over 20 MB cannot be downloaded through the Bot API and are reported as not checked. Your computer must be on and SENTRIX running."
              />
            </div>
            <p className="mt-2 text-xs text-muted">Files are downloaded to an isolated temporary folder, scanned, and deleted. Ignored messages from other senders: {t.rejectedSubmissions}.</p>
          </Card>
        </>
      )}

      <Card className="p-5">
        <h2 className="text-sm font-semibold text-ink">Telegram Desktop downloads</h2>
        <p className="mt-1 text-sm text-muted">Files Telegram Desktop saves to your computer are scanned like any other download, and labelled “Telegram Desktop” in your history and reports. This works without a bot and without signing in to anything.</p>
        <dl className="mt-4 grid max-w-xl grid-cols-[12rem_1fr] gap-y-2 text-sm">
          <dt className="text-muted">Telegram Desktop</dt>
          <dd className="text-ink">{d.detection.installed ? 'Found on this computer' : 'Not found'}</dd>
          <dt className="text-muted">Watched folder</dt>
          <dd className="break-all font-mono text-xs text-ink">{d.folder ?? 'None'}</dd>
          <dt className="text-muted">Status</dt>
          <dd><Pill tone={d.watching ? 'ok' : d.folder ? 'warn' : 'muted'}>{d.watching ? 'Watching' : d.folder ? (d.exists ? 'Not watching' : 'Folder missing') : 'Off'}</Pill></dd>
          <dt className="text-muted">Scanned so far</dt>
          <dd className="text-ink">{d.scanned} · {d.threats} flagged</dd>
        </dl>
        {d.error && <div className="mt-3"><Notice tone="warn">{d.error}</Notice></div>}
        {d.detection.candidates.length > 0 && !d.folder && (
          <div className="mt-4 space-y-2">
            <div className="text-sm font-medium text-ink">Possible Telegram folders</div>
            {d.detection.candidates.map((c) => (
              <div key={c.path} className="flex items-center justify-between gap-3 rounded border border-line px-3 py-2">
                <div className="min-w-0">
                  <div className="truncate font-mono text-xs text-ink" title={c.path}>{c.path}</div>
                  <div className="text-xs text-muted">{c.exists ? `${c.fileCount} file(s)` : 'Does not exist yet'}</div>
                </div>
                <Button disabled={!c.exists} busy={busy === 'folder'} onClick={() => run('folder', () => api.tgSetDesktopFolder(c.path), set)}>Watch this</Button>
              </div>
            ))}
            <p className="text-xs text-muted">SENTRIX cannot read Telegram's own settings, so check these against Telegram Desktop → Settings → Advanced → Download path.</p>
          </div>
        )}
        <div className="mt-4 flex flex-wrap gap-3">
          <Button onClick={pickFolder} busy={busy === 'folder'}><FolderOpen className="size-4" /> Choose folder…</Button>
          {d.folder && <Button variant="danger" onClick={() => run('folder', () => api.tgSetDesktopFolder(null), set)}>Stop watching</Button>}
        </div>
        <p className="mt-3 text-xs text-muted">Covers files that Telegram Desktop saved to disk. Media you have only viewed, or have not downloaded, is not on disk and is not scanned.</p>
      </Card>

      <Card className="p-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-ink">Telegram account monitoring</h2>
            <p className="mt-1 text-sm text-muted">Scanning attachments in your personal chats, groups and channels directly from your account.</p>
          </div>
          <Pill tone="muted">Not available in this build</Pill>
        </div>
        <p className="mt-3 text-sm text-muted">{t.account.detail ?? 'Account-level monitoring is not implemented in this build.'}</p>
        <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-muted">
          <li>When it exists it will only use Telegram's official API, with your own API credentials, and will never ask for your Telegram password, login codes or two-step password.</li>
          <li>Even then it could only see attachments your account can download. It could not see secret chats, content you have not received, or messages deleted before they arrived.</li>
          <li>Until then, use Telegram Desktop folder scanning and the bot above. They cover files saved to your computer and files you send to your bot, not every Telegram message.</li>
        </ul>
      </Card>

      <Card className="overflow-hidden">
        <div className="border-b border-line px-6 py-4">
          <h2 className="text-sm font-semibold text-ink">Recent notifications</h2>
          <p className="mt-0.5 text-sm text-muted">Messages SENTRIX queued for your bot. Delivery state comes from Telegram's response.</p>
        </div>
        {!t.recentNotifications.length ? (
          <div className="px-6 py-5 text-sm text-muted">Nothing has been sent yet.</div>
        ) : (
          <ul className="divide-y divide-line">
            {t.recentNotifications.map((n) => (
              <li key={n.id} className="flex items-start justify-between gap-4 px-6 py-3">
                <div className="min-w-0">
                  <div className="text-sm text-ink">{n.kind.replace(/_/g, ' ')}</div>
                  <div className="text-xs text-muted" title={whenMs(n.createdAt)}>{agoMs(n.createdAt)}{n.attempts > 1 ? ` · ${n.attempts} attempts` : ''}</div>
                  {n.lastError && n.state !== 'sent' && <div className="mt-0.5 text-xs text-warn">{n.lastError}</div>}
                </div>
                <Pill tone={n.state === 'sent' ? 'ok' : n.state === 'dead' ? 'danger' : 'warn'}>{n.state === 'sent' ? 'Delivered' : n.state === 'dead' ? 'Gave up' : 'Waiting'}</Pill>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Modal
        open={confirmOff}
        onClose={() => setConfirmOff(false)}
        title="Disconnect your bot?"
        footer={
          <>
            <Button onClick={() => setConfirmOff(false)}>Cancel</Button>
            <Button variant="danger" busy={busy === 'off'} onClick={async () => { await run('off', () => api.tgDisconnect(), (s) => { set(s); toast('ok', 'Bot disconnected and the token was removed from this computer.'); }); setConfirmOff(false); }}>Disconnect</Button>
          </>
        }
      >
        <p>The saved token is erased from this computer, queued messages are discarded, and SENTRIX stops sending reports and reading files from the bot.</p>
        <p className="mt-2">This does not delete the bot. To make the old token unusable, revoke it with <span className="font-mono">/revoke</span> in @BotFather.</p>
      </Modal>
    </div>
  );
}

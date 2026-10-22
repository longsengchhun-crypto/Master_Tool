import { useState } from 'react';
import { open } from '@tauri-apps/plugin-dialog';
import { CheckCircle2, Eye, EyeOff, FolderOpen, Send } from 'lucide-react';
import { api, errText } from '../lib/api';
import { useApp } from '../lib/app';
import { agoMs } from '../lib/format';
import { usePolled } from '../lib/hooks';
import type { NotifyPrefs, TelegramStatus } from '../lib/types';
import { Button, Card, Disclosure, Modal, Notice, PageHeader, Pill, Tabs, Toggle, type TabTone } from '../components/ui';
import { TelegramAccount } from './TelegramAccount';
import { TelegramModes } from './TelegramModes';
import { openLink, TelegramSetup } from './TelegramSetup';

type Tab = 'account' | 'groups' | 'downloads' | 'reports';

const MORE: [keyof NotifyPrefs, string][] = [
  ['quarantined', 'When a file is quarantined automatically'],
  ['unableToVerify', 'Files that could not be fully checked (can be frequent)'],
  ['cleanScans', 'Every clean result (very frequent)'],
  ['accountEvents', 'If your Telegram account session ends'],
  ['includeHash', 'Include the file fingerprint (SHA-256) in reports'],
];

export function Telegram() {
  const { toast, refresh, status } = useApp();
  const st = usePolled(() => api.tgStatus(), 5000);
  const [token, setToken] = useState('');
  const [show, setShow] = useState(false);
  const [chats, setChats] = useState<number[] | null>(null);
  const [manual, setManual] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [confirmOff, setConfirmOff] = useState(false);
  const [confirmUnlink, setConfirmUnlink] = useState(false);
  const [tab, setTab] = useState<Tab>('account');
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

  const linkToBot = (code: string) => run('relay', () => api.tgRelayLink(code), (s) => { set(s); toast('ok', 'Linked. Check Telegram: the bot just said hello.'); });

  const bot = t.bot;
  const r = t.relay;
  const tokenOk = /^\d{5,}:[A-Za-z0-9_-]{30,}$/.test(token.trim());
  const d = t.desktop;
  const candidate = d.detection.candidates.find((c) => c.exists);
  const problems = t.notify.engineProblems && t.notify.protectionStopped;
  const healthy = bot.connected && bot.lastTestOk !== false;
  const reportsReady = r.linked || bot.configured;
  const relayHealthy = r.linked && r.reachable !== false && !r.error;

  // ---- pieces shared by the two ways of getting results -------------------------------------------------------------

  const ownBotSetup = (
    <Card className="p-6">
      <h2 className="text-base font-semibold text-ink">Use your own Telegram bot</h2>
      <p className="mt-1 text-sm text-muted">For people who want a private bot that only they control. SENTRIX never asks for your Telegram password or login code.</p>
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
  );

  const desktopCard = (
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
  );

  const unlinkModal = (
    <Modal
      open={confirmUnlink}
      onClose={() => setConfirmUnlink(false)}
      title="Unlink this computer from the SENTRIX bot?"
      footer={
        <>
          <Button onClick={() => setConfirmUnlink(false)}>Cancel</Button>
          <Button variant="danger" busy={busy === 'unlink'} onClick={async () => { await run('unlink', () => api.tgRelayUnlink(), (s) => { set(s); toast('ok', 'Unlinked. Results will no longer be sent to Telegram.'); }); setConfirmUnlink(false); }}>Unlink</Button>
        </>
      }
    >
      <p>Results from this computer stop going to your chat with the bot. Your groups, which are managed in the bot, are not affected. You can link again any time with a new code.</p>
    </Modal>
  );

  const ownBotModal = (
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
  );

  // ---- first run: nothing is linked yet -----------------------------------------------------------------------------

  if (!reportsReady && r.available) {
    return (
      <div className="space-y-5">
        <PageHeader title="Telegram" subtitle="Connect SENTRIX to Telegram so results reach you, privately." />
        {!t.allowed && <Notice tone="info">Your organization does not allow Telegram on this device.</Notice>}
        <TelegramSetup t={t} busy={busy === 'relay'} onLink={linkToBot} />
        <Disclosure title="Use my own bot instead" hint="advanced">
          <div className="p-1">{ownBotSetup}</div>
        </Disclosure>
        {desktopCard}
        {unlinkModal}
        {ownBotModal}
      </div>
    );
  }

  if (!reportsReady) {
    // This build has no shared bot: the person brings their own.
    return (
      <div className="space-y-5">
        <PageHeader title="Telegram" subtitle="Connect your own Telegram bot so results reach you." />
        {!t.allowed && <Notice tone="info">Your organization does not allow Telegram on this device.</Notice>}
        <Notice tone="info" title="The SENTRIX bot is not set up in this copy of the app">
          Normally you would just open the SENTRIX bot and link it with a code. This copy does not know where the SENTRIX bot's relay is, so only your own bot can be used for now.
        </Notice>
        {ownBotSetup}
        {desktopCard}
        {ownBotModal}
      </div>
    );
  }

  // ---- connected ----------------------------------------------------------------------------------------------------

  const a = t.account;
  const tones: Record<Tab, TabTone> = {
    reports: r.linked ? (relayHealthy ? 'ok' : 'warn') : healthy ? 'ok' : 'warn',
    account:
      a.state === 'connected' ? (a.options.enabled && a.connection === 'ready' ? 'ok' : 'warn')
      : a.state === 'expired' || a.state === 'failed' || a.state === 'two_step_unsupported' ? 'warn'
      : 'off',
    groups: r.linked ? 'off' : t.groups.shield ? (t.groups.privacyBlocks ? 'warn' : 'ok') : 'off',
    downloads: d.folder ? (d.watching ? 'ok' : 'warn') : 'off',
  };

  const toggles = (
    <Card className="divide-y divide-line px-5 py-1">
      <Toggle checked={t.notify.malicious} disabled={busy === 'opts' || !t.allowed} onChange={(v) => savePrefs({ malicious: v })} label="Dangerous files" description="A malware engine identified a file as malicious." />
      <Toggle checked={t.notify.suspicious} disabled={busy === 'opts' || !t.allowed} onChange={(v) => savePrefs({ suspicious: v })} label="Suspicious files" description="Signs that deserve a closer look. Not proof of malware." />
      <Toggle checked={problems} disabled={busy === 'opts' || !t.allowed} onChange={(v) => savePrefs({ engineProblems: v, protectionStopped: v })} label="Problems with SENTRIX" description="The scanner stopped, definitions are out of date, or a watched folder stopped working." />
      {!r.linked && (
        <Toggle
          checked={t.acceptSubmissions}
          disabled={busy === 'opts' || !t.allowed}
          onChange={(v) => run('opts', () => api.tgSetOptions(t.notify, v), set)}
          label="Scan files I send to my bot"
          description="Send a file to your bot and get the result back. Only your own chat is accepted, files up to 20 MB, and this computer must be on."
        />
      )}
    </Card>
  );

  const moreOptions = (
    <Disclosure title="More options">
      <div className="divide-y divide-line px-5 py-1">
        {MORE.map(([k, label]) => (
          <Toggle key={k} checked={t.notify[k]} disabled={busy === 'opts' || !t.allowed} onChange={(v) => savePrefs({ [k]: v })} label={label} />
        ))}
      </div>
      {!r.linked && t.recentNotifications.length > 0 && (
        <ul className="divide-y divide-line border-t border-line">
          {t.recentNotifications.slice(0, 8).map((n) => (
            <li key={n.id} className="flex items-center justify-between gap-4 px-5 py-2.5 text-sm">
              <span className="text-ink">{n.kind.replace(/_/g, ' ')} <span className="text-xs text-muted">{agoMs(n.createdAt)}</span></span>
              <Pill tone={n.state === 'sent' ? 'ok' : n.state === 'dead' ? 'danger' : 'warn'}>{n.state === 'sent' ? 'Delivered' : n.state === 'dead' ? 'Gave up' : 'Waiting'}</Pill>
            </li>
          ))}
        </ul>
      )}
    </Disclosure>
  );

  const relayCard = (
    <Card className="p-5">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <CheckCircle2 className={`size-6 ${relayHealthy ? 'text-ok' : 'text-warn'}`} aria-hidden />
          <div>
            <div className="text-sm font-semibold text-ink">
              {relayHealthy ? 'Linked to the SENTRIX bot' : 'Linked, but the bot cannot reach you'}
              {r.userName ? ` as ${r.userName}` : ''}
            </div>
            <div className="text-xs text-muted">
              Results arrive in your chat with @{r.botUsername}
              {r.checkedAt ? ` · checked ${agoMs(r.checkedAt)}` : ''}
            </div>
          </div>
        </div>
        <div className="flex gap-2">
          {r.botLink && <Button onClick={() => void openLink(r.botLink!)}>Open the bot</Button>}
          <Button busy={busy === 'rtest'} onClick={() => run('rtest', () => api.tgRelayTest(), (s) => { set(s); toast('ok', 'A test message was sent. Check Telegram.'); })}>
            <Send className="size-4" /> Send test
          </Button>
          <Button variant="danger" onClick={() => setConfirmUnlink(true)}>Unlink</Button>
        </div>
      </div>
      {r.reachable === false && <div className="mt-3"><Notice tone="warn" title="The bot cannot write to you">Open the bot in Telegram and press Start (and unblock it if you blocked it). Until then, results cannot reach you.</Notice></div>}
      {r.error && <div className="mt-3"><Notice tone="danger">{r.error}</Notice></div>}
    </Card>
  );

  const ownBotCard = (
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
  );

  const groupsInBot = (
    <Card className="p-6">
      <h2 className="text-base font-semibold text-ink">Protect a group</h2>
      <p className="mt-1 max-w-2xl text-sm text-muted">Groups are set up in the SENTRIX bot, not in this app, and they keep working even when this computer is off.</p>
      <ol className="mt-4 space-y-2 text-sm text-muted">
        <li><span className="font-semibold text-ink">1.</span> Open the bot and choose <span className="font-medium text-ink">Protect a group</span>.</li>
        <li><span className="font-semibold text-ink">2.</span> Press <span className="font-medium text-ink">Choose a group</span> and pick it. Telegram adds the bot. You must be an administrator of that group.</li>
        <li><span className="font-semibold text-ink">3.</span> The bot confirms in your chat. From then on, results for that group arrive there, never in the group itself.</li>
      </ol>
      <div className="mt-4">{r.botLink && <Button variant="primary" onClick={() => void openLink(r.botLink!)}>Open the bot</Button>}</div>
      <div className="mt-5 grid gap-x-8 gap-y-1.5 border-t border-line pt-4 text-xs text-muted md:grid-cols-2">
        <p>Send <span className="font-mono text-ink">/groups</span> to the bot to see, pause or remove your groups.</p>
        <p>Documents up to 20 MB are checked. Photos, videos and bigger files are reported as not checked.</p>
        <p>Files from the group are checked on SENTRIX's server and deleted straight away. They are not kept.</p>
        <p>If Telegram hides a group's files from the bot, the bot tells you to make it an administrator there.</p>
      </div>
    </Card>
  );

  const groupsOwnBot = bot.configured ? (
    <Card className="overflow-hidden">
      <div className="px-5 py-1">
        <Toggle
          checked={t.groups.shield}
          disabled={busy === 'groups' || !t.allowed || !t.groups.allowed}
          onChange={(v) => run('groups', () => api.tgSetGroupShield(v), set)}
          label="Protect Telegram groups"
          description={t.groups.allowed ? 'Add your bot to a group. A group administrator then sends /setup on there. Files posted as documents (up to 20 MB) are scanned on this computer, so it must be on. Results come to your chat with the bot, not the group.' : 'Your organization does not allow this.'}
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
          <p className="border-t border-line px-5 py-3 text-xs text-muted">Photos, videos and files over 20 MB cannot be scanned. Only a group administrator confirmed by Telegram can change a group's settings, and only that same administrator can agree to automatic deletion.</p>
        </div>
      )}
    </Card>
  ) : null;

  const tabs: { id: Tab; label: string; tone: TabTone }[] = [
    { id: 'account', label: 'Your account', tone: tones.account },
    { id: 'groups', label: 'Groups', tone: tones.groups },
    { id: 'downloads', label: 'Downloads', tone: tones.downloads },
    { id: 'reports', label: 'Reports', tone: tones.reports },
  ];

  return (
    <div className="space-y-5">
      <PageHeader title="Telegram" subtitle="Choose what SENTRIX watches. Results come to you in Telegram, privately." />
      {!t.allowed && <Notice tone="info">Your organization does not allow Telegram on this device.</Notice>}
      {r.removedRemotely && <Notice tone="warn" title="This computer was unlinked in the bot">Results are not reaching you until you link it again.</Notice>}

      <TelegramModes
        t={t}
        engine={status?.engine}
        busy={busy === 'both'}
        onOpen={(x) => setTab(x === 'reports' ? 'reports' : x)}
        onBoth={() => {
          if (r.linked) {
            // The shared bot manages groups itself; the account needs this person's own consent and QR approval here.
            setTab('account');
            return;
          }
          if (!t.groups.shield) void run('both', () => api.tgSetGroupShield(true), (s) => { set(s); setTab('account'); });
          else setTab('account');
        }}
      />

      <Tabs label="Telegram protection" value={tab} onChange={setTab} tabs={tabs} />

      {tab === 'account' && (
        <div role="tabpanel" id="panel-account" aria-labelledby="tab-account">
          <TelegramAccount a={a} reload={st.reload} setData={(acc) => st.setData({ ...t, account: acc })} />
        </div>
      )}

      {tab === 'groups' && (
        <div role="tabpanel" id="panel-groups" aria-labelledby="tab-groups">
          {r.linked ? groupsInBot : groupsOwnBot}
        </div>
      )}

      {tab === 'downloads' && (
        <div role="tabpanel" id="panel-downloads" aria-labelledby="tab-downloads">{desktopCard}</div>
      )}

      {tab === 'reports' && (
        <div role="tabpanel" id="panel-reports" aria-labelledby="tab-reports" className="space-y-5">
          {r.linked ? relayCard : ownBotCard}
          {toggles}
          {moreOptions}
        </div>
      )}

      {unlinkModal}
      {ownBotModal}
    </div>
  );
}

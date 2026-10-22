import { agoMs } from '../lib/format';
import type { AppStatus, TelegramStatus } from '../lib/types';
import { Button, Card, Pill } from '../components/ui';

type Tone = 'ok' | 'warn' | 'danger' | 'muted';
type Dot = 'ok' | 'warn' | 'danger' | 'off';

interface Mode {
  title: string;
  /** One of: Protection active, Limited coverage, Permission required, Scanner unavailable, Connection expired, Disconnected, Connected, Paused, Offline, Off. */
  word: string;
  tone: Tone;
  detail: string;
  lights: [string, Dot][];
  /** `undefined` hides the line (the desktop cannot know it, for example for groups managed in the bot). */
  lastScan: number | null | undefined;
  lastReport: number | null | undefined;
  threats: number;
}

/**
 * "Enabled" is not "protected". The status word is only "Protection active" when the integration is connected, the scanner is
 * healthy and something is actually being watched. Every other state says what is missing.
 */
export function modes(t: TelegramStatus, engine: AppStatus['engine'] | undefined): { group: Mode; personal: Mode } {
  const scannerOk = engine?.state === 'running';
  const scannerDot: Dot = scannerOk ? 'ok' : 'danger';
  const viaBot = t.relay.linked;
  const reportOk = viaBot ? t.relay.reachable !== false && !t.relay.error : t.bot.connected && t.bot.lastTestOk !== false;
  const reportDot: Dot = viaBot ? (reportOk ? 'ok' : 'warn') : !t.bot.configured ? 'off' : t.bot.failed24h > 0 || t.bot.lastDeliveryError ? 'warn' : reportOk ? 'ok' : 'warn';
  const reports: [string, Dot] = ['Reports', reportDot];

  // ---- groups
  const g = t.groups;
  const enabledGroups = g.list.filter((x) => x.enabled);
  const gLast = g.list.reduce<number | null>((m, x) => (x.stats.lastScanAt && (!m || x.stats.lastScanAt > m) ? x.stats.lastScanAt : m), null);
  const gThreats = g.list.reduce((n, x) => n + x.stats.threats, 0);
  let group: Pick<Mode, 'word' | 'tone' | 'detail'>;
  if (!t.allowed || !g.allowed) group = { word: 'Off', tone: 'muted', detail: 'Your organization does not allow this.' };
  else if (viaBot) group = { word: 'Set up in the bot', tone: 'muted', detail: 'Groups are added and managed in the SENTRIX bot. Open it and choose Protect a group. Results appear in your Scan History group.' };
  else if (!t.bot.configured) group = { word: 'Disconnected', tone: 'muted', detail: 'Connect your bot first. Group protection runs through it.' };
  else if (!g.shield) group = { word: 'Off', tone: 'muted', detail: 'Switch it on, add your bot to a group, then a group administrator sends /setup on.' };
  else if (!scannerOk) group = { word: 'Scanner unavailable', tone: 'danger', detail: 'Files in groups cannot be checked right now, and are never reported as safe.' };
  else if (enabledGroups.length === 0) group = { word: 'Permission required', tone: 'warn', detail: g.list.length ? 'A group administrator still has to send /setup on in the group.' : 'No group yet. Add your bot to a group, then an administrator sends /setup on.' };
  else if (g.privacyBlocks) group = { word: 'Limited coverage', tone: 'warn', detail: 'Telegram privacy mode hides group files from your bot. Make it an administrator or disable privacy mode.' };
  else group = { word: 'Protection active', tone: 'ok', detail: `${enabledGroups.length} group${enabledGroups.length === 1 ? '' : 's'} protected. Documents up to 20 MB, only while this computer is on.` };
  const groupMode: Mode = {
    title: 'Group protection',
    ...group,
    lights: viaBot
      ? [
          ['Linked to the bot', 'ok'],
          reports,
        ]
      : [
          ['Enabled', g.shield ? 'ok' : 'off'],
          ['Bot connected', t.bot.configured ? (reportOk ? 'ok' : 'warn') : 'off'],
          ['Groups protected', enabledGroups.length ? 'ok' : g.shield ? 'warn' : 'off'],
          ['Visibility', g.shield ? (g.privacyBlocks ? 'warn' : 'ok') : 'off'],
          ['Scanner', g.shield ? scannerDot : 'off'],
          reports,
        ],
    lastScan: viaBot ? undefined : gLast,
    lastReport: viaBot ? undefined : t.bot.lastDeliveryAt,
    threats: viaBot ? 0 : gThreats,
  };

  // ---- personal account
  const a = t.account;
  let personal: Pick<Mode, 'word' | 'tone' | 'detail'>;
  const connected = a.state === 'connected';
  if (a.state === 'unconfigured') personal = { word: 'Off', tone: 'muted', detail: 'Not available in this copy of SENTRIX.' };
  else if (!a.allowed) personal = { word: 'Off', tone: 'muted', detail: 'Your organization does not allow this.' };
  else if (a.state === 'expired') personal = { word: 'Connection expired', tone: 'warn', detail: 'Telegram ended the session. Sign in again to resume.' };
  else if (a.state === 'two_step_unsupported') personal = { word: 'Disconnected', tone: 'muted', detail: 'That account uses a two-step password, which SENTRIX will not handle.' };
  else if (a.state === 'failed') personal = { word: 'Disconnected', tone: 'danger', detail: 'The last sign-in did not complete.' };
  else if (a.state === 'waiting_for_scan' || a.state === 'starting') personal = { word: 'Connected', tone: 'warn', detail: 'Waiting for you to approve the QR code on your phone.' };
  else if (!connected) personal = { word: 'Disconnected', tone: 'muted', detail: 'Sign in with a QR code to check files sent to your account.' };
  else if (!a.options.enabled) personal = { word: 'Paused', tone: 'warn', detail: 'Signed in, but not checking files.' };
  else if (!scannerOk) personal = { word: 'Scanner unavailable', tone: 'danger', detail: 'Files cannot be checked right now, and are never reported as safe.' };
  else if (a.connection !== 'ready' && a.connection !== 'updating') personal = { word: 'Offline', tone: 'warn', detail: 'Cannot reach Telegram. Files that arrive now may not be checked.' };
  else {
    const where = [a.options.privateChats && 'private chats', a.options.groups && 'groups', a.options.channels && 'channels'].filter(Boolean).join(', ') || 'nothing selected';
    const nothing = !a.options.privateChats && !a.options.groups && !a.options.channels;
    personal = nothing
      ? { word: 'Limited coverage', tone: 'warn', detail: 'No chat type is switched on, so nothing is being checked.' }
      : { word: 'Protection active', tone: 'ok', detail: `Checking files in ${where}. Secret chats and protected content are not covered.` };
  }
  const personalMode: Mode = {
    title: 'Personal account',
    ...personal,
    lights: [
      ['Enabled', connected || a.state === 'expired' ? (a.options.enabled ? 'ok' : 'warn') : 'off'],
      ['Signed in', connected ? 'ok' : a.state === 'expired' ? 'danger' : 'off'],
      ['Monitoring', connected && a.options.enabled && a.connection === 'ready' ? 'ok' : connected ? 'warn' : 'off'],
      ['Scanner', connected ? scannerDot : 'off'],
      ['Coverage', connected ? (a.options.privateChats && (a.options.groups || a.options.channels) ? 'ok' : 'warn') : 'off'],
      reports,
    ],
    lastScan: a.lastScanAt,
    lastReport: t.bot.lastDeliveryAt,
    threats: a.counts.threats,
  };
  return { group: groupMode, personal: personalMode };
}

const DOT = { ok: 'bg-ok', warn: 'bg-warn', danger: 'bg-danger', off: 'bg-strong' };
const DOT_WORD = { ok: 'ok', warn: 'needs attention', danger: 'problem', off: 'off' };

function ModeCard({ m, action }: { m: Mode; action?: React.ReactNode }) {
  return (
    <Card className="flex flex-col p-5">
      <div className="flex items-start justify-between gap-3">
        <h2 className="text-sm font-semibold text-ink">{m.title}</h2>
        <Pill tone={m.tone}>{m.word}</Pill>
      </div>
      <p className="mt-1.5 min-h-10 text-sm text-muted">{m.detail}</p>
      <ul className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs text-muted">
        {m.lights.map(([k, d]) => (
          <li key={k} className="flex items-center gap-2">
            <span className={`size-2 shrink-0 rounded-full ${DOT[d]}`} aria-hidden />
            <span>{k}<span className="sr-only">: {DOT_WORD[d]}</span></span>
          </li>
        ))}
      </ul>
      <dl className="mt-3 flex flex-wrap gap-x-5 gap-y-1 border-t border-line pt-3 text-xs">
        {m.lastScan !== undefined && <div><dt className="inline text-muted">Last scan </dt><dd className="inline font-semibold text-ink">{m.lastScan ? agoMs(m.lastScan) : 'None yet'}</dd></div>}
        {m.lastReport !== undefined && <div><dt className="inline text-muted">Last report </dt><dd className="inline font-semibold text-ink">{m.lastReport ? agoMs(m.lastReport) : 'None yet'}</dd></div>}
        {m.threats > 0 && <div><dt className="inline text-muted">Threats </dt><dd className="inline font-semibold text-danger">{m.threats}</dd></div>}
      </dl>
      {action && <div className="mt-3">{action}</div>}
    </Card>
  );
}

export function TelegramModes({ t, engine, onOpen, onBoth, busy }: { t: TelegramStatus; engine: AppStatus['engine'] | undefined; onOpen: (tab: 'reports' | 'account' | 'groups') => void; onBoth: () => void; busy: boolean }) {
  const { group, personal } = modes(t, engine);
  const bothOn = group.word === 'Protection active' && personal.word === 'Protection active';
  const groupGo = t.bot.configured || t.relay.linked ? 'groups' : 'reports';
  return (
    <section aria-label="Protection modes" className="mb-5">
      <div className="grid gap-4 md:grid-cols-2">
        <ModeCard m={group} action={<Button onClick={() => onOpen(groupGo)}>{t.relay.linked ? 'How to add a group' : t.bot.configured ? 'Group settings' : 'Set up your bot'}</Button>} />
        <ModeCard m={personal} action={<Button onClick={() => onOpen('account')}>Account settings</Button>} />
      </div>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-3 text-sm text-muted">
        <span>{bothOn ? 'Both are active. Each keeps its own settings and counts, and reports go to your bot without duplicates.' : 'Use either one, or both. They are independent: turning one off does not affect the other.'}</span>
        {!bothOn && t.allowed && t.groups.allowed && t.account.allowed && t.account.state !== 'unconfigured' && (
          <Button busy={busy} onClick={onBoth}>Set up both</Button>
        )}
      </div>
    </section>
  );
}

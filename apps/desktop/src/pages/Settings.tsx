import { useEffect, useState } from 'react';
import { disable, enable, isEnabled } from '@tauri-apps/plugin-autostart';
import { api, errText } from '../lib/api';
import { useApp } from '../lib/app';
import type { Settings as S, UpdateInfo } from '../lib/types';
import { Button, Card, Disclosure, Modal, Notice, PageHeader, Row, Rows, Toggle } from '../components/ui';
import { Account } from './Account';

export function Settings() {
  const { status, refresh, toast } = useApp();
  const [autostart, setAutostart] = useState<boolean | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const [upd, setUpd] = useState<UpdateInfo | null>(null);
  const [updBusy, setUpdBusy] = useState<'check' | 'install' | null>(null);
  const [confirmInstall, setConfirmInstall] = useState(false);

  const checkUpdate = async () => {
    setUpdBusy('check');
    try {
      setUpd(await api.checkUpdate());
    } catch (e) {
      toast('danger', errText(e));
    } finally {
      setUpdBusy(null);
    }
  };

  const installUpdate = async () => {
    setUpdBusy('install');
    try {
      await api.installUpdate(); // verifies the signature, installs, then restarts the app
    } catch (e) {
      setConfirmInstall(false);
      toast('danger', errText(e));
      setUpdBusy(null);
    }
  };

  useEffect(() => {
    isEnabled().then(setAutostart).catch(() => setAutostart(null));
  }, []);

  if (!status) return <div className="text-muted">Loading…</div>;
  const s = status.settings;
  const managed = !!status.managedBy;

  const save = async (patch: Partial<S>) => {
    try {
      await api.setSettings({ ...s, ...patch });
      await refresh();
    } catch (e) {
      toast('danger', errText(e));
    }
  };

  const setStartup = async (v: boolean) => {
    try {
      v ? await enable() : await disable();
      setAutostart(await isEnabled());
    } catch (e) {
      toast('danger', errText(e));
    }
  };

  const pub = status.publisher.state;

  return (
    <div className="space-y-5">
      <PageHeader title="Settings" />

      <Card className="divide-y divide-line px-5 py-1">
        <div className="flex items-center justify-between gap-6 py-3">
          <label htmlFor="theme" className="text-sm font-semibold text-ink">Appearance</label>
          <select id="theme" value={s.theme} onChange={(e) => save({ theme: e.target.value as S['theme'] })} className="h-9 rounded-lg border border-strong bg-solid px-3 text-sm text-ink">
            <option value="system">Match Windows</option>
            <option value="dark">Dark</option>
            <option value="light">Light</option>
          </select>
        </div>
        <Toggle checked={s.notifications} onChange={(v) => save({ notifications: v })} label="Desktop notifications" description="Tell me when a dangerous or suspicious file is found." />
        <Toggle checked={!!autostart} disabled={autostart === null} onChange={setStartup} label="Start when I sign in" description="Keeps automatic scanning on after a restart. SENTRIX only protects you while it is running." />
      </Card>

      <Card className="px-5 py-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-ink">Updates</h2>
            <p className="mt-0.5 text-sm text-muted">
              {upd ? (upd.available ? `Version ${upd.version} is available.` : `${upd.message}${upd.configured ? ` (version ${upd.current})` : ''}`) : `Version ${status.version}. Updates are signed and verified before they install.`}
            </p>
          </div>
          {upd?.available ? <Button variant="primary" onClick={() => setConfirmInstall(true)}>Install {upd.version}</Button> : <Button busy={updBusy === 'check'} onClick={checkUpdate}>Check for updates</Button>}
        </div>
        {upd?.available && upd.notes && <p className="mt-3 whitespace-pre-line rounded-lg bg-surface2 p-3 text-sm text-muted">{upd.notes}</p>}
      </Card>

      <Card className="px-5 py-4">
        <h2 className="text-sm font-semibold text-ink">Your privacy</h2>
        <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-muted">
          <li>Files are scanned on this computer and never uploaded.</li>
          <li>The only download is malware definitions from ClamAV, which says nothing about your files.</li>
          <li>If you connect a Telegram bot, report text (file name, result) goes to Telegram. Nothing else leaves this computer.</li>
        </ul>
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <Button variant="danger" onClick={() => setConfirmClear(true)}>Clear scan history</Button>
          <span className="text-xs text-muted">Quarantined files are not affected.</span>
        </div>
      </Card>

      <Disclosure title="Scan limits" hint="for advanced use">
        <div className="space-y-3 px-5 py-4">
          {managed && <Notice tone="info">Managed by {status.managedBy}.</Notice>}
          <p className="text-sm text-muted">Files above these limits are only partly checked and are reported that way, never as clean.</p>
          <div className="grid gap-4 sm:grid-cols-2">
            <label className="block text-sm">
              <span className="font-semibold text-ink">Largest file to check (MB)</span>
              <input type="number" disabled={managed} min={1} max={4096} defaultValue={s.maxFileSizeMb} onBlur={(e) => { const n = Number(e.target.value); if (n !== s.maxFileSizeMb) void save({ maxFileSizeMb: n }); }} className="mt-1.5 h-9 w-full rounded-lg border border-strong bg-solid px-3 text-ink" />
            </label>
            <label className="block text-sm">
              <span className="font-semibold text-ink">Archive nesting depth</span>
              <input type="number" disabled={managed} min={0} max={8} defaultValue={s.archiveMaxDepth} onBlur={(e) => { const n = Number(e.target.value); if (n !== s.archiveMaxDepth) void save({ archiveMaxDepth: n }); }} className="mt-1.5 h-9 w-full rounded-lg border border-strong bg-solid px-3 text-ink" />
            </label>
          </div>
          <Toggle checked={s.allowRestoreSuspicious} disabled={managed} onChange={(v) => save({ allowRestoreSuspicious: v })} label="Let me restore or dismiss suspicious files" />
        </div>
      </Disclosure>

      <Disclosure title="Organization" hint={status.managedBy ? `managed by ${status.managedBy}` : 'optional, for company devices'}>
        <div className="space-y-4 p-5">
          <Toggle checked={s.telemetryEnabled} onChange={(v) => save({ telemetryEnabled: v })} label="Share health information with my organization" description="Only if this device is enrolled. Counts and status, never file names or contents. Turning it off never turns protection off." />
          <Account />
        </div>
      </Disclosure>

      <Disclosure title="About">
        <Rows>
          <Row label="Version">{status.version}</Row>
          <Row label="Publisher check" tone={pub === 'signed_trusted' ? 'ok' : 'warn'}>
            {pub === 'signed_trusted' ? 'Signed by a trusted publisher' : pub === 'unsigned' ? 'Not code-signed, so Windows cannot confirm the publisher' : pub === 'unknown' ? 'Could not be determined' : `Problem: ${pub.replace('_', ' ')}`}
          </Row>
          <Row label="Data folder"><span className="break-all font-mono text-xs">{status.dataDir}</span></Row>
        </Rows>
      </Disclosure>

      <Modal
        open={confirmInstall}
        onClose={() => updBusy !== 'install' && setConfirmInstall(false)}
        title={`Install SENTRIX ${upd?.version ?? ''}?`}
        footer={
          <>
            <Button disabled={updBusy === 'install'} onClick={() => setConfirmInstall(false)}>Not now</Button>
            <Button variant="primary" busy={updBusy === 'install'} onClick={installUpdate}>Install and restart</Button>
          </>
        }
      >
        SENTRIX downloads the update, checks its signature, installs it and restarts. Protection pauses briefly. If the check fails, nothing is installed.
      </Modal>

      <Modal
        open={confirmClear}
        onClose={() => setConfirmClear(false)}
        title="Clear scan history?"
        footer={
          <>
            <Button onClick={() => setConfirmClear(false)}>Cancel</Button>
            <Button
              variant="danger"
              onClick={async () => {
                await api.clearHistory();
                setConfirmClear(false);
                toast('ok', 'Scan history cleared.');
                void refresh();
              }}
            >
              Clear history
            </Button>
          </>
        }
      >
        This removes the list of past scans from this computer. No files are deleted.
      </Modal>
    </div>
  );
}

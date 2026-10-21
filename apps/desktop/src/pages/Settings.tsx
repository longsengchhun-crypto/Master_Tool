import { useEffect, useState } from 'react';
import { disable, enable, isEnabled } from '@tauri-apps/plugin-autostart';
import { api, errText } from '../lib/api';
import { useApp } from '../lib/app';
import type { Settings as S, UpdateInfo } from '../lib/types';
import { Button, Card, Modal, Notice, PageHeader, Toggle } from '../components/ui';

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

  return (
    <div className="space-y-6">
      <PageHeader title="Settings" />

      <Card className="divide-y divide-line px-5 py-1">
        <div className="py-4">
          <label htmlFor="theme" className="block text-sm font-medium text-ink">
            Appearance
          </label>
          <select id="theme" value={s.theme} onChange={(e) => save({ theme: e.target.value as S['theme'] })} className="mt-2 h-8 rounded border border-strong bg-solid px-2 text-sm text-ink">
            <option value="system">Match my system</option>
            <option value="dark">Dark</option>
            <option value="light">Light</option>
          </select>
        </div>
        <Toggle checked={s.notifications} onChange={(v) => save({ notifications: v })} label="Notifications" description="Tell me when a malicious or suspicious file is found. Each file is announced once." />
        <Toggle
          checked={!!autostart}
          disabled={autostart === null}
          onChange={setStartup}
          label="Start SENTRIX when I sign in"
          description="Runs quietly in the system tray so real-time protection is on from the start. Off unless you turn it on here."
        />
      </Card>

      <Card className="px-5 py-4">
        <h2 className="text-sm font-semibold text-ink">Scan limits</h2>
        <p className="mt-1 text-sm text-muted">Files above these limits are only partly checked and are reported as such. They are never reported as clean.</p>
        {status.managedBy && <div className="mt-3"><Notice tone="info">Managed by {status.managedBy}.</Notice></div>}
        <div className="mt-4 grid gap-5 sm:grid-cols-2">
          <label className="block text-sm">
            <span className="font-medium text-ink">Largest file sent to the engine (MB)</span>
            <input type="number" disabled={!!status.managedBy} min={1} max={4096} defaultValue={s.maxFileSizeMb} onBlur={(e) => { const n = Number(e.target.value); if (n !== s.maxFileSizeMb) void save({ maxFileSizeMb: n }); }} className="mt-2 w-full rounded border border-line bg-solid px-3 py-2 text-ink" />
          </label>
          <label className="block text-sm">
            <span className="font-medium text-ink">Archive nesting depth</span>
            <input type="number" disabled={!!status.managedBy} min={0} max={8} defaultValue={s.archiveMaxDepth} onBlur={(e) => { const n = Number(e.target.value); if (n !== s.archiveMaxDepth) void save({ archiveMaxDepth: n }); }} className="mt-2 w-full rounded border border-line bg-solid px-3 py-2 text-ink" />
          </label>
        </div>
      </Card>

      <Card className="px-5 py-3">
        <h2 className="text-sm font-semibold text-ink">Privacy</h2>
        <ul className="mt-2 space-y-1.5 text-sm text-muted">
          <li>Files are scanned on this computer. File contents are never uploaded.</li>
          <li>Downloading new signatures from ClamAV's servers does not send any information about your files.</li>
          <li>Hash-based reputation lookups and sample uploads are not part of this build.</li>
          <li>Your scan history and quarantine live in <span className="break-all font-mono text-xs text-ink">{status.dataDir}</span>.</li>
        </ul>
        <div className="mt-2 divide-y divide-line">
          <Toggle
            checked={s.telemetryEnabled}
            onChange={(v) => save({ telemetryEnabled: v })}
            label="Share operational health with my organization's console"
            description="Only if this device is enrolled. Sends engine status and scan counts, not file names or contents. Turning this off never turns protection off."
          />
        </div>
      </Card>

      <Card className="px-5 py-4">
        <h2 className="text-sm font-semibold text-ink">Data</h2>
        <div className="mt-3 flex flex-wrap gap-3">
          <Button variant="danger" onClick={() => setConfirmClear(true)}>
            Clear scan history
          </Button>
        </div>
        <p className="mt-3 text-xs text-muted">Quarantined files are not affected.</p>
      </Card>

      <Card className="px-5 py-4">
        <h2 className="text-sm font-semibold text-ink">Application updates</h2>
        <p className="mt-1 text-sm text-muted">Updates to SENTRIX itself. These are separate from malware signature updates. Every update is checked against a publisher signature before it is installed; an update that fails the check is refused.</p>
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <Button busy={updBusy === 'check'} onClick={checkUpdate}>Check for updates</Button>
          {upd && !upd.available && <span className={`text-sm ${upd.configured ? 'text-muted' : 'text-warn'}`}>{upd.message} {upd.configured ? `(version ${upd.current})` : ''}</span>}
          {upd?.available && (
            <Button variant="primary" onClick={() => setConfirmInstall(true)}>
              Install {upd.version}
            </Button>
          )}
        </div>
        {upd?.available && upd.notes && <p className="mt-3 whitespace-pre-line rounded bg-surface2 p-3 text-sm text-muted">{upd.notes}</p>}
      </Card>

      <Card className="px-5 py-4">
        <h2 className="text-sm font-semibold text-ink">About</h2>
        <dl className="mt-3 grid max-w-md grid-cols-[12rem_1fr] gap-y-2 text-sm">
          <dt className="text-muted">Version</dt>
          <dd className="text-ink">{status.version}</dd>
          <dt className="text-muted">Analysis core</dt>
          <dd className="text-ink">{status.engine.core_version}</dd>
          <dt className="text-muted">Platform</dt>
          <dd className="text-ink">{status.capabilities.platform}</dd>
          <dt className="text-muted">Publisher verification</dt>
          <dd className="text-ink">
            {status.publisher.state === 'signed_trusted' ? 'Verified: code-signed with a trusted certificate' : status.publisher.state === 'unsigned' ? 'Not verified: this build is not code-signed, so Windows cannot confirm the publisher' : status.publisher.state === 'unknown' ? 'Could not be determined' : `Problem: ${status.publisher.state.replace('_', ' ')}`}
          </dd>
        </dl>
      </Card>

      <Modal
        open={confirmInstall}
        onClose={() => updBusy !== 'install' && setConfirmInstall(false)}
        title={`Install SENTRIX ${upd?.version ?? ''}?`}
        footer={
          <>
            <Button disabled={updBusy === 'install'} onClick={() => setConfirmInstall(false)}>Not now</Button>
            <Button variant="primary" busy={updBusy === 'install'} onClick={installUpdate}>Download, verify and install</Button>
          </>
        }
      >
        SENTRIX downloads the update, verifies its signature, installs it and restarts. Real-time protection pauses briefly during the restart. If the signature check fails, nothing is installed.
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
        This removes the list of past scans and reports from this computer. It does not delete any files.
      </Modal>
    </div>
  );
}

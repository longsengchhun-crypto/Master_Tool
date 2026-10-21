import { useCallback, useEffect, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import { LogOut, RefreshCw } from 'lucide-react';
import { api, errText } from '../lib/api';
import { useApp } from '../lib/app';
import { ago, when } from '../lib/format';
import type { AccountStatus } from '../lib/types';
import { Button, Card, Modal, Notice, Pill } from '../components/ui';

const LICENSE_TEXT: Record<string, { tone: 'ok' | 'warn' | 'danger' | 'muted'; label: string; body: string }> = {
  valid: { tone: 'ok', label: 'Valid', body: 'Your license is active.' },
  expired: { tone: 'danger', label: 'Expired', body: 'Your organization\'s license has expired. SENTRIX keeps scanning on this device, but management features may stop until it is renewed.' },
  revoked: { tone: 'danger', label: 'Revoked', body: 'Your organization revoked this license. SENTRIX keeps scanning on this device. Protection is never switched off because of a license problem.' },
  suspended: { tone: 'warn', label: 'Suspended', body: 'This license is suspended. Contact your administrator.' },
  none: { tone: 'warn', label: 'No license assigned', body: 'No license seat is linked to this device.' },
};

export function Account() {
  const { refresh, toast } = useApp();
  const [acct, setAcct] = useState<AccountStatus | null>(null);
  const [url, setUrl] = useState('');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmLeave, setConfirmLeave] = useState(false);

  const load = useCallback(async () => setAcct(await api.accountStatus()), []);
  useEffect(() => {
    void load();
    const un = listen('account-changed', () => void load());
    return () => {
      void un.then((f) => f());
    };
  }, [load]);

  if (!acct) return <div className="text-muted">Loading…</div>;

  const enroll = async () => {
    setBusy('enroll');
    setError(null);
    try {
      setAcct(await api.enroll(url, code));
      setCode('');
      toast('ok', 'This device is now managed by your organization.');
      await refresh();
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(null);
    }
  };

  const sync = async () => {
    setBusy('sync');
    try {
      setAcct(await api.syncNow());
      await refresh();
    } catch (e) {
      toast('danger', errText(e));
      await load();
    } finally {
      setBusy(null);
    }
  };

  const leave = async () => {
    setBusy('leave');
    try {
      const notified = await api.unenroll();
      setConfirmLeave(false);
      toast(notified ? 'ok' : 'warn', notified ? 'You left management. Your organization was notified.' : 'You left management on this device. Your organization could not be reached; an administrator can remove the seat from the console.');
      await load();
      await refresh();
    } catch (e) {
      toast('danger', errText(e));
    } finally {
      setBusy(null);
    }
  };

  const lic = acct.license ? (LICENSE_TEXT[acct.license.state] ?? LICENSE_TEXT.none) : null;

  return (
    <div className="space-y-4">
      {!acct.enrolled ? (
        <>
          <Card className="p-5">
            <div className="flex items-start gap-4">
              
              <div>
                <h2 className="text-sm font-semibold text-ink">This device is not managed</h2>
                <p className="mt-1 text-sm text-muted">Only needed if your IT administrator gave you an enrollment code. Nothing is shared until you enroll.</p>
              </div>
            </div>
            <div className="mt-6 grid gap-4 sm:grid-cols-2">
              <label className="block text-sm">
                <span className="font-medium text-ink">Console address</span>
                <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://console.yourcompany.com" className="mt-2 w-full rounded border border-line bg-solid px-3 py-2.5 text-ink placeholder:text-faint" autoComplete="off" spellCheck={false} />
              </label>
              <label className="block text-sm">
                <span className="font-medium text-ink">Enrollment code</span>
                <input value={code} onChange={(e) => setCode(e.target.value.toUpperCase())} placeholder="SX-XXXX-XXXX-XXXX-XXXX" className="mt-2 w-full rounded border border-line bg-solid px-3 py-2.5 font-mono text-ink placeholder:text-faint" autoComplete="off" spellCheck={false} />
              </label>
            </div>
            {error && (
              <div className="mt-4">
                <Notice tone="danger">{error}</Notice>
              </div>
            )}
            <div className="mt-5">
              <Button variant="primary" busy={busy === 'enroll'} disabled={!url || code.length < 16} onClick={enroll}>
                Enroll this device
              </Button>
            </div>
          </Card>
          <Disclosure />
        </>
      ) : (
        <>
          <Card className="p-5">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <div className="text-sm text-muted">Managed by</div>
                <h2 className="mt-0.5 text-2xl font-semibold tracking-tight text-ink">{acct.orgName}</h2>
                <p className="mt-1 text-sm text-muted">Enrolled {acct.enrolledAt ? when(acct.enrolledAt) : ''} · {acct.portalUrl}</p>
              </div>
              <div className="flex gap-3">
                <Button busy={busy === 'sync'} onClick={sync}>
                  <RefreshCw className="size-4" /> Check in now
                </Button>
                <Button variant="danger" onClick={() => setConfirmLeave(true)}>
                  <LogOut className="size-4" /> Leave management
                </Button>
              </div>
            </div>
            <dl className="mt-6 grid gap-x-8 gap-y-3 text-sm sm:grid-cols-2">
              <div className="flex justify-between"><dt className="text-muted">Last check-in</dt><dd className="text-ink">{ago(acct.lastSyncAt)}</dd></div>
              <div className="flex justify-between"><dt className="text-muted">Device ID</dt><dd className="font-mono text-xs text-ink">{acct.deviceId?.slice(0, 8)}…</dd></div>
            </dl>
            {acct.lastError && (
              <div className="mt-4">
                <Notice tone="warn" title="The last check-in failed">{acct.lastError}</Notice>
              </div>
            )}
          </Card>

          <Card className="p-5">
            <div className="flex items-start gap-4">
              
              <div className="min-w-0 flex-1">
                <div className="flex items-center justify-between gap-3">
                  <h2 className="text-sm font-semibold text-ink">License</h2>
                  {lic && <Pill tone={lic.tone}>{lic.label}</Pill>}
                </div>
                <p className="mt-1 text-sm text-muted">{lic?.body ?? 'License status has not been reported yet.'}</p>
                {acct.license?.plan && <p className="mt-2 text-sm text-ink">Plan: {acct.license.plan}{acct.license.expiresAt ? ` · renews or expires ${when(acct.license.expiresAt)}` : ' · no expiry'}</p>}
              </div>
            </div>
          </Card>

          {acct.update && (
            <Notice tone="info" title={`SENTRIX ${acct.update.version} is available`}>
              Your organization has released a newer version. Install it from Settings, under Application updates; its signature is verified first.
            </Notice>
          )}
          <Disclosure enrolled />
        </>
      )}

      <Modal
        open={confirmLeave}
        onClose={() => setConfirmLeave(false)}
        title="Leave management?"
        footer={
          <>
            <Button onClick={() => setConfirmLeave(false)}>Stay enrolled</Button>
            <Button variant="danger" busy={busy === 'leave'} onClick={leave}>Leave management</Button>
          </>
        }
      >
        <p>Your organization stops receiving information from this device and can no longer change its settings. Your current settings stay as they are, and you can change them yourself again. Scanning and protection keep working.</p>
        <p className="mt-2">Your organization may require management for company-owned devices. Leaving is your choice and works even if you are offline.</p>
      </Modal>
    </div>
  );
}

function Disclosure({ enrolled }: { enrolled?: boolean }) {
  return (
    <Card className="p-5">
      <h2 className="text-sm font-semibold text-ink">{enrolled ? 'What your organization can do' : 'If you enroll, this is exactly what happens'}</h2>
      <div className="mt-4 grid gap-6 md:grid-cols-2">
        <div>
          <h3 className="text-sm font-medium text-ink">They can see</h3>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-muted">
            <li>This computer's name, Windows version and SENTRIX version.</li>
            <li>Whether protection is running, and how old your signatures are.</li>
            <li>When the device last checked in.</li>
            <li>Only if you turn on health reporting in Settings: scan counts, and for each suspicious or malicious finding a file hash and verdict. File names only if their policy allows it.</li>
          </ul>
        </div>
        <div>
          <h3 className="text-sm font-medium text-ink">They can ask this device to</h3>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-muted">
            <li>Run a quick scan of your protected folders.</li>
            <li>Update malware signatures.</li>
            <li>Apply protection settings (real-time folders, automatic quarantine, scan limits).</li>
          </ul>
          <p className="mt-2 text-sm text-muted">You see a notification each time. That is the complete list: there is no remote shell, no hidden control and no way to read your files or run other programs.</p>
        </div>
      </div>
    </Card>
  );
}

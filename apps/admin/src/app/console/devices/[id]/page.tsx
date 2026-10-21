'use client';

import { use, useState } from 'react';
import { RefreshCw, ScanSearch, ShieldOff } from 'lucide-react';
import { can } from '@/lib/rbac';
import { Badge, Button, Card, Modal, Notice, PageHeader, Table } from '@/components/ui';
import { useConsole } from '../../provider';
import { fmtDate, useData } from '../../use-data';
import { ProtectionBadge, type DeviceRow } from '../shared';

interface Detail {
  device: DeviceRow & {
    org_id: string;
    created_at: string;
    queue?: { queued: number; failed: number; stuck: number };
    telegram?: { botConnected: boolean; deliveryFailures24h: number; accountState: string };
    tg_groups?: { registered: number; protected: number; autoDelete: number; scans24h: number; threats24h: number; errors24h: number };
  };
  events: { id: string; kind: string; severity: string; detail: string | null; created_at: string }[];
  sessions: { id: string; kind: string; started_at: string; files_total: number; files_failed: number; complete: boolean }[];
  jobs: { id: string; kind: string; state: string; result: string | null; created_at: string }[];
}

const JOB_LABEL: Record<string, string> = { scan_quick: 'Quick scan', intel_update: 'Signature update', app_update: 'Application update check' };

export default function DevicePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { me, call } = useConsole();
  const { data, error, reload } = useData<Detail>(`/api/admin/devices/${id}`);
  const [confirmRevoke, setConfirmRevoke] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ tone: 'ok' | 'danger'; text: string } | null>(null);

  if (error) return <Notice tone="danger">{error}</Notice>;
  if (!data) return <div className="text-muted">Loading…</div>;
  const d = data.device;
  const manage = can(me.role, 'device:manage') && d.status === 'enrolled';

  const request = async (kind: string) => {
    setBusy(kind);
    setMsg(null);
    try {
      await call(`/api/admin/devices/${id}/jobs`, { method: 'POST', body: { kind } });
      setMsg({ tone: 'ok', text: `${JOB_LABEL[kind]} requested. The device runs it at its next check-in and shows the user a notification.` });
      await reload();
    } catch (e) {
      setMsg({ tone: 'danger', text: e instanceof Error ? e.message : 'Request failed' });
    } finally {
      setBusy(null);
    }
  };

  const revoke = async () => {
    setBusy('revoke');
    try {
      await call(`/api/admin/devices/${id}/revoke`, { method: 'POST' });
      setConfirmRevoke(false);
      await reload();
    } catch (e) {
      setMsg({ tone: 'danger', text: e instanceof Error ? e.message : 'Revoke failed' });
      setConfirmRevoke(false);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title={d.hostname}
        subtitle={`${d.org_name} · ${d.os} ${d.os_version ?? ''} · enrolled ${fmtDate(d.created_at)}`}
        actions={
          <>
            {manage && (
              <>
                <Button busy={busy === 'scan_quick'} onClick={() => request('scan_quick')}><ScanSearch className="size-4" /> Request quick scan</Button>
                <Button busy={busy === 'intel_update'} onClick={() => request('intel_update')}><RefreshCw className="size-4" /> Request signature update</Button>
              </>
            )}
            {can(me.role, 'device:revoke') && d.status === 'enrolled' && (
              <Button variant="danger" onClick={() => setConfirmRevoke(true)}><ShieldOff className="size-4" /> Revoke device</Button>
            )}
          </>
        }
      />
      {msg && <Notice tone={msg.tone}>{msg.text}</Notice>}
      {manage && (
        <Notice tone="info">Remote actions are limited to the fixed set above. They are visible to the device's user, logged here, and cannot run arbitrary commands.</Notice>
      )}

      <div className="grid gap-4 md:grid-cols-3">
        <Card className="p-5"><div className="text-xs text-muted">Protection (reported)</div><div className="mt-2"><ProtectionBadge d={d} /></div>{d.protection?.detail && <p className="mt-2 text-xs text-muted">{d.protection.detail}</p>}</Card>
        <Card className="p-5"><div className="text-xs text-muted">Engine / signatures</div><div className="mt-2 text-sm text-ink">{d.engine_version ?? '—'}</div><div className="text-xs text-muted">Signatures updated {fmtDate(d.intel_updated_at)}</div></Card>
        <Card className="p-5"><div className="text-xs text-muted">App version · last seen</div><div className="mt-2 text-sm text-ink">{d.app_version ?? '—'}</div><div className="text-xs text-muted">{fmtDate(d.last_seen_at)}</div></Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card className="p-5">
          <div className="text-xs text-muted">Scan queue (reported)</div>
          {d.queue && 'queued' in d.queue ? (
            <div className="mt-2 flex flex-wrap gap-2">
              <Badge tone={d.queue.queued > 0 ? 'warn' : 'muted'}>{d.queue.queued} waiting</Badge>
              <Badge tone={d.queue.failed > 0 ? 'danger' : 'muted'}>{d.queue.failed} could not be checked</Badge>
              <Badge tone={d.queue.stuck > 0 ? 'danger' : 'muted'}>{d.queue.stuck} stuck</Badge>
            </div>
          ) : (
            <div className="mt-2 text-sm text-muted">Not reported by this version of the app.</div>
          )}
        </Card>
        <Card className="p-5">
          <div className="text-xs text-muted">Telegram integration (status only)</div>
          {d.telegram && 'botConnected' in d.telegram ? (
            <div className="mt-2 flex flex-wrap gap-2">
              <Badge tone={d.telegram.botConnected ? 'ok' : 'muted'}>{d.telegram.botConnected ? 'Bot connected' : 'No bot'}</Badge>
              <Badge tone={d.telegram.deliveryFailures24h > 0 ? 'warn' : 'muted'}>{d.telegram.deliveryFailures24h} delivery failures (24 h)</Badge>
              <Badge>Account monitoring: {d.telegram.accountState.replace('_', ' ')}</Badge>
            </div>
          ) : (
            <div className="mt-2 text-sm text-muted">Not reported.</div>
          )}
          {d.tg_groups && 'registered' in d.tg_groups && (
            <div className="mt-2 flex flex-wrap gap-2">
              <Badge>{d.tg_groups.registered} groups ({d.tg_groups.protected} protected)</Badge>
              <Badge tone={d.tg_groups.threats24h > 0 ? 'danger' : 'muted'}>{d.tg_groups.threats24h} threats (24 h)</Badge>
              <Badge tone={d.tg_groups.errors24h > 0 ? 'warn' : 'muted'}>{d.tg_groups.errors24h} errors (24 h)</Badge>
            </div>
          )}
          <p className="mt-2 text-xs text-muted">Tokens, chat IDs, message text and file contents are never sent to the console.</p>
        </Card>
      </div>

      <Card className="overflow-hidden">
        <h2 className="px-5 pt-5 text-sm font-semibold text-ink">Remote requests</h2>
        <Table head={['Request', 'State', 'Result', 'Requested']}>
          {data.jobs.map((j) => (
            <tr key={j.id}><td className="px-4 py-3 text-ink">{JOB_LABEL[j.kind] ?? j.kind}</td><td className="px-4 py-3"><Badge tone={j.state === 'succeeded' ? 'ok' : j.state === 'failed' ? 'danger' : 'muted'}>{j.state}</Badge></td><td className="px-4 py-3 text-muted">{j.result ?? '—'}</td><td className="px-4 py-3 text-muted">{fmtDate(j.created_at)}</td></tr>
          ))}
        </Table>
        {!data.jobs.length && <div className="px-5 pb-5 text-sm text-muted">No remote requests yet.</div>}
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="overflow-hidden">
          <h2 className="px-5 pt-5 text-sm font-semibold text-ink">Recent scans</h2>
          <Table head={['Started', 'Kind', 'Files', 'Complete']}>
            {data.sessions.map((s) => (
              <tr key={s.id}><td className="px-4 py-3 text-muted">{fmtDate(s.started_at)}</td><td className="px-4 py-3 text-ink">{s.kind}</td><td className="px-4 py-3 text-muted">{s.files_total}{s.files_failed ? ` (${s.files_failed} unreadable)` : ''}</td><td className="px-4 py-3">{s.complete ? <Badge tone="ok">Yes</Badge> : <Badge tone="warn">Partial</Badge>}</td></tr>
            ))}
          </Table>
          {!data.sessions.length && <div className="px-5 pb-5 text-sm text-muted">No scan sessions reported. Devices only share these if telemetry is enabled.</div>}
        </Card>
        <Card className="overflow-hidden">
          <h2 className="px-5 pt-5 text-sm font-semibold text-ink">Security events</h2>
          <Table head={['When', 'Event', 'Severity']}>
            {data.events.map((e) => (
              <tr key={e.id}><td className="px-4 py-3 text-muted">{fmtDate(e.created_at)}</td><td className="px-4 py-3 text-ink">{e.kind}{e.detail && <div className="text-xs text-muted">{e.detail}</div>}</td><td className="px-4 py-3"><Badge tone={e.severity === 'critical' ? 'danger' : e.severity === 'warning' ? 'warn' : 'muted'}>{e.severity}</Badge></td></tr>
            ))}
          </Table>
          {!data.events.length && <div className="px-5 pb-5 text-sm text-muted">No events reported.</div>}
        </Card>
      </div>

      <Modal open={confirmRevoke} onClose={() => setConfirmRevoke(false)} title="Revoke this device?" footer={<><Button onClick={() => setConfirmRevoke(false)}>Cancel</Button><Button variant="danger" busy={busy === 'revoke'} onClick={revoke}>Revoke device</Button></>}>
        <p>The device loses its management credential immediately, its license seat is freed, and pending requests are cancelled. The software keeps working locally; it just stops being managed. This is logged.</p>
      </Modal>
    </div>
  );
}

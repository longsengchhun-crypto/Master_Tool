'use client';

import { useState } from 'react';
import { Plus } from 'lucide-react';
import { can } from '@/lib/rbac';
import { Badge, Button, Card, Empty, Field, Modal, Notice, PageHeader, Table, inputCls } from '@/components/ui';
import { useConsole } from '../provider';
import { fmtDate, useData } from '../use-data';

interface Lic { id: string; org_id: string; org_name: string; key_hint: string; plan: string; seats: number; seats_used: string; status: string; expires_at: string | null; created_at: string }
interface Org { id: string; name: string }

export default function Licenses() {
  const { me, call } = useConsole();
  const { data, error, loading, reload } = useData<{ licenses: Lic[] }>('/api/admin/licenses');
  const orgs = useData<{ organizations: Org[] }>('/api/admin/orgs');
  const [open, setOpen] = useState(false);
  const [orgId, setOrgId] = useState('');
  const [plan, setPlan] = useState('standard');
  const [seats, setSeats] = useState(5);
  const [days, setDays] = useState(365);
  const [created, setCreated] = useState<string | null>(null);
  const [revoke, setRevoke] = useState<Lic | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const create = async () => {
    setBusy(true);
    setErr(null);
    try {
      const r = await call<{ license: { key: string } }>('/api/admin/licenses', { method: 'POST', body: { orgId, plan, seats, expiresAt: days > 0 ? new Date(Date.now() + days * 86400000).toISOString() : null } });
      setOpen(false);
      setCreated(r.license.key);
      await reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed');
    } finally {
      setBusy(false);
    }
  };

  const doRevoke = async () => {
    if (!revoke) return;
    setBusy(true);
    try {
      await call(`/api/admin/licenses/${revoke.id}/revoke`, { method: 'POST' });
      setRevoke(null);
      await reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed');
      setRevoke(null);
    } finally {
      setBusy(false);
    }
  };

  const manage = can(me.role, 'license:manage');
  return (
    <div>
      <PageHeader title="Licenses" subtitle="A license grants seats to an organization. Revoking one takes effect at each device's next check-in." actions={manage && <Button variant="primary" onClick={() => setOpen(true)}><Plus className="size-4" /> New license</Button>} />
      {(error || err) && <div className="mb-4"><Notice tone="danger">{error ?? err}</Notice></div>}
      <Card className="overflow-hidden">
        {loading ? <Empty>Loading…</Empty> : !data?.licenses.length ? <Empty>No licenses yet.</Empty> : (
          <Table head={['Organization', 'Key', 'Plan', 'Seats', 'Status', 'Expires', '']}>
            {data.licenses.map((l) => (
              <tr key={l.id}>
                <td className="px-4 py-3 font-medium text-ink">{l.org_name}</td>
                <td className="px-4 py-3 font-mono text-xs text-muted">SXLK-…-{l.key_hint}</td>
                <td className="px-4 py-3 text-muted">{l.plan}</td>
                <td className="px-4 py-3 text-muted">{l.seats_used} / {l.seats}</td>
                <td className="px-4 py-3"><Badge tone={l.status === 'active' ? 'ok' : 'danger'}>{l.status}</Badge></td>
                <td className="px-4 py-3 text-muted">{l.expires_at ? fmtDate(l.expires_at) : 'Never'}</td>
                <td className="px-4 py-3 text-right">{manage && l.status === 'active' && <Button variant="danger" onClick={() => setRevoke(l)}>Revoke</Button>}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <Modal open={open} onClose={() => setOpen(false)} title="New license" footer={<><Button onClick={() => setOpen(false)}>Cancel</Button><Button variant="primary" busy={busy} disabled={!orgId} onClick={create}>Create license</Button></>}>
        <div className="space-y-4">
          <Field label="Organization">
            <select className={inputCls} value={orgId} onChange={(e) => setOrgId(e.target.value)}>
              <option value="">Select…</option>
              {orgs.data?.organizations.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
            </select>
          </Field>
          <Field label="Plan"><input className={inputCls} value={plan} onChange={(e) => setPlan(e.target.value)} /></Field>
          <div className="grid grid-cols-2 gap-4">
            <Field label="Seats"><input type="number" min={1} className={inputCls} value={seats} onChange={(e) => setSeats(Number(e.target.value))} /></Field>
            <Field label="Valid for (days)" hint="0 = no expiry"><input type="number" min={0} className={inputCls} value={days} onChange={(e) => setDays(Number(e.target.value))} /></Field>
          </div>
        </div>
      </Modal>

      <Modal open={!!created} onClose={() => setCreated(null)} title="License key" footer={<Button variant="primary" onClick={() => setCreated(null)}>Done</Button>}>
        <p className="mb-3">Copy this key now. It is shown once; only a hash is stored.</p>
        <div className="select-all rounded border border-line bg-surface2 p-4 text-center font-mono text-base tracking-wider text-ink">{created}</div>
      </Modal>

      <Modal open={!!revoke} onClose={() => setRevoke(null)} title="Revoke this license?" footer={<><Button onClick={() => setRevoke(null)}>Cancel</Button><Button variant="danger" busy={busy} onClick={doRevoke}>Revoke license</Button></>}>
        <p>Devices using this license are told it was revoked at their next check-in. This is logged and cannot be undone; issue a new license to restore access.</p>
      </Modal>
    </div>
  );
}

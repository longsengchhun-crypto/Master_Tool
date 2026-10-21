'use client';

import { useState } from 'react';
import { Plus, QrCode } from 'lucide-react';
import { can } from '@/lib/rbac';
import { Button, Card, Empty, Field, Modal, Notice, PageHeader, Table, inputCls } from '@/components/ui';
import { useConsole } from '../provider';
import { fmtDate, useData } from '../use-data';

interface Org { id: string; name: string; created_at: string; devices: string; members: string; active_licenses: string }

export default function Organizations() {
  const { me, call } = useConsole();
  const { data, error, loading, reload } = useData<{ organizations: Org[] }>('/api/admin/orgs');
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState('');
  const [code, setCode] = useState<{ org: string; code: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const create = async () => {
    setBusy(true);
    setErr(null);
    try {
      await call('/api/admin/orgs', { method: 'POST', body: { name } });
      setCreating(false);
      setName('');
      await reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed');
    } finally {
      setBusy(false);
    }
  };

  const enroll = async (o: Org) => {
    setErr(null);
    try {
      const r = await call<{ code: string }>('/api/admin/enrollments', { method: 'POST', body: { orgId: o.id, hoursValid: 24 } });
      setCode({ org: o.name, code: r.code });
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed');
    }
  };

  return (
    <div>
      <PageHeader title="Organizations" actions={can(me.role, 'org:manage') && <Button variant="primary" onClick={() => setCreating(true)}><Plus className="size-4" /> New organization</Button>} />
      {(error || err) && <div className="mb-4"><Notice tone="danger">{error ?? err}</Notice></div>}
      <Card className="overflow-hidden">
        {loading ? <Empty>Loading…</Empty> : !data?.organizations.length ? <Empty>No organizations yet.</Empty> : (
          <Table head={['Organization', 'Devices', 'Members', 'Active licenses', 'Created', '']}>
            {data.organizations.map((o) => (
              <tr key={o.id}>
                <td className="px-4 py-3 font-medium text-ink">{o.name}</td>
                <td className="px-4 py-3 text-muted">{o.devices}</td>
                <td className="px-4 py-3 text-muted">{o.members}</td>
                <td className="px-4 py-3 text-muted">{o.active_licenses}</td>
                <td className="px-4 py-3 text-muted">{fmtDate(o.created_at)}</td>
                <td className="px-4 py-3 text-right">{can(me.role, 'device:manage') && <Button onClick={() => enroll(o)}><QrCode className="size-4" /> Enrollment code</Button>}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <Modal open={creating} onClose={() => setCreating(false)} title="New organization" footer={<><Button onClick={() => setCreating(false)}>Cancel</Button><Button variant="primary" busy={busy} disabled={name.trim().length < 2} onClick={create}>Create</Button></>}>
        <Field label="Name"><input className={inputCls} value={name} onChange={(e) => setName(e.target.value)} autoFocus /></Field>
      </Modal>

      <Modal open={!!code} onClose={() => setCode(null)} title="Enrollment code" footer={<Button variant="primary" onClick={() => setCode(null)}>Done</Button>}>
        {code && (
          <div className="space-y-3">
            <p>One-time code for <span className="font-medium text-ink">{code.org}</span>. Valid for 24 hours and works once. It is shown only now.</p>
            <div className="select-all rounded border border-line bg-surface2 p-4 text-center font-mono text-lg tracking-widest text-ink">{code.code}</div>
            <p>In SENTRIX on the device: Account and License, then Enroll this device. Enrolling uses one license seat.</p>
          </div>
        )}
      </Modal>
    </div>
  );
}

'use client';

import { useState } from 'react';
import { Plus } from 'lucide-react';
import { Badge, Button, Card, Empty, Field, Modal, Notice, PageHeader, Table, inputCls } from '@/components/ui';
import { useConsole } from '../provider';
import { useData } from '../use-data';

interface U { id: string; email: string; name: string; platform_role: string | null; is_active: boolean; mfa_enabled: boolean; memberships: { orgId: string; org: string; role: string }[] }
interface Org { id: string; name: string }

const ROLES = [['super_admin', 'Super Administrator'], ['security_admin', 'Security Administrator'], ['support', 'Support Operator'], ['auditor', 'Read-only Auditor']] as const;

export default function Users() {
  const { me, call } = useConsole();
  const { data, error, loading, reload } = useData<{ users: U[] }>('/api/admin/users');
  const orgs = useData<{ organizations: Org[] }>('/api/admin/orgs');
  const [open, setOpen] = useState(false);
  const [f, setF] = useState({ email: '', name: '', password: '', scope: 'platform', platformRole: 'support', orgId: '', orgRole: 'org_admin' });
  const [confirm, setConfirm] = useState<{ u: U; change: Record<string, unknown>; label: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const create = async () => {
    setBusy(true);
    setErr(null);
    try {
      await call('/api/admin/users', {
        method: 'POST',
        body: { email: f.email, name: f.name, password: f.password, ...(f.scope === 'platform' ? { platformRole: f.platformRole } : { orgId: f.orgId, orgRole: f.orgRole }) },
      });
      setOpen(false);
      setF({ ...f, email: '', name: '', password: '' });
      await reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed');
    } finally {
      setBusy(false);
    }
  };

  const apply = async () => {
    if (!confirm) return;
    setBusy(true);
    setErr(null);
    try {
      await call(`/api/admin/users/${confirm.u.id}`, { method: 'PATCH', body: confirm.change });
      setConfirm(null);
      await reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed');
      setConfirm(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <PageHeader title="Users and roles" subtitle="Every administrator account requires two-step verification. Role changes are logged and take effect immediately." actions={<Button variant="primary" onClick={() => setOpen(true)}><Plus className="size-4" /> New administrator</Button>} />
      {(error || err) && <div className="mb-4"><Notice tone="danger">{err ?? error}</Notice></div>}
      <Card className="overflow-hidden">
        {loading ? <Empty>Loading…</Empty> : (
          <Table head={['User', 'Role', '2-step', 'Status', '']}>
            {data?.users.map((u) => (
              <tr key={u.id}>
                <td className="px-4 py-3"><div className="font-medium text-ink">{u.name}</div><div className="text-xs text-muted">{u.email}</div></td>
                <td className="px-4 py-3 text-muted">{u.platform_role ? ROLES.find((r) => r[0] === u.platform_role)?.[1] : u.memberships.map((m) => `${m.role === 'org_admin' ? 'Org admin' : 'Member'} · ${m.org}`).join(', ') || '—'}</td>
                <td className="px-4 py-3">{u.mfa_enabled ? <Badge tone="ok">On</Badge> : <Badge tone="warn">Not set up</Badge>}</td>
                <td className="px-4 py-3">{u.is_active ? <Badge tone="ok">Active</Badge> : <Badge>Deactivated</Badge>}</td>
                <td className="px-4 py-3">
                  {u.email !== me.email && (
                    <div className="flex justify-end gap-2">
                      {u.mfa_enabled && <Button onClick={() => setConfirm({ u, change: { resetMfa: true }, label: 'Reset two-step verification' })}>Reset 2-step</Button>}
                      {u.is_active ? <Button variant="danger" onClick={() => setConfirm({ u, change: { isActive: false }, label: 'Deactivate account' })}>Deactivate</Button> : <Button onClick={() => setConfirm({ u, change: { isActive: true }, label: 'Reactivate account' })}>Reactivate</Button>}
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <Modal open={open} onClose={() => setOpen(false)} title="New administrator" footer={<><Button onClick={() => setOpen(false)}>Cancel</Button><Button variant="primary" busy={busy} disabled={!f.email || !f.name || f.password.length < 12 || (f.scope === 'org' && !f.orgId)} onClick={create}>Create account</Button></>}>
        <div className="space-y-3">
          <Field label="Name"><input className={inputCls} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
          <Field label="Email"><input type="email" className={inputCls} value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></Field>
          <Field label="Temporary password" hint="At least 12 characters. They set up two-step verification at first sign-in."><input type="password" autoComplete="new-password" className={inputCls} value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></Field>
          <Field label="Access">
            <select className={inputCls} value={f.scope} onChange={(e) => setF({ ...f, scope: e.target.value })}><option value="platform">Platform role (all organizations)</option><option value="org">Organization administrator (one organization)</option></select>
          </Field>
          {f.scope === 'platform' ? (
            <Field label="Role"><select className={inputCls} value={f.platformRole} onChange={(e) => setF({ ...f, platformRole: e.target.value })}>{ROLES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></Field>
          ) : (
            <Field label="Organization"><select className={inputCls} value={f.orgId} onChange={(e) => setF({ ...f, orgId: e.target.value })}><option value="">Select…</option>{orgs.data?.organizations.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}</select></Field>
          )}
        </div>
      </Modal>

      <Modal open={!!confirm} onClose={() => setConfirm(null)} title={confirm?.label ?? ''} footer={<><Button onClick={() => setConfirm(null)}>Cancel</Button><Button variant="danger" busy={busy} onClick={apply}>Confirm</Button></>}>
        <p>{confirm?.u.email}: this signs them out everywhere{confirm?.change.isActive === true ? '' : ' and is logged'}.</p>
      </Modal>
    </div>
  );
}

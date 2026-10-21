'use client';

import { useState } from 'react';
import { can } from '@/lib/rbac';
import { Badge, Button, Card, Empty, Modal, Notice, PageHeader, Table, inputCls } from '@/components/ui';
import { useConsole } from '../provider';
import { fmtDate, useData } from '../use-data';

interface Pol { id: string; org_id: string; org_name: string; name: string; version: number; config: Record<string, unknown>; updated_at: string }
interface Org { id: string; name: string }

const DEFAULT = {
  realtimeMonitoring: true,
  monitoredFolders: ['downloads'],
  autoQuarantine: 'malicious_only',
  maxFileSizeMb: 512,
  archiveMaxDepth: 3,
  allowHashReputationLookup: false,
  allowFileNameTelemetry: false,
  allowUserRestoreSuspicious: true,
  maxIntelAgeHours: 48,
  telegramBotAllowed: true,
  telegramAccountAllowed: true,
  telegramGroupsAllowed: true,
};

export default function Policies() {
  const { me, call } = useConsole();
  const { data, error, loading, reload } = useData<{ policies: Pol[] }>('/api/admin/policies');
  const orgs = useData<{ organizations: Org[] }>('/api/admin/orgs');
  const [editing, setEditing] = useState<{ orgId: string; json: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const save = async () => {
    if (!editing) return;
    setBusy(true);
    setErr(null);
    try {
      await call('/api/admin/policies', { method: 'PUT', body: { orgId: editing.orgId, name: 'default', config: JSON.parse(editing.json) } });
      setEditing(null);
      await reload();
    } catch (e) {
      setErr(e instanceof SyntaxError ? 'That is not valid JSON.' : e instanceof Error ? e.message : 'Failed');
    } finally {
      setBusy(false);
    }
  };

  const write = can(me.role, 'policy:write');
  return (
    <div>
      <PageHeader title="Policies" subtitle="A policy is a closed set of settings pushed to enrolled devices at their next check-in. It cannot carry commands, scripts or paths, and unknown settings are rejected." />
      {(error || err) && <div className="mb-4"><Notice tone="danger">{err ?? error}</Notice></div>}
      <Card className="overflow-hidden">
        {loading ? <Empty>Loading…</Empty> : (
          <Table head={['Organization', 'Version', 'Auto-quarantine', 'Real-time', 'Updated', '']}>
            {orgs.data?.organizations.map((o) => {
              const p = data?.policies.find((x) => x.org_id === o.id);
              return (
                <tr key={o.id}>
                  <td className="px-4 py-3 font-medium text-ink">{o.name}</td>
                  <td className="px-4 py-3 text-muted">{p ? `v${p.version}` : <Badge>built-in defaults</Badge>}</td>
                  <td className="px-4 py-3 text-muted">{String(p?.config.autoQuarantine ?? 'malicious_only')}</td>
                  <td className="px-4 py-3 text-muted">{p?.config.realtimeMonitoring === false ? 'Off' : 'On'}</td>
                  <td className="px-4 py-3 text-muted">{p ? fmtDate(p.updated_at) : '—'}</td>
                  <td className="px-4 py-3 text-right">{write && <Button onClick={() => setEditing({ orgId: o.id, json: JSON.stringify(p?.config ?? DEFAULT, null, 2) })}>Edit</Button>}</td>
                </tr>
              );
            })}
          </Table>
        )}
        {!loading && !orgs.data?.organizations.length && <Empty>No organizations yet.</Empty>}
      </Card>

      <Modal open={!!editing} onClose={() => setEditing(null)} title="Edit policy" footer={<><Button onClick={() => setEditing(null)}>Cancel</Button><Button variant="primary" busy={busy} onClick={save}>Save policy</Button></>}>
        <p className="mb-3">Changes apply to enrolled devices at their next check-in and are written to the audit log, including the full new policy.</p>
        <textarea className={`${inputCls} h-72 font-mono text-xs`} spellCheck={false} value={editing?.json ?? ''} onChange={(e) => editing && setEditing({ ...editing, json: e.target.value })} aria-label="Policy JSON" />
        {err && <p role="alert" className="mt-2 text-danger">{err}</p>}
      </Modal>
    </div>
  );
}

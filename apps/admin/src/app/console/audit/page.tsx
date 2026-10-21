'use client';

import { useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { Badge, Button, Card, Empty, Notice, PageHeader, Table } from '@/components/ui';
import { useConsole } from '../provider';
import { fmtDate, useData } from '../use-data';

interface Ev { seq: string; at: string; actor_email: string | null; action: string; target: string | null; detail: Record<string, unknown>; ip: string | null }

export default function Audit() {
  const { call } = useConsole();
  const { data, error, loading } = useData<{ events: Ev[] }>('/api/admin/audit?limit=200');
  const [verify, setVerify] = useState<null | { intact: boolean; firstBrokenSeq?: number | null }>(null);
  const [busy, setBusy] = useState(false);

  return (
    <div>
      <PageHeader
        title="Audit log"
        subtitle="Append-only and hash-chained: each entry commits to the one before it, so edits or deletions are detectable."
        actions={<Button busy={busy} onClick={async () => { setBusy(true); try { setVerify(await call('/api/admin/audit?verify=1')); } finally { setBusy(false); } }}><ShieldCheck className="size-4" /> Verify integrity</Button>}
      />
      {error && <div className="mb-4"><Notice tone="danger">{error}</Notice></div>}
      {verify && <div className="mb-4">{verify.intact ? <Notice tone="ok">The audit chain is intact.</Notice> : <Notice tone="danger" title="The audit chain is broken">{verify.firstBrokenSeq ? `First inconsistent entry: #${verify.firstBrokenSeq}.` : 'An entry was altered or removed.'} Treat this as a security incident.</Notice>}</div>}
      <Card className="overflow-hidden">
        {loading ? <Empty>Loading…</Empty> : !data?.events.length ? <Empty>No audit events.</Empty> : (
          <Table head={['#', 'When', 'Actor', 'Action', 'Target', 'IP']}>
            {data.events.map((e) => (
              <tr key={e.seq} className="align-top">
                <td className="px-4 py-3 tabular-nums text-faint">{e.seq}</td>
                <td className="whitespace-nowrap px-4 py-3 text-muted">{fmtDate(e.at)}</td>
                <td className="px-4 py-3 text-ink">{e.actor_email ?? 'system'}</td>
                <td className="px-4 py-3"><Badge tone={e.action.includes('failed') || e.action.includes('revoke') || e.action.includes('denied') ? 'warn' : 'muted'}>{e.action}</Badge>{Object.keys(e.detail ?? {}).length > 0 && <details className="mt-1 text-xs text-muted"><summary className="cursor-pointer">details</summary><pre className="mt-1 max-w-md overflow-auto whitespace-pre-wrap">{JSON.stringify(e.detail, null, 2)}</pre></details>}</td>
                <td className="max-w-[160px] truncate px-4 py-3 font-mono text-xs text-muted" title={e.target ?? ''}>{e.target ?? '—'}</td>
                <td className="px-4 py-3 text-muted">{e.ip ?? '—'}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}

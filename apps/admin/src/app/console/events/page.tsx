'use client';

import { Badge, Card, Empty, Notice, PageHeader, Table } from '@/components/ui';
import { fmtDate, useData } from '../use-data';

interface Data {
  events: { id: string; kind: string; severity: string; detail: string | null; created_at: string; hostname: string; org_name: string }[];
  findings: { id: string; sha256: string; file_name: string | null; verdict: string; source: string; engine_version: string | null; found_at: string; hostname: string; org_name: string }[];
}

export default function Events() {
  const { data, error, loading } = useData<Data>('/api/admin/events');
  return (
    <div className="space-y-8">
      <PageHeader title="Security events" subtitle="Findings carry a file hash and verdict, never file contents. File names appear only where the organization's policy allows sending them." />
      {error && <Notice tone="danger">{error}</Notice>}
      <section>
        <h2 className="mb-3 text-sm font-semibold text-ink">Findings</h2>
        <Card className="overflow-hidden">
          {loading ? <Empty>Loading…</Empty> : !data?.findings.length ? <Empty>No suspicious or malicious findings have been reported.</Empty> : (
            <Table head={['When', 'Device', 'Verdict', 'SHA-256', 'Source']}>
              {data.findings.map((f) => (
                <tr key={f.id}>
                  <td className="whitespace-nowrap px-4 py-3 text-muted">{fmtDate(f.found_at)}</td>
                  <td className="px-4 py-3"><div className="text-ink">{f.hostname}</div><div className="text-xs text-muted">{f.org_name}</div></td>
                  <td className="px-4 py-3"><Badge tone={f.verdict === 'MALICIOUS' ? 'danger' : f.verdict === 'SUSPICIOUS' ? 'warn' : 'muted'}>{f.verdict.replace(/_/g, ' ').toLowerCase()}</Badge>{f.file_name && <div className="mt-1 text-xs text-muted">{f.file_name}</div>}</td>
                  <td className="px-4 py-3 font-mono text-xs text-muted" title={f.sha256}>{f.sha256.slice(0, 16)}…</td>
                  <td className="px-4 py-3 text-muted">{f.source}{f.engine_version ? ` (${f.engine_version})` : ''}</td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
      </section>
      <section>
        <h2 className="mb-3 text-sm font-semibold text-ink">Device events</h2>
        <Card className="overflow-hidden">
          {loading ? <Empty>Loading…</Empty> : !data?.events.length ? <Empty>No device events.</Empty> : (
            <Table head={['When', 'Device', 'Event', 'Severity']}>
              {data.events.map((e) => (
                <tr key={e.id}>
                  <td className="whitespace-nowrap px-4 py-3 text-muted">{fmtDate(e.created_at)}</td>
                  <td className="px-4 py-3"><div className="text-ink">{e.hostname}</div><div className="text-xs text-muted">{e.org_name}</div></td>
                  <td className="px-4 py-3 text-ink">{e.kind}{e.detail && <div className="text-xs text-muted">{e.detail}</div>}</td>
                  <td className="px-4 py-3"><Badge tone={e.severity === 'critical' ? 'danger' : e.severity === 'warning' ? 'warn' : 'muted'}>{e.severity}</Badge></td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
      </section>
    </div>
  );
}

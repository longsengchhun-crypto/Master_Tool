'use client';

import Link from 'next/link';
import { Badge, Card, Empty, Notice, PageHeader, Table } from '@/components/ui';
import { useData, ago } from '../use-data';
import { ProtectionBadge, type DeviceRow } from './shared';

export default function Devices() {
  const { data, error, loading } = useData<{ devices: DeviceRow[] }>('/api/admin/devices');
  return (
    <div>
      <PageHeader title="Devices" subtitle="Reported state is what each device says about itself. A silent device is flagged, not assumed healthy." />
      {error && <Notice tone="danger">{error}</Notice>}
      <Card className="overflow-hidden">
        {loading ? (
          <Empty>Loading…</Empty>
        ) : !data?.devices.length ? (
          <Empty>No devices are enrolled yet. Create an enrollment code under Organizations.</Empty>
        ) : (
          <Table head={['Device', 'Organization', 'Protection', 'Signatures', 'Version', 'Last seen']}>
            {data.devices.map((d) => (
              <tr key={d.id} className="hover:bg-surface2/60">
                <td className="px-4 py-3">
                  <Link href={`/console/devices/${d.id}`} className="font-medium text-ink hover:text-accent">{d.hostname}</Link>
                  <div className="text-xs text-muted">{d.os} {d.os_version ?? ''}</div>
                </td>
                <td className="px-4 py-3 text-muted">{d.org_name}</td>
                <td className="px-4 py-3"><ProtectionBadge d={d} /></td>
                <td className="px-4 py-3">{d.status === 'enrolled' ? (d.intel_outdated ? <Badge tone="warn">Outdated</Badge> : <Badge tone="ok">{ago(d.intel_updated_at)}</Badge>) : '—'}</td>
                <td className="px-4 py-3 text-muted">{d.app_version ?? '—'}</td>
                <td className="px-4 py-3">{d.stale && d.status === 'enrolled' ? <Badge tone="warn">{ago(d.last_seen_at)}</Badge> : <span className="text-muted">{ago(d.last_seen_at)}</span>}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}

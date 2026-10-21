import { Badge } from '@/components/ui';

export interface DeviceRow {
  id: string;
  org_name: string;
  hostname: string;
  os: string;
  os_version: string | null;
  app_version: string | null;
  engine_version: string | null;
  intel_updated_at: string | null;
  protection: { engineState?: string; realtimeState?: string; detail?: string };
  status: 'enrolled' | 'revoked';
  last_seen_at: string | null;
  stale: boolean;
  intel_outdated: boolean;
}

/** Shows exactly what the device reported. No report is shown as "No report yet", never as healthy. */
export function ProtectionBadge({ d }: { d: Pick<DeviceRow, 'protection' | 'status'> }) {
  if (d.status === 'revoked') return <Badge>Revoked</Badge>;
  const e = d.protection?.engineState;
  const r = d.protection?.realtimeState;
  if (!e) return <Badge tone="muted">No report yet</Badge>;
  if (e !== 'running') return <Badge tone="danger">Engine {e}</Badge>;
  if (r === 'error') return <Badge tone="danger">Real-time error</Badge>;
  if (r === 'paused') return <Badge tone="warn">Real-time paused</Badge>;
  if (r === 'unsupported') return <Badge tone="warn">Real-time unsupported</Badge>;
  return <Badge tone="ok">Engine running</Badge>;
}

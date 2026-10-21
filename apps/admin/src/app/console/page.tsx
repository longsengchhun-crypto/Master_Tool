'use client';

import { Card, Notice, PageHeader, Badge } from '@/components/ui';
import { useData, ago } from './use-data';

interface Overview {
  operational: {
    fleet: Record<string, string>;
    versions: { app_version: string | null; n: string }[];
    scans: Record<string, string>;
  };
  security: { verdicts_30d: { verdict: string; n: string }[]; quarantine: Record<string, string> };
  releases: { version: string; platform: string; channel: string; status: string; rollout_pct: number; code_signed: boolean; published_at: string | null }[];
  intel: { engine: string; version: string; published_at: string }[];
  note: string;
}

function Metric({ label, value, tone, hint }: { label: string; value: string | number; tone?: 'danger' | 'warn'; hint?: string }) {
  const n = Number(value);
  return (
    <Card className="p-5">
      <div className={`text-3xl font-semibold tabular-nums tracking-tight ${tone && n > 0 ? (tone === 'danger' ? 'text-danger' : 'text-warn') : 'text-ink'}`}>{value}</div>
      <div className="mt-1 text-sm text-ink">{label}</div>
      {hint && <div className="mt-0.5 text-xs text-muted">{hint}</div>}
    </Card>
  );
}

export default function Overview() {
  const { data, error, loading } = useData<Overview>('/api/admin/overview');
  if (error) return <Notice tone="danger" title="Could not load the overview">{error}</Notice>;
  if (loading || !data) return <div className="text-muted">Loading…</div>;
  const f = data.operational.fleet;
  const s = data.operational.scans;
  const verdict = (v: string) => data.security.verdicts_30d.find((x) => x.verdict === v)?.n ?? '0';
  const failRate = Number(s.files_30d) > 0 ? ((Number(s.files_failed_30d) / Number(s.files_30d)) * 100).toFixed(1) : '0.0';

  return (
    <div className="space-y-10">
      <PageHeader title="Overview" subtitle="Operational health tells you whether protection is actually running. Detection activity is shown separately because a high or low count says nothing about effectiveness." />

      <section aria-labelledby="ops">
        <h2 id="ops" className="mb-3 text-sm font-semibold uppercase tracking-wider text-muted">Operational health</h2>
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Metric label="Enrolled devices" value={f.enrolled} hint={`${f.revoked} revoked`} />
          <Metric label="Seen in last 24 h" value={f.seen_24h} />
          <Metric label="Engine not running" value={f.engine_not_running} tone="danger" hint="Reported protection state" />
          <Metric label="Outdated signatures (>72 h)" value={f.outdated_intel} tone="warn" />
          <Metric label="Silent for 7+ days" value={f.stale} tone="warn" />
          <Metric label="Real-time protection errors" value={f.realtime_error} tone="danger" />
          <Metric label="Scan sessions (30 d)" value={s.sessions_30d} hint={`${s.incomplete_30d} incomplete`} />
          <Metric label="Files unreadable (30 d)" value={`${failRate}%`} hint={`${s.files_failed_30d} of ${s.files_30d} files`} />
          <Metric label="Devices with unchecked files" value={f.devices_with_unchecked_files} tone="danger" hint="Scans that kept failing; files are not known safe" />
          <Metric label="Devices with stuck scans" value={f.devices_with_stuck_scans} tone="danger" />
          <Metric label="Devices with a scan backlog" value={f.devices_with_backlog} tone="warn" />
          <Metric label="Telegram bots connected" value={f.telegram_bots_connected} hint="Counts only: never tokens or chats" />
          <Metric label="Telegram delivery failures (24 h)" value={f.telegram_delivery_failures} tone="warn" hint="Devices with undelivered reports" />
        </div>
        <Card className="mt-4 p-5">
          <h3 className="text-sm font-semibold text-ink">Installed versions</h3>
          <div className="mt-3 flex flex-wrap gap-2">
            {data.operational.versions.length === 0 && <span className="text-sm text-muted">No devices have reported yet.</span>}
            {data.operational.versions.map((v) => (
              <Badge key={v.app_version ?? 'unknown'}>{v.app_version ?? 'unknown'} · {v.n}</Badge>
            ))}
          </div>
        </Card>
      </section>

      <section aria-labelledby="sec">
        <h2 id="sec" className="mb-3 text-sm font-semibold uppercase tracking-wider text-muted">Detection activity (30 days)</h2>
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Metric label="Malicious findings" value={verdict('MALICIOUS')} />
          <Metric label="Suspicious findings" value={verdict('SUSPICIOUS')} />
          <Metric label="Unable to verify" value={verdict('UNABLE_TO_VERIFY')} />
          <Metric label="In quarantine now" value={data.security.quarantine.quarantined} hint={`${data.security.quarantine.restored} restored, ${data.security.quarantine.deleted} deleted`} />
        </div>
        <div className="mt-3"><Notice tone="info">{data.note}</Notice></div>
      </section>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="p-5">
          <h3 className="text-sm font-semibold text-ink">Signature intelligence</h3>
          <ul className="mt-3 divide-y divide-line text-sm">
            {data.intel.length === 0 && <li className="py-2 text-muted">No versions reported yet.</li>}
            {data.intel.map((i) => (
              <li key={`${i.engine}-${i.version}`} className="flex justify-between py-2"><span className="text-ink">{i.engine} {i.version}</span><span className="text-muted">first seen {ago(i.published_at)}</span></li>
            ))}
          </ul>
        </Card>
        {data.releases.length > 0 && (
          <Card className="p-5">
            <h3 className="text-sm font-semibold text-ink">Recent releases</h3>
            <ul className="mt-3 divide-y divide-line text-sm">
              {data.releases.map((r) => (
                <li key={`${r.version}-${r.platform}-${r.channel}`} className="flex items-center justify-between py-2">
                  <span className="text-ink">{r.version} <span className="text-muted">{r.platform}</span></span>
                  <span className="flex gap-2"><Badge tone={r.status === 'published' ? 'ok' : r.status === 'staged' ? 'info' : 'muted'}>{r.status}{r.status === 'staged' ? ` ${r.rollout_pct}%` : ''}</Badge>{!r.code_signed && <Badge tone="warn">unsigned</Badge>}</span>
                </li>
              ))}
            </ul>
          </Card>
        )}
      </div>
    </div>
  );
}

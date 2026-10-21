'use client';

import { Badge, Card, Notice, PageHeader, Row, Rows, Section } from '@/components/ui';
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
  const n = parseFloat(String(value));
  return (
    <Row label={label} hint={hint} tone={tone && n > 0 ? tone : undefined}>
      {value}
    </Row>
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
    <div className="space-y-6">
      <PageHeader title="Overview" subtitle="Operational health says whether protection is running. Detection counts say nothing about effectiveness, so they are shown separately." />

      <section aria-labelledby="ops" className="space-y-4">
        <h2 id="ops" className="text-sm font-semibold text-ink">Operational health</h2>
        <div className="grid gap-4 lg:grid-cols-3">
          <Section title="Fleet">
            <Rows>
              <Metric label="Enrolled devices" value={f.enrolled} hint={`${f.revoked} revoked`} />
              <Metric label="Seen in last 24 h" value={f.seen_24h} />
              <Metric label="Silent for 7+ days" value={f.stale} tone="warn" />
              <Metric label="Engine not running" value={f.engine_not_running} tone="danger" hint="Reported protection state" />
              <Metric label="Outdated signatures (over 72 h)" value={f.outdated_intel} tone="warn" />
              <Metric label="Real-time protection errors" value={f.realtime_error} tone="danger" />
            </Rows>
          </Section>
          <Section title="Scanning (30 days)">
            <Rows>
              <Metric label="Scan sessions" value={s.sessions_30d} hint={`${s.incomplete_30d} incomplete`} />
              <Metric label="Files unreadable" value={`${failRate}%`} hint={`${s.files_failed_30d} of ${s.files_30d} files`} />
              <Metric label="Devices with unchecked files" value={f.devices_with_unchecked_files} tone="danger" hint="Scans that kept failing; files are not known safe" />
              <Metric label="Devices with stuck scans" value={f.devices_with_stuck_scans} tone="danger" />
              <Metric label="Devices with a scan backlog" value={f.devices_with_backlog} tone="warn" />
            </Rows>
          </Section>
          <Section title="Telegram">
            <Rows>
              <Metric label="Bots connected" value={f.telegram_bots_connected} hint="Counts only: never tokens or chats" />
              <Metric label="Devices with delivery failures (24 h)" value={f.telegram_delivery_failures} tone="warn" hint="Devices with undelivered reports" />
            </Rows>
          </Section>
        </div>
        <Card className="p-4">
          <h3 className="text-sm font-semibold text-ink">Installed versions</h3>
          <div className="mt-2 flex flex-wrap gap-2">
            {data.operational.versions.length === 0 && <span className="text-sm text-muted">No devices have reported yet.</span>}
            {data.operational.versions.map((v) => (
              <Badge key={v.app_version ?? 'unknown'}>{v.app_version ?? 'unknown'} · {v.n}</Badge>
            ))}
          </div>
        </Card>
      </section>

      <section aria-labelledby="sec" className="space-y-4">
        <h2 id="sec" className="text-sm font-semibold text-ink">Detection activity (30 days)</h2>
        <Section title="Findings">
          <div className="grid md:grid-cols-2 md:divide-x md:divide-line">
            <Rows>
              <Metric label="Malicious findings" value={verdict('MALICIOUS')} />
              <Metric label="Suspicious findings" value={verdict('SUSPICIOUS')} />
            </Rows>
            <Rows>
              <Metric label="Unable to verify" value={verdict('UNABLE_TO_VERIFY')} />
              <Metric label="In quarantine now" value={data.security.quarantine.quarantined} hint={`${data.security.quarantine.restored} restored, ${data.security.quarantine.deleted} deleted`} />
            </Rows>
          </div>
        </Section>
        <Notice tone="info">{data.note}</Notice>
      </section>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-4">
          <h3 className="text-sm font-semibold text-ink">Signature intelligence</h3>
          <ul className="mt-3 divide-y divide-line text-sm">
            {data.intel.length === 0 && <li className="py-2 text-muted">No versions reported yet.</li>}
            {data.intel.map((i) => (
              <li key={`${i.engine}-${i.version}`} className="flex justify-between py-2"><span className="text-ink">{i.engine} {i.version}</span><span className="text-muted">first seen {ago(i.published_at)}</span></li>
            ))}
          </ul>
        </Card>
        {data.releases.length > 0 && (
          <Card className="p-4">
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

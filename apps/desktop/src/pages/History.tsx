import { useEffect, useMemo, useState } from 'react';
import { History as HistoryIcon } from 'lucide-react';
import { api } from '../lib/api';
import { useApp } from '../lib/app';
import { bytes, splitPath, when } from '../lib/format';
import type { ScanReport, Verdict } from '../lib/types';
import { Card, Empty, PageHeader, VerdictBadge } from '../components/ui';

type Filter = 'all' | Verdict;
const FILTERS: [Filter, string][] = [
  ['all', 'All'],
  ['MALICIOUS', 'Malicious'],
  ['SUSPICIOUS', 'Suspicious'],
  ['UNABLE_TO_VERIFY', 'Unable to verify'],
  ['CLEAN', 'Clean'],
];

export function History() {
  const { openReport, status } = useApp();
  const [rows, setRows] = useState<ScanReport[] | null>(null);
  const [f, setF] = useState<Filter>('all');

  useEffect(() => {
    void api.history(2000).then(setRows);
  }, [status?.stats.scansTotal]);

  const counts = useMemo(() => {
    const c: Record<string, number> = { all: rows?.length ?? 0 };
    rows?.forEach((r) => (c[r.verdict] = (c[r.verdict] ?? 0) + 1));
    return c;
  }, [rows]);
  const shown = (rows ?? []).filter((r) => f === 'all' || r.verdict === f);

  return (
    <div>
      <PageHeader title="Scan History" subtitle="Everything SENTRIX has scanned on this device. History stays on this computer." />
      <div className="mb-4 flex flex-wrap gap-2" role="tablist" aria-label="Filter by verdict">
        {FILTERS.map(([k, label]) => (
          <button key={k} role="tab" aria-selected={f === k} onClick={() => setF(k)} className={`rounded-full border px-3.5 py-1.5 text-sm transition ${f === k ? 'border-accent/60 bg-accent/10 text-ink' : 'border-line text-muted hover:text-ink'}`}>
            {label} <span className="tabular-nums text-faint">{counts[k] ?? 0}</span>
          </button>
        ))}
      </div>
      <Card className="overflow-hidden">
        {rows === null ? (
          <div className="p-8 text-sm text-muted">Loading…</div>
        ) : shown.length === 0 ? (
          <Empty icon={<HistoryIcon className="size-6" />} title={rows.length ? 'Nothing in this view' : 'No scan history yet'}>{rows.length ? 'Try another filter.' : 'Scanned files are listed here.'}</Empty>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="border-b border-line text-xs font-semibold text-muted">
              <tr>
                <th className="px-5 py-3 font-medium">File</th>
                <th className="px-3 py-3 font-medium">Source</th>
                <th className="px-3 py-3 font-medium">Type</th>
                <th className="px-3 py-3 font-medium">Verdict</th>
                <th className="px-3 py-3 text-right font-medium">Size</th>
                <th className="px-5 py-3 text-right font-medium">Scanned</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {shown.slice(0, 500).map((r) => (
                <tr key={r.id} className="cursor-pointer hover:bg-surface2/60" onClick={() => openReport(r.id)} tabIndex={0} onKeyDown={(e) => e.key === 'Enter' && openReport(r.id)}>
                  <td className="max-w-[300px] px-5 py-3">
                    <div className="truncate font-medium text-ink">{r.file.name}</div>
                    <div className="truncate text-xs text-muted">{splitPath(r.file.path)[0]}</div>
                  </td>
                  <td className="max-w-[150px] truncate px-3 py-3 text-muted">{r.origin ?? 'Manual scan'}</td>
                  <td className="max-w-[160px] truncate px-3 py-3 text-muted">{r.file.detected_type}</td>
                  <td className="px-3 py-3">
                    <VerdictBadge verdict={r.verdict} incomplete={!r.complete} />
                    {r.quarantined && <span className="ml-2 text-xs text-muted">quarantined</span>}
                  </td>
                  <td className="px-3 py-3 text-right tabular-nums text-muted">{bytes(r.file.size)}</td>
                  <td className="px-5 py-3 text-right text-muted">{when(r.finished_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}

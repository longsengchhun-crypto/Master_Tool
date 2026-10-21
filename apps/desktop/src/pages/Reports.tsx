import { useEffect, useMemo, useState } from 'react';
import { FileText, Search } from 'lucide-react';
import { api } from '../lib/api';
import { useApp } from '../lib/app';
import { ago, splitPath } from '../lib/format';
import type { ScanReport } from '../lib/types';
import { Card, Empty, PageHeader, VerdictBadge } from '../components/ui';
import { ReportView } from '../components/ReportView';

export function Reports() {
  const { reportId, openReport, status } = useApp();
  const [rows, setRows] = useState<ScanReport[] | null>(null);
  const [q, setQ] = useState('');

  const load = () => api.history(500).then(setRows);
  useEffect(() => {
    void load();
  }, [status?.stats.scansTotal]);

  const filtered = useMemo(() => {
    const t = q.trim().toLowerCase();
    return (rows ?? []).filter((r) => !t || r.file.name.toLowerCase().includes(t) || r.file.sha256.startsWith(t) || r.file.path.toLowerCase().includes(t));
  }, [rows, q]);

  const selected = rows?.find((r) => r.id === reportId) ?? null;

  return (
    <div>
      <PageHeader title="Reports" subtitle="Every scan produces a report that lists what was checked, what could not be checked, and the evidence behind the verdict." />
      <div className="grid gap-6 lg:grid-cols-[minmax(0,320px)_minmax(0,1fr)]">
        <Card className="overflow-hidden">
          <div className="border-b border-line p-3">
            <label className="relative block">
              <span className="sr-only">Search reports</span>
              <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-faint" />
              <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search name, path or hash" className="w-full rounded border border-line bg-solid py-2 pl-9 pr-3 text-sm text-ink placeholder:text-faint" />
            </label>
          </div>
          <ul className="max-h-[calc(100vh-290px)] divide-y divide-line overflow-auto">
            {rows === null && <li className="p-6 text-sm text-muted">Loading…</li>}
            {rows && filtered.length === 0 && (
              <li>
                <Empty icon={<FileText className="size-6" />} title={rows.length ? 'No matches' : 'No reports yet'}>
                  {rows.length ? 'Try a different search.' : 'Reports appear here after you scan a file.'}
                </Empty>
              </li>
            )}
            {filtered.map((r) => (
              <li key={r.id}>
                <button onClick={() => openReport(r.id)} className={`flex w-full flex-col gap-1.5 px-4 py-3 text-left hover:bg-surface2/60 ${r.id === reportId ? 'bg-surface2' : ''}`}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-sm font-medium text-ink">{r.file.name}</span>
                    <VerdictBadge verdict={r.verdict} incomplete={!r.complete} />
                  </div>
                  <div className="flex justify-between text-xs text-muted">
                    <span className="truncate">{splitPath(r.file.path)[0]}</span>
                    <span className="shrink-0 pl-2">{ago(r.finished_at)}</span>
                  </div>
                </button>
              </li>
            ))}
          </ul>
        </Card>
        <Card className="p-5">
          {selected ? <ReportView key={selected.id} report={selected} onChanged={load} /> : <Empty icon={<FileText className="size-6" />} title="Select a report">Choose a scan on the left to read the full report.</Empty>}
        </Card>
      </div>
    </div>
  );
}

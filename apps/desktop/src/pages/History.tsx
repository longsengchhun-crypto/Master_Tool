import { useEffect, useMemo, useState } from 'react';
import { FileText, Search } from 'lucide-react';
import { api } from '../lib/api';
import { useApp } from '../lib/app';
import { ago, splitPath } from '../lib/format';
import type { ScanReport, Verdict } from '../lib/types';
import { Card, Empty, PageHeader, VerdictBadge } from '../components/ui';
import { ReportView } from '../components/ReportView';

type Filter = 'all' | 'attention' | Verdict;
const FILTERS: [Filter, string][] = [
  ['all', 'All'],
  ['attention', 'Needs attention'],
  ['CLEAN', 'Clean'],
];

const needs = (r: ScanReport) => r.verdict === 'MALICIOUS' || r.verdict === 'SUSPICIOUS' || r.verdict === 'UNABLE_TO_VERIFY' || !r.complete;

export function History() {
  const { reportId, openReport, status } = useApp();
  const [rows, setRows] = useState<ScanReport[] | null>(null);
  const [q, setQ] = useState('');
  const [f, setF] = useState<Filter>('all');

  const load = () => api.history(1000).then(setRows);
  useEffect(() => {
    void load();
  }, [status?.stats.scansTotal, status?.stats.quarantined]);

  const shown = useMemo(() => {
    const t = q.trim().toLowerCase();
    return (rows ?? []).filter((r) => (f === 'all' ? true : f === 'attention' ? needs(r) : r.verdict === f) && (!t || r.file.name.toLowerCase().includes(t) || r.file.sha256.startsWith(t) || r.file.path.toLowerCase().includes(t)));
  }, [rows, q, f]);

  const selected = rows?.find((r) => r.id === reportId) ?? null;

  return (
    <div>
      <PageHeader title="History" />
      <div className="grid gap-4 lg:grid-cols-[minmax(0,340px)_minmax(0,1fr)]">
        <Card className="overflow-hidden">
          <div className="space-y-2 border-b border-line p-3">
            <label className="relative block">
              <span className="sr-only">Search</span>
              <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-faint" />
              <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search by name or path" className="h-9 w-full rounded-lg border border-strong bg-solid pl-9 pr-3 text-sm text-ink placeholder:text-faint" />
            </label>
            <div className="flex gap-1.5" role="tablist" aria-label="Filter">
              {FILTERS.map(([k, label]) => (
                <button key={k} role="tab" aria-selected={f === k} onClick={() => setF(k)} className={`rounded-full px-3 py-1 text-xs font-semibold transition-colors ${f === k ? 'bg-accent text-accentink' : 'bg-surface2 text-muted hover:text-ink'}`}>
                  {label}
                </button>
              ))}
            </div>
          </div>
          <ul className="max-h-[calc(100vh-250px)] divide-y divide-line overflow-auto">
            {rows === null && <li className="p-5 text-sm text-muted">Loading…</li>}
            {rows && shown.length === 0 && (
              <li>
                <Empty icon={<FileText className="size-6" />} title={rows.length ? 'Nothing here' : 'No scans yet'}>
                  {rows.length ? 'Try another filter or search.' : 'Results appear here after you scan a file.'}
                </Empty>
              </li>
            )}
            {shown.slice(0, 500).map((r) => (
              <li key={r.id}>
                <button onClick={() => openReport(r.id)} className={`flex w-full flex-col gap-1 px-4 py-3 text-left transition-colors hover:bg-surface2 ${r.id === reportId ? 'bg-select' : ''}`}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-sm font-semibold text-ink">{r.file.name}</span>
                    <VerdictBadge verdict={r.verdict} incomplete={!r.complete} />
                  </div>
                  <div className="flex justify-between text-xs text-muted">
                    <span className="truncate">{r.origin ?? splitPath(r.file.path)[0]}</span>
                    <span className="shrink-0 pl-2">{ago(r.finished_at)}</span>
                  </div>
                </button>
              </li>
            ))}
          </ul>
        </Card>
        <Card className="p-6">
          {selected ? <ReportView key={selected.id} report={selected} onChanged={load} /> : <Empty icon={<FileText className="size-6" />} title="Pick a scan">Its full result appears here.</Empty>}
        </Card>
      </div>
    </div>
  );
}

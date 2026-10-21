import { useState } from 'react';
import { open } from '@tauri-apps/plugin-dialog';
import { FilePlus2, FolderSearch, UploadCloud } from 'lucide-react';
import { api } from '../lib/api';
import { useApp } from '../lib/app';
import { needsAttention, splitPath } from '../lib/format';
import type { ScanReport } from '../lib/types';
import { Button, Card, Notice, PageHeader, VerdictBadge } from '../components/ui';
import { ReportView } from '../components/ReportView';

export function Scan() {
  const { scan, startScan, requestFullScan, cancelScan, status } = useApp();
  const [selected, setSelected] = useState<ScanReport | null>(null);
  const [cancelling, setCancelling] = useState(false);

  const chooseFiles = async () => {
    const sel = await open({ multiple: true, title: 'Choose files to scan' });
    if (sel) void startScan(Array.isArray(sel) ? sel : [sel]);
  };
  const chooseFolder = async () => {
    const sel = await open({ directory: true, title: 'Choose a folder to scan' });
    if (typeof sel === 'string') void startScan([sel]);
  };

  const p = scan.progress;
  // While files are still being discovered the total is unknown, so the bar stays indeterminate rather than lying.
  const known = !!p && !p.discovering && p.discovered > 0;
  const pct = p && known ? Math.round((p.done / p.discovered) * 100) : 0;
  const result = scan.result;
  const engineDown = status && status.engine.state === 'unavailable';

  return (
    <div>
      <PageHeader title="Scan" subtitle="Files are inspected where they are and never run. Nothing is uploaded." />

      {engineDown && (
        <div className="mb-4">
          <Notice tone="warn" title="No malware-signature engine is available">
            Scans can still inspect file structure, but no file can be declared clean until the engine is set up. Open Protection to install signatures.
          </Notice>
        </div>
      )}

      {!scan.running && (
        <Card className="mb-5 grid place-items-center border-dashed border-strong px-8 py-10 text-center" aria-label="Drop zone">
          <UploadCloud className="mb-3 size-7 text-faint" strokeWidth={1.5} aria-hidden />
          <h2 className="text-sm font-semibold text-ink">Drop files or folders anywhere in this window</h2>
          <p className="mt-1 max-w-md text-sm text-muted">The file type comes from the content, not the name. Archives (ZIP, JAR, APK, Office) are opened in memory, never extracted to disk.</p>
          <div className="mt-5 flex flex-wrap justify-center gap-2">
            <Button variant="primary" onClick={chooseFiles}>
              <FilePlus2 className="size-4" /> Choose files
            </Button>
            <Button onClick={chooseFolder}>
              <FolderSearch className="size-4" /> Choose a folder
            </Button>
            <Button onClick={requestFullScan}>Full system scan</Button>
          </div>
        </Card>
      )}

      {scan.running && (
        <Card className="mb-5 p-5" role="status" aria-live="polite">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h2 className="text-sm font-semibold text-ink">{scan.kind === 'full' ? 'Scanning all fixed drives…' : 'Scanning…'}</h2>
              <p className="mt-1 max-w-xl truncate text-sm text-muted" title={p?.current}>
                {p ? p.current : 'Collecting files…'}
              </p>
            </div>
            <Button
              variant="danger"
              disabled={cancelling}
              onClick={async () => {
                setCancelling(true);
                await cancelScan();
                setTimeout(() => setCancelling(false), 1500);
              }}
            >
              {cancelling ? 'Cancelling…' : 'Cancel'}
            </Button>
          </div>
          <div className="mt-4 h-1 overflow-hidden rounded-full bg-surface2">
            <div className={`h-full rounded-full bg-accent transition-all ${known ? '' : 'animate-pulse'}`} style={{ width: known ? `${Math.max(pct, 2)}%` : '100%', opacity: known ? 1 : 0.5 }} />
          </div>
          <div className="mt-2 flex justify-between text-xs text-muted tabular-nums">
            <span>
              {p ? (known ? `${p.done.toLocaleString()} of ${p.discovered.toLocaleString()} files` : `${p.done.toLocaleString()} files scanned · ${p.discovered.toLocaleString()} found so far`) : ''}
            </span>
            <span>{known ? `${pct}%` : p ? 'Finding files…' : ''}</span>
          </div>
        </Card>
      )}

      {scan.error && (
        <div className="mb-6">
          <Notice tone="danger" title="The scan could not run">
            {scan.error}
          </Notice>
        </div>
      )}

      {result && !scan.running && (
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
          <Card className="overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-3">
              <h2 className="text-sm font-semibold text-ink">Results · {result.counts.total.toLocaleString()} file{result.counts.total === 1 ? '' : 's'} scanned</h2>
              <span className="text-xs text-muted">{result.cancelled ? 'Cancelled' : result.complete ? 'Scan complete' : 'Scan incomplete'}</span>
            </div>
            <dl className="grid grid-cols-2 gap-px border-b border-line bg-line text-center sm:grid-cols-4">
              {([['Malicious', result.counts.malicious, 'text-danger'], ['Suspicious', result.counts.suspicious, 'text-warn'], ['Unable to verify', result.counts.unable_to_verify, 'text-muted'], ['Clean', result.counts.clean, 'text-ink']] as const).map(([k, v, c]) => (
                <div key={k} className="bg-solid px-3 py-3">
                  <dd className={`text-xl font-semibold tabular-nums ${v > 0 ? c : 'text-faint'}`}>{v.toLocaleString()}</dd>
                  <dt className="text-xs text-muted">{k}</dt>
                </div>
              ))}
            </dl>
            {result.reportsTruncated && (
              <div className="px-5 pt-4">
                <Notice tone="info">This was a large scan, so only files that need attention are listed. {result.counts.clean.toLocaleString()} clean file{result.counts.clean === 1 ? '' : 's'} were counted but not listed.</Notice>
              </div>
            )}
            {!result.complete && !result.cancelled && (
              <div className="px-5 pt-4">
                <Notice tone="warn" title="Not everything could be checked">
                  {result.skippedTotal > 0 ? `${result.skippedTotal.toLocaleString()} item(s) could not be read or were skipped. ` : ''}
                  {result.counts.incomplete > 0 ? `${result.counts.incomplete.toLocaleString()} file(s) were only partly inspected. ` : ''}
                  These are never declared clean.
                </Notice>
              </div>
            )}
            {result.autoQuarantined > 0 && (
              <div className="px-5 pt-4">
                <Notice tone="info">
                  {result.autoQuarantined} file{result.autoQuarantined > 1 ? 's were' : ' was'} quarantined automatically under your policy.
                </Notice>
              </div>
            )}
            <ul className="max-h-[560px] divide-y divide-line overflow-auto">
              {result.reports.map((r) => (
                <li key={r.id}>
                  <button onClick={() => setSelected(r)} className={`flex w-full items-center gap-3 px-5 py-3 text-left hover:bg-surface2/60 ${selected?.id === r.id ? 'bg-surface2' : ''}`}>
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-medium text-ink">{r.file.name}</div>
                      <div className="truncate text-xs text-muted">{splitPath(r.file.path)[0]}</div>
                    </div>
                    <VerdictBadge verdict={r.verdict} incomplete={!r.complete} />
                  </button>
                </li>
              ))}
              {result.reports.length === 0 && <li className="px-5 py-8 text-center text-sm text-muted">No files were found to scan.</li>}
            </ul>
            {result.skipped.length > 0 && (
              <details className="border-t border-line px-5 py-3 text-sm">
                <summary className="cursor-pointer text-muted">Skipped items ({result.skippedTotal.toLocaleString()}{result.skippedTotal > result.skipped.length ? `, first ${result.skipped.length} shown` : ''})</summary>
                <ul className="mt-2 space-y-1 text-xs text-muted">
                  {result.skipped.slice(0, 200).map(([path, why], i) => (
                    <li key={i} className="break-all">
                      {path} — {why}
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </Card>
          <Card className="p-5">
            {selected ? (
              <ReportView
                key={selected.id}
                report={selected}
                onChanged={async () => setSelected(await api.report(selected.id))}
              />
            ) : (
              <div className="grid h-full place-items-center py-16 text-center text-sm text-muted">
                {result.reports.some((r) => needsAttention(r.verdict, r.complete)) ? 'Select a file to see its report. Some results need your attention.' : 'Select a file to see its full report.'}
              </div>
            )}
          </Card>
        </div>
      )}
    </div>
  );
}

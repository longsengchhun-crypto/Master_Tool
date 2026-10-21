import { useState } from 'react';
import { save } from '@tauri-apps/plugin-dialog';
import { AlertTriangle, Check, ChevronDown, Copy, Download, FolderOpen, Minus, RotateCw, ShieldAlert, Trash2 } from 'lucide-react';
import { api, errText } from '../lib/api';
import { useApp } from '../lib/app';
import { CHECK_LABEL, bytes, when } from '../lib/format';
import type { CheckStatus, ScanReport, Severity } from '../lib/types';
import { Button, Modal, Notice, VerdictBadge } from './ui';

const SEV: Record<Severity, string> = {
  info: 'bg-surface2 text-muted',
  low: 'bg-infobg text-info',
  medium: 'bg-warnbg text-warn',
  high: 'bg-dangerbg text-danger',
};

/** Icons are only ever "check" for checks that really completed. Gaps get a warning, not a green tick. */
function CheckIcon({ s }: { s: CheckStatus }) {
  if (s === 'completed') return <Check className="size-4 text-ok" aria-hidden />;
  if (s === 'not_applicable') return <Minus className="size-4 text-faint" aria-hidden />;
  return <AlertTriangle className="size-4 text-warn" aria-hidden />;
}

export function ReportView({ report: r, onChanged }: { report: ScanReport; onChanged?: () => void }) {
  const { toast, startScan, refresh, status } = useApp();
  const [busy, setBusy] = useState<string | null>(null);
  const [tech, setTech] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const dismissed = !!status?.dismissedHashes.includes(r.file.sha256);
  const canDismiss = r.verdict === 'SUSPICIOUS' && !dismissed && !!status?.settings.allowRestoreSuspicious && !!r.file.sha256;

  const act = async (key: string, fn: () => Promise<void>, ok?: string) => {
    setBusy(key);
    try {
      await fn();
      if (ok) toast('ok', ok);
      onChanged?.();
      void refresh();
    } catch (e) {
      toast('danger', errText(e));
    } finally {
      setBusy(null);
    }
  };

  const exportAs = async (format: 'text' | 'json') => {
    const base = r.file.name.replace(/[^\w.-]+/g, '_');
    const path = await save({ defaultPath: `${base}-report.${format === 'json' ? 'json' : 'txt'}`, filters: [{ name: format === 'json' ? 'JSON' : 'Text', extensions: [format === 'json' ? 'json' : 'txt'] }] });
    if (path) await act('export', () => api.exportReport(r.id, format, path), 'Report exported.');
  };

  const copy = () =>
    act(
      'copy',
      async () => {
        await navigator.clipboard.writeText(await api.reportText(r.id));
      },
      'Report copied to clipboard.',
    );

  const gaps = r.checks.filter((c) => c.status === 'unavailable' || c.status === 'failed' || c.status === 'incomplete');
  const canQuarantine = !r.quarantined && r.verdict !== 'CLEAN' && !!r.file.sha256;

  return (
    <div className="rise space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="truncate text-xl font-semibold text-ink" title={r.file.name}>
            {r.file.name}
          </h2>
          <p className="mt-1 text-sm text-muted">
            {r.file.detected_type} · {bytes(r.file.size)} · scanned {when(r.finished_at)}
          </p>
        </div>
        <VerdictBadge verdict={r.verdict} incomplete={!r.complete} />
      </div>

      {r.verdict === 'MALICIOUS' && (
        <Notice tone="danger" title="Do not open this file">
          {r.summary}
        </Notice>
      )}
      {r.verdict === 'SUSPICIOUS' && (
        <Notice tone="warn" title="Needs a closer look">
          {r.summary}
        </Notice>
      )}
      {(r.verdict === 'UNABLE_TO_VERIFY' || r.verdict === 'CLEAN') && <p className="text-sm text-muted">{r.summary}</p>}
      {dismissed && <Notice tone="info">You dismissed this warning. The file was not changed and is still marked suspicious in the report.</Notice>}
      {r.origin && <p className="text-sm text-muted">Scanned because: {r.origin}</p>}
      {r.file.source && <p className="text-sm text-muted">Origin: {r.file.source}</p>}
      {r.blocked && !r.quarantined && (
        <Notice tone="warn" title="Windows has been told not to run this file">
          SENTRIX added a reversible permission that stops this file from being launched. It does not stop the file being read or copied, and it does not affect anything already running.
          <div className="mt-2">
            <Button busy={busy === 'allow'} onClick={() => act('allow', () => api.allowExecution(r.id), 'Execution allowed again for this file.')}>Allow this file to run again</Button>
          </div>
        </Notice>
      )}

      <Modal
        open={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        title="Delete this file permanently?"
        footer={
          <>
            <Button onClick={() => setConfirmDelete(false)}>Keep it</Button>
            <Button
              variant="danger"
              busy={busy === 'delete'}
              onClick={async () => {
                await act('delete', () => api.deleteFile(r.id), 'File deleted.');
                setConfirmDelete(false);
              }}
            >
              Delete permanently
            </Button>
          </>
        }
      >
        <p><span className="font-medium text-ink">{r.file.name}</span> will be erased and cannot be recovered. If you are unsure, quarantine it instead: you can restore it later.</p>
        <p className="mt-2">SENTRIX only deletes the file if it is still exactly the one that was scanned.</p>
      </Modal>

      <section>
        <h3 className="mb-1 text-sm font-semibold text-ink">Recommended action</h3>
        <p className="text-sm text-muted">{r.recommended_action}</p>
      </section>

      <div className="flex flex-wrap gap-2">
        {canQuarantine && (
          <Button variant={r.verdict === 'MALICIOUS' ? 'primary' : 'secondary'} busy={busy === 'q'} onClick={() => act('q', () => api.quarantineReport(r.id), 'File moved to quarantine.')}>
            <ShieldAlert className="size-4" /> Quarantine file
          </Button>
        )}
        {r.quarantined && <Notice tone="info">This file is in quarantine.</Notice>}
        {canDismiss && (
          <Button busy={busy === 'dismiss'} onClick={() => act('dismiss', () => api.dismissWarning(r.id), 'Warning dismissed. The file is not changed.')}>
            This is a false alarm
          </Button>
        )}
        {r.verdict !== 'CLEAN' && !r.quarantined && !!r.file.sha256 && (
          <Button variant="danger" onClick={() => setConfirmDelete(true)}>
            <Trash2 className="size-4" /> Delete file
          </Button>
        )}
        <Button disabled={r.quarantined} onClick={() => act('reveal', () => api.reveal(r.file.path))}>
          <FolderOpen className="size-4" /> Open containing folder
        </Button>
        <Button disabled={r.quarantined} onClick={() => void startScan([r.file.path], true)}>
          <RotateCw className="size-4" /> Scan again
        </Button>
        <Button onClick={copy} busy={busy === 'copy'}>
          <Copy className="size-4" /> Copy report
        </Button>
        <Button onClick={() => exportAs('text')}>
          <Download className="size-4" /> Export
        </Button>
      </div>

      <section>
        <h3 className="mb-2 text-sm font-semibold text-ink">What we checked</h3>
        <ul className="divide-y divide-line rounded-xl border border-line">
          {r.checks.map((c, i) => (
            <li key={`${c.id}-${i}`} className="flex items-start gap-3 px-4 py-3">
              <span className="mt-0.5">
                <CheckIcon s={c.status} />
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <span className="text-sm font-medium text-ink">{c.name}</span>
                  <span className={`text-xs ${c.status === 'completed' ? 'text-ok' : c.status === 'not_applicable' ? 'text-faint' : 'text-warn'}`}>{CHECK_LABEL[c.status]}</span>
                </div>
                {(c.note || c.engine_version) && (
                  <p className="mt-0.5 text-xs text-muted">
                    {c.note}
                    {c.note && c.engine_version ? ' · ' : ''}
                    {c.engine_version}
                  </p>
                )}
              </div>
            </li>
          ))}
        </ul>
        {gaps.length > 0 && (
          <p className="mt-2 text-xs text-warn">
            {gaps.length} check{gaps.length > 1 ? 's' : ''} could not be completed, so this result is incomplete.
          </p>
        )}
      </section>

      {r.findings.length > 0 && (
        <section>
          <h3 className="mb-2 text-sm font-semibold text-ink">Findings</h3>
          <ul className="space-y-2">
            {r.findings.map((f, i) => (
              <li key={i} className="rounded-xl border border-line px-4 py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`rounded-md px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ${SEV[f.severity]}`}>{f.severity}</span>
                  <span className="text-sm font-medium text-ink">{f.name}</span>
                  {f.location && <span className="rounded bg-surface2 px-1.5 py-0.5 font-mono text-xs text-muted">{f.location}</span>}
                </div>
                <p className="mt-1.5 text-sm text-muted">{f.evidence}</p>
                <p className="mt-1 text-xs text-faint">
                  Source: {f.source}
                  {f.engine_version ? ` (${f.engine_version})` : ''}
                </p>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section>
        <button className="flex items-center gap-1.5 text-sm font-medium text-muted hover:text-ink" onClick={() => setTech((v) => !v)} aria-expanded={tech}>
          <ChevronDown className={`size-4 transition ${tech ? 'rotate-180' : ''}`} /> Technical details
        </button>
        {tech && (
          <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 rounded-xl bg-surface2 p-4 text-xs">
            <dt className="text-faint">Location</dt>
            <dd className="break-all font-mono text-ink">{r.file.path}</dd>
            <dt className="text-faint">SHA-256</dt>
            <dd className="break-all font-mono text-ink">{r.file.sha256 || '(file could not be read)'}</dd>
            <dt className="text-faint">Extension</dt>
            <dd className="text-ink">{r.file.declared_extension ? `.${r.file.declared_extension}` : 'none'}{r.file.type_mismatch ? ' (does not match the content)' : ''}</dd>
            <dt className="text-faint">Digital signature</dt>
            <dd className="text-ink">{r.file.signature ? `${r.file.signature.state.replace('_', ' ')}${r.file.signature.detail ? ` — ${r.file.signature.detail}` : ''}` : 'not applicable'}</dd>
            <dt className="text-faint">Complete scan</dt>
            <dd className="text-ink">{r.complete ? 'Yes' : 'No'}</dd>
            <dt className="text-faint">Quarantined</dt>
            <dd className="text-ink">{r.quarantined ? 'Yes' : 'No'}</dd>
            <dt className="text-faint">Execution blocked</dt>
            <dd className="text-ink">{r.blocked ? 'Yes: a deny-execute permission was added to this file (reversible).' : 'No. SENTRIX scans and warns; it can only block launching of confirmed-malicious files when the execution guard is on.'}</dd>
            {r.cached && (
              <>
                <dt className="text-faint">Note</dt>
                <dd className="text-ink">Reused a previous result for identical content and engine versions.</dd>
              </>
            )}
          </dl>
        )}
      </section>

      <p className="text-xs text-faint">A CLEAN result means the checks that ran found nothing. It is not a guarantee of safety.</p>
    </div>
  );
}

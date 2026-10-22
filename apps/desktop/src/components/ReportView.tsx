import { useState } from 'react';
import { save } from '@tauri-apps/plugin-dialog';
import { AlertTriangle, Check, ChevronDown, ChevronRight, Minus, MoreHorizontal, ShieldAlert, Trash2 } from 'lucide-react';
import { api, errText } from '../lib/api';
import { useApp } from '../lib/app';
import { CHECK_LABEL, bytes, when } from '../lib/format';
import type { CheckStatus, ScanReport, Severity, ThreatInfo } from '../lib/types';
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

/** What kind of threat this is. Says plainly when it is the engine's identification and when it is only a resemblance. */
function ThreatCard({ t, danger }: { t: ThreatInfo; danger: boolean }) {
  const identified = t.basis === 'identified';
  return (
    <section className={`rounded-lg border-l-4 bg-surface2 px-4 py-3 ${danger ? 'border-danger' : 'border-warn'}`} aria-label="What kind of threat this is">
      <p className="text-xs font-semibold uppercase tracking-wide text-faint">{identified ? 'Identified as' : 'Looks like'}</p>
      <h3 className="text-base font-semibold text-ink">{t.title}</h3>
      {!identified && <p className="mt-0.5 text-xs text-muted">This comes from how the file behaves. It is a guess to help you decide, not proof.</p>}
      <dl className="mt-3 space-y-2 text-sm">
        <div>
          <dt className="text-xs font-semibold text-faint">What the attacker wants</dt>
          <dd className="text-ink">{t.goal}</dd>
        </div>
        {t.arrives_via.length > 0 && (
          <div>
            <dt className="text-xs font-semibold text-faint">How it usually arrives</dt>
            <dd className="text-ink">{t.arrives_via.join(' · ')}</dd>
          </div>
        )}
        <div>
          <dt className="text-xs font-semibold text-faint">What to do</dt>
          <dd className="text-ink">{t.advice}</dd>
        </div>
        {t.also.length > 0 && (
          <div>
            <dt className="text-xs font-semibold text-faint">Also resembles</dt>
            <dd className="text-muted">{t.also.join(', ')}</dd>
          </div>
        )}
      </dl>
      {t.attack.length > 0 && (
        <p className="mt-3 flex flex-wrap items-center gap-1.5 text-xs text-faint">
          MITRE ATT&amp;CK
          {t.attack.map((a) => (
            <span key={a} className="rounded bg-solid px-1.5 py-0.5 font-mono text-muted">{a}</span>
          ))}
        </p>
      )}
    </section>
  );
}

export function ReportView({ report: r, onChanged }: { report: ScanReport; onChanged?: () => void }) {
  const { toast, startScan, refresh, status } = useApp();
  const [busy, setBusy] = useState<string | null>(null);
  const [details, setDetails] = useState(false);
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
    if (path) await act('export', () => api.exportReport(r.id, format, path), 'Report saved.');
  };

  const copy = () =>
    act(
      'copy',
      async () => {
        await navigator.clipboard.writeText(await api.reportText(r.id));
      },
      'Report copied.',
    );

  const gaps = r.checks.filter((c) => c.status === 'unavailable' || c.status === 'failed' || c.status === 'incomplete');
  const canQuarantine = !r.quarantined && r.verdict !== 'CLEAN' && !!r.file.sha256;
  const danger = r.verdict === 'MALICIOUS';

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="truncate text-lg font-semibold text-ink" title={r.file.name}>
            {r.file.name}
          </h2>
          <p className="mt-0.5 text-sm text-muted">
            {bytes(r.file.size)} · {r.origin ?? 'Scanned manually'} · {when(r.finished_at)}
          </p>
        </div>
        <VerdictBadge verdict={r.verdict} incomplete={!r.complete} />
      </div>

      {danger && <Notice tone="danger" title="Dangerous file">{r.summary}</Notice>}
      {r.verdict === 'SUSPICIOUS' && <Notice tone="warn" title="Be careful with this file">{r.summary}</Notice>}
      {r.verdict === 'UNABLE_TO_VERIFY' && <Notice tone="warn" title="Could not be fully checked">{r.summary}</Notice>}
      {r.verdict === 'CLEAN' && <p className="text-sm text-muted">{r.summary}</p>}
      {dismissed && <Notice tone="info">You marked this warning as a false alarm. The file itself was not changed.</Notice>}
      {gaps.length > 0 && r.verdict !== 'UNABLE_TO_VERIFY' && (
        <p className="text-sm text-warn">{gaps.length} check{gaps.length > 1 ? 's' : ''} could not finish, so this result is incomplete.</p>
      )}
      {r.blocked && !r.quarantined && (
        <Notice tone="warn" title="Windows will refuse to run this file">
          SENTRIX added a reversible block. The file can still be read or copied.
          <div className="mt-2">
            <Button busy={busy === 'allow'} onClick={() => act('allow', () => api.allowExecution(r.id), 'This file can run again.')}>Allow it to run again</Button>
          </div>
        </Notice>
      )}
      {r.quarantined && <Notice tone="info">This file is in quarantine. Open Quarantine to restore or delete it.</Notice>}

      <p className="text-sm text-ink">{r.recommended_action}</p>

      {r.threat && <ThreatCard t={r.threat} danger={danger} />}

      <div className="flex flex-wrap items-center gap-2">
        {canQuarantine && (
          <Button variant={danger ? 'primary' : 'secondary'} busy={busy === 'q'} onClick={() => act('q', () => api.quarantineReport(r.id), 'Moved to quarantine.')}>
            <ShieldAlert className="size-4" /> Quarantine
          </Button>
        )}
        {canDismiss && (
          <Button busy={busy === 'dismiss'} onClick={() => act('dismiss', () => api.dismissWarning(r.id), 'Marked as a false alarm.')}>
            It is safe
          </Button>
        )}
        {r.verdict !== 'CLEAN' && !r.quarantined && !!r.file.sha256 && (
          <Button variant="danger" onClick={() => setConfirmDelete(true)}>
            <Trash2 className="size-4" /> Delete
          </Button>
        )}
        <details className="relative">
          <summary className="inline-flex h-9 cursor-pointer list-none items-center gap-1.5 rounded-lg border border-strong bg-solid px-3 text-sm font-semibold text-ink hover:bg-surface2 [&::-webkit-details-marker]:hidden">
            <MoreHorizontal className="size-4" aria-hidden /> More
          </summary>
          <div className="panel absolute left-0 z-10 mt-1 w-52 rounded-lg p-1 shadow-xl">
            {[
              ['Scan again', () => void startScan([r.file.path], true), r.quarantined],
              ['Show in folder', () => void act('reveal', () => api.reveal(r.file.path)), r.quarantined],
              ['Copy report', () => void copy(), false],
              ['Save report…', () => void exportAs('text'), false],
            ].map(([label, fn, off]) => (
              <button key={label as string} disabled={off as boolean} onClick={fn as () => void} className="block w-full rounded px-3 py-2 text-left text-sm text-ink hover:bg-surface2 disabled:opacity-40">
                {label as string}
              </button>
            ))}
          </div>
        </details>
      </div>

      {r.findings.length > 0 && (
        <section>
          <h3 className="mb-2 text-sm font-semibold text-ink">What was found</h3>
          <ul className="space-y-2">
            {r.findings.slice(0, 4).map((f, i) => (
              <li key={i} className="rounded-lg border border-line px-4 py-2.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`rounded px-1.5 py-0.5 text-xs font-semibold capitalize ${SEV[f.severity]}`}>{f.severity}</span>
                  <span className="text-sm font-semibold text-ink">{f.name}</span>
                  {f.location && <span className="rounded bg-surface2 px-1.5 py-0.5 font-mono text-xs text-muted">{f.location}</span>}
                </div>
                <p className="mt-1 text-sm text-muted">{f.evidence}</p>
              </li>
            ))}
          </ul>
          {r.findings.length > 4 && <p className="mt-2 text-xs text-muted">{r.findings.length - 4} more in the details below.</p>}
        </section>
      )}

      <section>
        <button className="flex items-center gap-1.5 text-sm font-semibold text-muted hover:text-ink" onClick={() => setDetails((v) => !v)} aria-expanded={details}>
          {details ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />} Details
        </button>
        {details && (
          <div className="mt-3 space-y-4">
            <ul className="divide-y divide-line rounded-lg border border-line">
              {r.checks.map((c, i) => (
                <li key={`${c.id}-${i}`} className="flex items-start gap-3 px-4 py-2.5">
                  <span className="mt-0.5">
                    <CheckIcon s={c.status} />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-baseline justify-between gap-2">
                      <span className="text-sm text-ink">{c.name}</span>
                      <span className={`text-xs ${c.status === 'completed' ? 'text-ok' : c.status === 'not_applicable' ? 'text-faint' : 'text-warn'}`}>{CHECK_LABEL[c.status]}</span>
                    </div>
                    {(c.note || c.engine_version) && <p className="mt-0.5 text-xs text-muted">{[c.note, c.engine_version].filter(Boolean).join(' · ')}</p>}
                  </div>
                </li>
              ))}
            </ul>
            {r.findings.slice(4).map((f, i) => (
              <p key={i} className="text-sm text-muted"><span className="font-semibold text-ink">{f.name}</span>: {f.evidence}</p>
            ))}
            <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 rounded-lg bg-surface2 p-4 text-xs">
              <dt className="text-faint">Location</dt>
              <dd className="break-all font-mono text-ink">{r.file.path}</dd>
              <dt className="text-faint">Type</dt>
              <dd className="text-ink">{r.file.detected_type}{r.file.type_mismatch ? ' (does not match the file name)' : ''}</dd>
              <dt className="text-faint">SHA-256</dt>
              <dd className="break-all font-mono text-ink">{r.file.sha256 || '(file could not be read)'}</dd>
              <dt className="text-faint">Signature</dt>
              <dd className="text-ink">{r.file.signature ? `${r.file.signature.state.replace('_', ' ')}${r.file.signature.detail ? `: ${r.file.signature.detail}` : ''}` : 'Not applicable'}</dd>
              {r.file.source && (
                <>
                  <dt className="text-faint">Downloaded from</dt>
                  <dd className="text-ink">{r.file.source}</dd>
                </>
              )}
              {r.cached && (
                <>
                  <dt className="text-faint">Note</dt>
                  <dd className="text-ink">Reused an earlier result for identical content.</dd>
                </>
              )}
            </dl>
            <p className="text-xs text-faint">A clean result means the checks that ran found nothing. It is not a guarantee.</p>
          </div>
        )}
      </section>

      <Modal
        open={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        title="Delete this file?"
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
        <p><span className="font-semibold text-ink">{r.file.name}</span> will be erased and cannot be recovered. Not sure? Quarantine it instead, you can restore it later.</p>
      </Modal>
    </div>
  );
}

import { useCallback, useEffect, useState } from 'react';
import { ArchiveRestore, ShieldCheck, Trash2 } from 'lucide-react';
import { api, errText } from '../lib/api';
import { useApp } from '../lib/app';
import { bytes, splitPath, when } from '../lib/format';
import type { QuarantineRecord } from '../lib/types';
import { Button, Card, Empty, Modal, Notice, PageHeader, Pill, VerdictBadge } from '../components/ui';

export function Quarantine() {
  const { toast, refresh } = useApp();
  const [rows, setRows] = useState<QuarantineRecord[] | null>(null);
  const [restoreFor, setRestoreFor] = useState<QuarantineRecord | null>(null);
  const [deleteFor, setDeleteFor] = useState<QuarantineRecord | null>(null);
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [audit, setAudit] = useState<'unchecked' | 'ok' | 'broken'>('unchecked');

  const load = useCallback(async () => {
    try {
      setRows((await api.listQuarantine()).filter((r) => r.state === 'quarantined'));
    } catch (e) {
      toast('danger', errText(e));
      setRows([]);
    }
  }, [toast]);
  useEffect(() => {
    void load();
  }, [load]);

  const run = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true);
    try {
      await fn();
      toast('ok', ok);
      setRestoreFor(null);
      setDeleteFor(null);
      setTyped('');
      await load();
      void refresh();
    } catch (e) {
      toast('danger', errText(e));
    } finally {
      setBusy(false);
    }
  };

  const malicious = restoreFor?.verdict === 'MALICIOUS';

  return (
    <div>
      <PageHeader
        title="Quarantine"
        subtitle="Quarantined files are encrypted and cannot run or be opened. You can restore a file if you are sure it is safe, or delete it permanently."
        actions={
          <Button
            onClick={async () => {
              const bad = await api.verifyQuarantineAudit();
              setAudit(bad == null ? 'ok' : 'broken');
            }}
          >
            <ShieldCheck className="size-4" /> Verify audit log
          </Button>
        }
      />
      {audit === 'ok' && (
        <div className="mb-4">
          <Notice tone="ok">The quarantine audit log is intact: no entries were altered or removed.</Notice>
        </div>
      )}
      {audit === 'broken' && (
        <div className="mb-4">
          <Notice tone="danger" title="Audit log was modified">
            One or more quarantine log entries do not match their integrity checks. Something other than SENTRIX changed this record.
          </Notice>
        </div>
      )}
      <Card className="overflow-hidden">
        {rows === null ? (
          <div className="p-8 text-sm text-muted">Loading…</div>
        ) : rows.length === 0 ? (
          <Empty icon={<ShieldCheck className="size-6" />} title="Quarantine is empty">Files you quarantine appear here. Nothing is moved automatically unless you turn that on under Protection.</Empty>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="border-b border-line text-xs uppercase tracking-wide text-muted">
              <tr>
                <th className="px-5 py-3 font-medium">File</th>
                <th className="px-3 py-3 font-medium">Verdict</th>
                <th className="px-3 py-3 font-medium">Quarantined</th>
                <th className="px-3 py-3 text-right font-medium">Size</th>
                <th className="px-5 py-3 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {rows.map((r) => (
                <tr key={r.id}>
                  <td className="max-w-[320px] px-5 py-3">
                    <div className="truncate font-medium text-ink">{r.original_name}</div>
                    <div className="truncate text-xs text-muted" title={r.original_path}>
                      {splitPath(r.original_path)[0]}
                    </div>
                    <div className="truncate font-mono text-[11px] text-faint" title={r.sha256}>
                      {r.sha256.slice(0, 20)}…
                    </div>
                  </td>
                  <td className="px-3 py-3">
                    {r.tampered ? <Pill tone="danger">Record tampered</Pill> : <VerdictBadge verdict={r.verdict} />}
                  </td>
                  <td className="px-3 py-3 text-muted">{when(r.quarantined_at)}</td>
                  <td className="px-3 py-3 text-right tabular-nums text-muted">{bytes(r.size)}</td>
                  <td className="px-5 py-3">
                    <div className="flex justify-end gap-2">
                      <Button disabled={r.tampered} onClick={() => setRestoreFor(r)}>
                        <ArchiveRestore className="size-4" /> Restore
                      </Button>
                      <Button variant="danger" onClick={() => setDeleteFor(r)}>
                        <Trash2 className="size-4" /> Delete
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Modal
        open={!!restoreFor}
        onClose={() => {
          setRestoreFor(null);
          setTyped('');
        }}
        title={malicious ? 'Restore a malicious file?' : 'Restore this file?'}
        footer={
          <>
            <Button onClick={() => { setRestoreFor(null); setTyped(''); }}>Keep in quarantine</Button>
            <Button variant={malicious ? 'danger' : 'primary'} busy={busy} disabled={malicious && typed !== 'RESTORE'} onClick={() => restoreFor && run(() => api.restoreQuarantine(restoreFor.id, malicious), 'File restored.')}>
              Restore file
            </Button>
          </>
        }
      >
        {restoreFor && (
          <div className="space-y-3">
            <p>
              <span className="font-medium text-ink">{restoreFor.original_name}</span> will be written back to <span className="break-all font-mono text-xs">{splitPath(restoreFor.original_path)[0] || 'its original folder'}</span>. An existing file with the same name will not be overwritten.
            </p>
            {malicious ? (
              <>
                <Notice tone="danger" title="This file was identified as malicious">
                  Restoring it can harm your computer or data. Only continue if you are certain this is a false alarm, for example after checking with a second scanner.
                </Notice>
                <label className="block text-sm">
                  Type <span className="font-mono font-semibold text-ink">RESTORE</span> to confirm
                  <input value={typed} onChange={(e) => setTyped(e.target.value)} className="mt-1 w-full rounded-xl border border-line bg-solid px-3 py-2 font-mono text-ink" autoComplete="off" spellCheck={false} />
                </label>
              </>
            ) : (
              <p>This file was marked {restoreFor.verdict.toLowerCase().replace('_', ' ')}. It is restored exactly as it was.</p>
            )}
          </div>
        )}
      </Modal>

      <Modal
        open={!!deleteFor}
        onClose={() => setDeleteFor(null)}
        title="Delete permanently?"
        footer={
          <>
            <Button onClick={() => setDeleteFor(null)}>Cancel</Button>
            <Button variant="danger" busy={busy} onClick={() => deleteFor && run(() => api.deleteQuarantine(deleteFor.id), 'File permanently deleted.')}>
              Delete permanently
            </Button>
          </>
        }
      >
        {deleteFor && (
          <p>
            <span className="font-medium text-ink">{deleteFor.original_name}</span> will be erased from quarantine. This cannot be undone.
          </p>
        )}
      </Modal>
    </div>
  );
}

'use client';

import { useState } from 'react';
import { Plus } from 'lucide-react';
import { can } from '@/lib/rbac';
import { Badge, Button, Card, Empty, Field, Modal, Notice, PageHeader, Table, inputCls } from '@/components/ui';
import { useConsole } from '../provider';
import { fmtDate, useData } from '../use-data';

interface Rel { id: string; version: string; platform: string; channel: string; status: string; rollout_pct: number; artifact_url: string | null; sha256: string | null; has_update_signature: boolean; code_signed: boolean; size_bytes: string | null; published_at: string | null; created_at: string }

const TONE: Record<string, 'ok' | 'info' | 'warn' | 'danger' | 'muted'> = { published: 'ok', staged: 'info', draft: 'muted', cancelled: 'warn', rolled_back: 'danger' };

export default function Releases() {
  const { me, call } = useConsole();
  const { data, error, loading, reload } = useData<{ releases: Rel[] }>('/api/admin/releases');
  const [creating, setCreating] = useState(false);
  const [f, setF] = useState({ version: '', platform: 'windows-x64', notes: '', artifactUrl: '', sha256: '', signature: '', codeSigned: false, sizeBytes: '' });
  const [act, setAct] = useState<{ r: Rel; action: 'stage' | 'publish' | 'cancel' | 'rollback'; pct: number } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const create = async () => {
    setBusy(true);
    setErr(null);
    try {
      await call('/api/admin/releases', {
        method: 'POST',
        body: { version: f.version, platform: f.platform, notes: f.notes, ...(f.artifactUrl ? { artifactUrl: f.artifactUrl } : {}), ...(f.sha256 ? { sha256: f.sha256.toLowerCase() } : {}), ...(f.signature ? { signature: f.signature } : {}), codeSigned: f.codeSigned, ...(f.sizeBytes ? { sizeBytes: Number(f.sizeBytes) } : {}) },
      });
      setCreating(false);
      await reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed');
    } finally {
      setBusy(false);
    }
  };

  const run = async () => {
    if (!act) return;
    setBusy(true);
    setErr(null);
    try {
      await call(`/api/admin/releases/${act.r.id}/action`, { method: 'POST', body: { action: act.action, ...(act.action === 'stage' ? { rolloutPct: act.pct } : {}) } });
      setAct(null);
      await reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed');
      setAct(null);
    } finally {
      setBusy(false);
    }
  };

  const publish = can(me.role, 'release:publish');
  return (
    <div>
      <PageHeader title="Releases" subtitle="Application updates only. Malware signatures update separately. A build can only be offered to devices when it has an artifact URL, a SHA-256 and an update signature." actions={publish && <Button variant="primary" onClick={() => setCreating(true)}><Plus className="size-4" /> New release</Button>} />
      {(error || err) && <div className="mb-4"><Notice tone="danger">{err ?? error}</Notice></div>}
      <Card className="overflow-hidden">
        {loading ? <Empty>Loading…</Empty> : !data?.releases.length ? <Empty>No releases yet.</Empty> : (
          <Table head={['Version', 'Platform', 'Status', 'Signing', 'Published', '']}>
            {data.releases.map((r) => (
              <tr key={r.id}>
                <td className="px-4 py-3 font-medium text-ink">{r.version}<div className="text-xs text-muted">{r.channel}</div></td>
                <td className="px-4 py-3 text-muted">{r.platform}</td>
                <td className="px-4 py-3"><Badge tone={TONE[r.status]}>{r.status.replace('_', ' ')}{r.status === 'staged' ? ` ${r.rollout_pct}%` : ''}</Badge></td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1.5">
                    <Badge tone={r.has_update_signature ? 'ok' : 'warn'}>{r.has_update_signature ? 'update-signed' : 'no update signature'}</Badge>
                    <Badge tone={r.code_signed ? 'ok' : 'warn'}>{r.code_signed ? 'code-signed' : 'unsigned build'}</Badge>
                  </div>
                </td>
                <td className="px-4 py-3 text-muted">{fmtDate(r.published_at)}</td>
                <td className="px-4 py-3">
                  {publish && (
                    <div className="flex justify-end gap-2">
                      {(r.status === 'draft' || r.status === 'staged') && <Button onClick={() => setAct({ r, action: 'stage', pct: r.status === 'staged' ? r.rollout_pct : 10 })}>Stage</Button>}
                      {(r.status === 'draft' || r.status === 'staged') && <Button variant="primary" onClick={() => setAct({ r, action: 'publish', pct: 100 })}>Publish</Button>}
                      {(r.status === 'draft' || r.status === 'staged') && <Button variant="danger" onClick={() => setAct({ r, action: 'cancel', pct: 0 })}>Cancel</Button>}
                      {(r.status === 'staged' || r.status === 'published') && <Button variant="danger" onClick={() => setAct({ r, action: 'rollback', pct: 0 })}>Roll back</Button>}
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <Modal open={creating} onClose={() => setCreating(false)} title="New release (draft)" footer={<><Button onClick={() => setCreating(false)}>Cancel</Button><Button variant="primary" busy={busy} disabled={!/^\d+\.\d+\.\d+$/.test(f.version)} onClick={create}>Create draft</Button></>}>
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <Field label="Version"><input className={inputCls} placeholder="0.1.0" value={f.version} onChange={(e) => setF({ ...f, version: e.target.value })} /></Field>
            <Field label="Platform"><select className={inputCls} value={f.platform} onChange={(e) => setF({ ...f, platform: e.target.value })}><option>windows-x64</option><option>macos-arm64</option><option>macos-x64</option><option>linux-x64</option></select></Field>
          </div>
          <Field label="Artifact URL (https)"><input className={inputCls} value={f.artifactUrl} onChange={(e) => setF({ ...f, artifactUrl: e.target.value })} /></Field>
          <Field label="SHA-256"><input className={`${inputCls} font-mono text-xs`} value={f.sha256} onChange={(e) => setF({ ...f, sha256: e.target.value })} /></Field>
          <Field label="Update signature (from `tauri signer sign`)"><textarea className={`${inputCls} h-16 font-mono text-xs`} value={f.signature} onChange={(e) => setF({ ...f, signature: e.target.value })} /></Field>
          <Field label="Release notes"><textarea className={`${inputCls} h-20`} value={f.notes} onChange={(e) => setF({ ...f, notes: e.target.value })} /></Field>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={f.codeSigned} onChange={(e) => setF({ ...f, codeSigned: e.target.checked })} /> The installer is Authenticode-signed with a valid publisher certificate</label>
        </div>
      </Modal>

      <Modal open={!!act} onClose={() => setAct(null)} title={act ? `${act.action[0].toUpperCase()}${act.action.slice(1)} ${act.r.version}?` : ''} footer={<><Button onClick={() => setAct(null)}>Back</Button><Button variant={act?.action === 'publish' || act?.action === 'stage' ? 'primary' : 'danger'} busy={busy} onClick={run}>Confirm</Button></>}>
        {act?.action === 'stage' && (
          <div className="space-y-3"><p>Offer this build to a share of devices first. Devices are placed in a stable cohort, so the same devices stay in as you increase the percentage.</p><Field label={`Rollout: ${act.pct}%`}><input type="range" min={1} max={99} value={act.pct} onChange={(e) => setAct({ ...act, pct: Number(e.target.value) })} className="w-full" /></Field></div>
        )}
        {act?.action === 'publish' && <p>This offers the build to every device on the {act.r.platform} stable channel. Devices verify its signature before installing.</p>}
        {act?.action === 'cancel' && <p>This withdraws the draft or staged build; devices that have not installed it will no longer be offered it.</p>}
        {act?.action === 'rollback' && <p>This stops offering the build. Devices that already installed it are not downgraded: ship a fixed newer version to move them forward.</p>}
      </Modal>
    </div>
  );
}

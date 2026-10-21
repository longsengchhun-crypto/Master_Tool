import { q } from '@/lib/db';
import { handle, uuidParam } from '@/lib/http';
import { assertScope, authorize, HttpError } from '@/lib/session';

export const runtime = 'nodejs';

export const GET = handle(async (_req, ctx: { params: Promise<{ id: string }> }) => {
  const p = await authorize({ perm: 'device:read' });
  const id = uuidParam((await ctx.params).id);
  const [d] = await q(
    `SELECT d.id, d.org_id, o.name AS org_name, d.hostname, d.os, d.os_version, d.app_version, d.engine_version,
            d.intel_version, d.intel_updated_at, d.protection, d.queue, d.telegram, d.status, d.last_seen_at, d.created_at
       FROM devices d JOIN organizations o ON o.id = d.org_id WHERE d.id = $1`,
    [id],
  );
  if (!d) throw new HttpError(404, 'Not found', 'not_found');
  assertScope(p, d.org_id as string);
  const events = await q('SELECT id, kind, severity, detail, created_at FROM security_events WHERE device_id = $1 ORDER BY created_at DESC LIMIT 50', [id]);
  const sessions = await q('SELECT id, kind, started_at, finished_at, files_total, files_failed, complete FROM scan_sessions WHERE device_id = $1 ORDER BY started_at DESC LIMIT 20', [id]);
  const jobs = await q('SELECT id, kind, state, result, created_at, updated_at FROM update_jobs WHERE device_id = $1 ORDER BY created_at DESC LIMIT 20', [id]);
  return { device: d, events, sessions, jobs };
});

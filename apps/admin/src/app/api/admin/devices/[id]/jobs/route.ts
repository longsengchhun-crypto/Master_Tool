import { z } from 'zod';
import { audit } from '@/lib/audit';
import { q, tx } from '@/lib/db';
import { body, clientIpOf, csrfOf, handle, uuidParam } from '@/lib/http';
import { assertScope, authorize, HttpError } from '@/lib/session';

export const runtime = 'nodejs';

/**
 * The ONLY remote actions an administrator can request are in this closed enum. There is no command string, no script,
 * no path: the device agent maps each kind to a fixed, visible, user-notified local action.
 */
const Req = z.strictObject({ kind: z.enum(['scan_quick', 'intel_update', 'app_update']) });

export const POST = handle(async (req, ctx: { params: Promise<{ id: string }> }) => {
  const p = await authorize({ perm: 'device:manage', csrf: csrfOf(req) });
  const id = uuidParam((await ctx.params).id);
  const { kind } = await body(req, Req);
  const [d] = await q<{ org_id: string; status: string }>('SELECT org_id, status FROM devices WHERE id = $1', [id]);
  if (!d) throw new HttpError(404, 'Not found', 'not_found');
  assertScope(p, d.org_id);
  if (d.status !== 'enrolled') throw new HttpError(409, 'Device is not enrolled', 'not_enrolled');

  const job = await tx(async (c) => {
    // At most one open job of each kind per device, so a console cannot flood an endpoint.
    const open = await c.query("SELECT 1 FROM update_jobs WHERE device_id = $1 AND kind = $2 AND state IN ('pending','delivered')", [id, kind]);
    if (open.rowCount) throw new HttpError(409, 'A request of this type is already pending for this device', 'duplicate_job');
    const r = await c.query<{ id: string }>('INSERT INTO update_jobs(device_id, kind, requested_by) VALUES ($1,$2,$3) RETURNING id', [id, kind, p.userId]);
    await audit({ actorId: p.userId, actorEmail: p.email, orgId: d.org_id, action: 'device.job_requested', target: id, detail: { kind }, ip: clientIpOf(req) }, c);
    return r.rows[0];
  });
  return { job };
});

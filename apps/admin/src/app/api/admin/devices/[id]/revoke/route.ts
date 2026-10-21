import { audit } from '@/lib/audit';
import { q, tx } from '@/lib/db';
import { clientIpOf, csrfOf, handle, uuidParam } from '@/lib/http';
import { assertScope, authorize, HttpError } from '@/lib/session';

export const runtime = 'nodejs';

/** Revoking a device invalidates its token immediately, frees its license seat and cancels pending jobs. */
export const POST = handle(async (req, ctx: { params: Promise<{ id: string }> }) => {
  const p = await authorize({ perm: 'device:revoke', csrf: csrfOf(req) });
  const id = uuidParam((await ctx.params).id);
  const [d] = await q<{ org_id: string; hostname: string; status: string }>('SELECT org_id, hostname, status FROM devices WHERE id = $1', [id]);
  if (!d) throw new HttpError(404, 'Not found', 'not_found');
  assertScope(p, d.org_id);
  if (d.status === 'revoked') return { ok: true, alreadyRevoked: true };

  await tx(async (c) => {
    await c.query("UPDATE devices SET status = 'revoked', revoked_at = now() WHERE id = $1", [id]);
    await c.query('DELETE FROM license_activations WHERE device_id = $1', [id]);
    await c.query("UPDATE update_jobs SET state = 'cancelled', updated_at = now() WHERE device_id = $1 AND state IN ('pending','delivered')", [id]);
    await audit({ actorId: p.userId, actorEmail: p.email, orgId: d.org_id, action: 'device.revoke', target: id, detail: { hostname: d.hostname }, ip: clientIpOf(req) }, c);
  });
  return { ok: true };
});

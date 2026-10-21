import { audit } from '@/lib/audit';
import { q, tx } from '@/lib/db';
import { clientIpOf, csrfOf, handle, uuidParam } from '@/lib/http';
import { authorize, HttpError } from '@/lib/session';

export const runtime = 'nodejs';

/** Revocation takes effect at the device's next heartbeat (license status is part of the heartbeat response). */
export const POST = handle(async (req, ctx: { params: Promise<{ id: string }> }) => {
  const p = await authorize({ perm: 'license:manage', csrf: csrfOf(req) });
  const id = uuidParam((await ctx.params).id);
  const [l] = await q<{ org_id: string; status: string }>('SELECT org_id, status FROM licenses WHERE id = $1', [id]);
  if (!l) throw new HttpError(404, 'Not found', 'not_found');
  if (l.status === 'revoked') return { ok: true, alreadyRevoked: true };
  await tx(async (c) => {
    await c.query("UPDATE licenses SET status = 'revoked', revoked_at = now() WHERE id = $1", [id]);
    await audit({ actorId: p.userId, actorEmail: p.email, orgId: l.org_id, action: 'license.revoke', target: id, ip: clientIpOf(req) }, c);
  });
  return { ok: true };
});

import { audit } from '@/lib/audit';
import { tx } from '@/lib/db';
import { authDevice } from '@/lib/device-auth';
import { clientIpOf, handle } from '@/lib/http';

export const runtime = 'nodejs';

/** A user can always remove their own device from management; this frees the license seat. */
export const POST = handle(
  async (req) => {
    const dev = await authDevice(req);
    await tx(async (c) => {
      await c.query("UPDATE devices SET status = 'revoked', revoked_at = now() WHERE id = $1", [dev.id]);
      await c.query('DELETE FROM license_activations WHERE device_id = $1', [dev.id]);
      await c.query("UPDATE update_jobs SET state = 'cancelled', updated_at = now() WHERE device_id = $1 AND state IN ('pending','delivered')", [dev.id]);
      await audit({ actorEmail: `device:${dev.hostname}`, orgId: dev.orgId, action: 'device.unenroll', target: dev.id, ip: clientIpOf(req) }, c);
    });
    return { ok: true };
  },
  { cookieAuth: false },
);

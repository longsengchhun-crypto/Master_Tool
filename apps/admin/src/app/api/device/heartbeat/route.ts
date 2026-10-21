import { HeartbeatRequest } from '@sentrix/contracts';
import { q, tx } from '@/lib/db';
import { authDevice } from '@/lib/device-auth';
import { policyForOrg, updateFor } from '@/lib/device-support';
import { body, handle } from '@/lib/http';

export const runtime = 'nodejs';

/**
 * Device check-in. The response carries everything the device needs to stay in sync: policy, license state, queued
 * jobs (closed enum) and an update offer. The device applies these visibly; the console cannot run arbitrary commands.
 */
export const POST = handle(
  async (req) => {
    const dev = await authDevice(req);
    const b = await body(req, HeartbeatRequest);

    await q(
      `UPDATE devices SET app_version = $2, engine_version = $3, intel_version = $4, intel_updated_at = $5, protection = $6, queue = $7, telegram = $8, last_seen_at = now() WHERE id = $1`,
      [dev.id, b.appVersion, b.engineVersion, b.intelVersion, b.intelUpdatedAt, JSON.stringify(b.protection), JSON.stringify(b.queue ?? {}), JSON.stringify(b.telegram ?? {})],
    );
    if (b.engineVersion && b.intelVersion) {
      await q('INSERT INTO intel_versions(engine, version) VALUES ($1,$2) ON CONFLICT (engine, version) DO NOTHING', [b.engineVersion.slice(0, 40), b.intelVersion.slice(0, 80)]);
    }

    const lic = await q<{ status: string; expired: boolean; plan: string; expires_at: string | null }>(
      `SELECT l.status::text AS status, (l.expires_at IS NOT NULL AND l.expires_at < now()) AS expired, l.plan, l.expires_at
         FROM license_activations a JOIN licenses l ON l.id = a.license_id WHERE a.device_id = $1 LIMIT 1`,
      [dev.id],
    );
    const l = lic[0];
    const license = !l ? { state: 'none' } : l.status !== 'active' ? { state: l.status } : l.expired ? { state: 'expired' } : { state: 'valid', plan: l.plan, expiresAt: l.expires_at };

    const jobs = await tx(async (c) => {
      const r = await c.query<{ id: string; kind: string }>(
        `UPDATE update_jobs SET state = 'delivered', updated_at = now() WHERE device_id = $1 AND state = 'pending' RETURNING id, kind`,
        [dev.id],
      );
      return r.rows;
    });

    const update = await updateFor('windows-x64', 'stable', b.appVersion, dev.id);
    return { serverTime: new Date().toISOString(), policy: await policyForOrg(dev.orgId), license, jobs, update };
  },
  { cookieAuth: false },
);

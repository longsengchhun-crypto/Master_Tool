import { DevicePolicy } from '@sentrix/contracts';
import { z } from 'zod';
import { audit } from '@/lib/audit';
import { q } from '@/lib/db';
import { body, clientIpOf, csrfOf, handle } from '@/lib/http';
import { authorize, scopeIds } from '@/lib/session';

export const runtime = 'nodejs';

export const GET = handle(async () => {
  const p = await authorize({ perm: 'policy:read' });
  const rows = await q(
    `SELECT pol.id, pol.org_id, o.name AS org_name, pol.name, pol.version, pol.config, pol.is_default, pol.updated_at
       FROM device_policies pol JOIN organizations o ON o.id = pol.org_id
      WHERE ($1::uuid[] IS NULL OR pol.org_id = ANY($1)) ORDER BY o.name, pol.name LIMIT 500`,
    [scopeIds(p)],
  );
  return { policies: rows };
});

const Put = z.strictObject({ orgId: z.string().uuid(), name: z.string().trim().min(1).max(60).default('default'), config: DevicePolicy });

/** Create/replace a policy. The config is validated against the closed DevicePolicy schema: unknown keys are rejected. */
export const PUT = handle(async (req) => {
  const b = await body(req, Put);
  const p = await authorize({ perm: 'policy:write', orgId: b.orgId, csrf: csrfOf(req) });
  const [row] = await q<{ version: number }>(
    `INSERT INTO device_policies(org_id, name, config, is_default, updated_by) VALUES ($1,$2,$3,true,$4)
     ON CONFLICT (org_id, name) DO UPDATE SET config = EXCLUDED.config, version = device_policies.version + 1, updated_by = EXCLUDED.updated_by, updated_at = now()
     RETURNING version`,
    [b.orgId, b.name, JSON.stringify(b.config), p.userId],
  );
  await audit({ actorId: p.userId, actorEmail: p.email, orgId: b.orgId, action: 'policy.write', target: b.name, detail: { version: row.version, config: b.config }, ip: clientIpOf(req) });
  return { ok: true, version: row.version };
});

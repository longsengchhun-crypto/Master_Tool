import { z } from 'zod';
import { audit } from '@/lib/audit';
import { hmac } from '@/lib/crypto';
import { q } from '@/lib/db';
import { body, clientIpOf, csrfOf, handle } from '@/lib/http';
import { newCode } from '@/lib/codes';
import { authorize, HttpError, scopeIds } from '@/lib/session';

export const runtime = 'nodejs';

export const GET = handle(async () => {
  const p = await authorize({ perm: 'license:read' });
  const rows = await q(
    `SELECT l.id, l.org_id, o.name AS org_name, l.key_hint, l.plan, l.seats, l.status, l.expires_at, l.revoked_at, l.created_at,
            (SELECT count(*) FROM license_activations a WHERE a.license_id = l.id) AS seats_used
       FROM licenses l JOIN organizations o ON o.id = l.org_id
      WHERE ($1::uuid[] IS NULL OR l.org_id = ANY($1)) ORDER BY l.created_at DESC LIMIT 500`,
    [scopeIds(p)],
  );
  return { licenses: rows };
});

const Create = z.strictObject({
  orgId: z.string().uuid(),
  plan: z.string().trim().min(1).max(40).default('standard'),
  seats: z.number().int().min(1).max(100_000),
  expiresAt: z.string().datetime().nullable().default(null),
});

/** The license key is returned exactly once; only its HMAC and last 4 characters are stored. */
export const POST = handle(async (req) => {
  const p = await authorize({ perm: 'license:manage', csrf: csrfOf(req) });
  const b = await body(req, Create);
  const [org] = await q('SELECT 1 FROM organizations WHERE id = $1', [b.orgId]);
  if (!org) throw new HttpError(404, 'Not found', 'not_found');
  const key = newCode('SXLK', 4, 5);
  const [l] = await q<{ id: string }>(
    `INSERT INTO licenses(org_id, key_hash, key_hint, plan, seats, expires_at) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
    [b.orgId, hmac(key), key.slice(-4), b.plan, b.seats, b.expiresAt],
  );
  await audit({ actorId: p.userId, actorEmail: p.email, orgId: b.orgId, action: 'license.create', target: l.id, detail: { plan: b.plan, seats: b.seats }, ip: clientIpOf(req) });
  return { license: { id: l.id, key } };
});

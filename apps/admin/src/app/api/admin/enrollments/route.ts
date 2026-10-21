import { z } from 'zod';
import { audit } from '@/lib/audit';
import { newCode } from '@/lib/codes';
import { hmac } from '@/lib/crypto';
import { q } from '@/lib/db';
import { body, clientIpOf, csrfOf, handle } from '@/lib/http';
import { authorize } from '@/lib/session';

export const runtime = 'nodejs';

const Req = z.strictObject({ orgId: z.string().uuid(), hoursValid: z.number().int().min(1).max(168).default(24) });

/** One-time enrollment code for a device. Shown once; only its HMAC is stored. */
export const POST = handle(async (req) => {
  const { orgId, hoursValid } = await body(req, Req);
  const p = await authorize({ perm: 'device:manage', orgId, csrf: csrfOf(req) });
  const [org] = await q('SELECT 1 FROM organizations WHERE id = $1', [orgId]);
  if (!org) return new Response(JSON.stringify({ error: { code: 'not_found', message: 'Not found' } }), { status: 404, headers: { 'content-type': 'application/json' } });
  const code = newCode('SX', 4, 4);
  await q(
    `INSERT INTO device_enrollments(org_id, code_hash, created_by, expires_at) VALUES ($1,$2,$3, now() + make_interval(hours => $4))`,
    [orgId, hmac(code), p.userId, hoursValid],
  );
  await audit({ actorId: p.userId, actorEmail: p.email, orgId, action: 'enrollment.create', detail: { hoursValid }, ip: clientIpOf(req) });
  return { code, expiresInHours: hoursValid };
});

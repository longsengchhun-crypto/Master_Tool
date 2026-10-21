import { randomUUID } from 'node:crypto';
import { EnrollRequest } from '@sentrix/contracts';
import { audit } from '@/lib/audit';
import { normalizeCode } from '@/lib/codes';
import { hmac, randomToken } from '@/lib/crypto';
import { tx } from '@/lib/db';
import { policyForOrg } from '@/lib/device-support';
import { body, clientIpOf, handle } from '@/lib/http';
import { allow } from '@/lib/ratelimit';
import { HttpError } from '@/lib/session';

export const runtime = 'nodejs';

/**
 * Exchange a one-time enrollment code for a device credential. Requires an available license seat. The credential is
 * returned once; only its HMAC is stored.
 */
export const POST = handle(
  async (req) => {
    const ip = clientIpOf(req) ?? 'unknown';
    if (!(await allow(`enroll:ip:${ip}`, 12, 600))) throw new HttpError(429, 'Too many enrollment attempts. Try again later.', 'rate_limited');
    const b = await body(req, EnrollRequest);
    const codeHash = hmac(normalizeCode(b.code));

    const out = await tx(async (c) => {
      const e = await c.query<{ id: string; org_id: string }>(
        'SELECT id, org_id FROM device_enrollments WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now() FOR UPDATE',
        [codeHash],
      );
      if (!e.rows[0]) throw new HttpError(400, 'That enrollment code is invalid or has expired.', 'invalid_code');
      const orgId = e.rows[0].org_id;

      const lic = await c.query<{ id: string; plan: string; expires_at: string | null }>(
        `SELECT l.id, l.plan, l.expires_at FROM licenses l
          WHERE l.org_id = $1 AND l.status = 'active' AND (l.expires_at IS NULL OR l.expires_at > now())
            AND l.seats > (SELECT count(*) FROM license_activations a WHERE a.license_id = l.id)
          ORDER BY l.expires_at NULLS LAST LIMIT 1 FOR UPDATE`,
        [orgId],
      );
      if (!lic.rows[0]) throw new HttpError(402, 'This organization has no available license seat.', 'no_license_seat');

      const id = randomUUID();
      const token = `dev_${id}.${randomToken(32)}`;
      await c.query(
        `INSERT INTO devices(id, org_id, hostname, os, os_version, app_version, token_hash, last_seen_at) VALUES ($1,$2,$3,$4,$5,$6,$7, now())`,
        [id, orgId, b.hostname, b.os, b.osVersion ?? null, b.appVersion, hmac(token)],
      );
      await c.query('INSERT INTO license_activations(license_id, device_id) VALUES ($1,$2)', [lic.rows[0].id, id]);
      await c.query('UPDATE device_enrollments SET used_at = now(), device_id = $2 WHERE id = $1', [e.rows[0].id, id]);
      const org = await c.query<{ name: string }>('SELECT name FROM organizations WHERE id = $1', [orgId]);
      await audit({ actorEmail: `device:${b.hostname}`, orgId, action: 'device.enroll', target: id, detail: { os: b.os, appVersion: b.appVersion }, ip }, c);
      return { id, token, orgId, orgName: org.rows[0].name, plan: lic.rows[0].plan, expiresAt: lic.rows[0].expires_at };
    });

    return {
      deviceId: out.id,
      token: out.token,
      org: { id: out.orgId, name: out.orgName },
      license: { plan: out.plan, expiresAt: out.expiresAt },
      policy: await policyForOrg(out.orgId),
    };
  },
  { cookieAuth: false },
);

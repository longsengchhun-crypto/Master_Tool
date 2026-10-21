import { z } from 'zod';
import { audit } from '@/lib/audit';
import { q, tx } from '@/lib/db';
import { body, clientIpOf, csrfOf, handle } from '@/lib/http';
import { hashPassword, passwordProblem } from '@/lib/password';
import { authorize, HttpError } from '@/lib/session';

export const runtime = 'nodejs';

export const GET = handle(async () => {
  await authorize({ perm: 'user:manage_roles' });
  const rows = await q(
    `SELECT u.id, u.email, u.name, u.platform_role::text AS platform_role, u.is_active, u.mfa_enabled, u.created_at,
            COALESCE((SELECT json_agg(json_build_object('orgId', m.org_id, 'org', o.name, 'role', m.role::text))
                        FROM memberships m JOIN organizations o ON o.id = m.org_id WHERE m.user_id = u.id), '[]') AS memberships
       FROM users u ORDER BY u.created_at DESC LIMIT 500`,
  );
  return { users: rows };
});

const Create = z
  .strictObject({
    email: z.string().email().max(254),
    name: z.string().trim().min(1).max(120),
    password: z.string().min(12).max(256),
    platformRole: z.enum(['super_admin', 'security_admin', 'support', 'auditor']).optional(),
    orgId: z.string().uuid().optional(),
    orgRole: z.enum(['org_admin', 'member']).optional(),
  })
  .refine((v) => !!v.platformRole !== !!v.orgId, { message: 'Provide either platformRole or orgId (with orgRole), not both' });

/** Super Administrators create accounts; the new user must enroll MFA at first sign-in (it is mandatory for every admin role). */
export const POST = handle(async (req) => {
  const p = await authorize({ perm: 'user:manage_roles', csrf: csrfOf(req) });
  const b = await body(req, Create);
  const problem = passwordProblem(b.password);
  if (problem) throw new HttpError(400, problem, 'weak_password');
  const hash = await hashPassword(b.password);
  try {
    const id = await tx(async (c) => {
      const r = await c.query<{ id: string }>('INSERT INTO users(email, name, password_hash, platform_role) VALUES ($1,$2,$3,$4) RETURNING id', [b.email.toLowerCase(), b.name, hash, b.platformRole ?? null]);
      if (b.orgId) {
        await c.query('INSERT INTO memberships(user_id, org_id, role) VALUES ($1,$2,$3)', [r.rows[0].id, b.orgId, b.orgRole ?? 'member']);
      }
      await audit({ actorId: p.userId, actorEmail: p.email, orgId: b.orgId ?? null, action: 'user.create', target: r.rows[0].id, detail: { email: b.email.toLowerCase(), platformRole: b.platformRole ?? null, orgRole: b.orgRole ?? null }, ip: clientIpOf(req) }, c);
      return r.rows[0].id;
    });
    return { user: { id } };
  } catch (e) {
    const code = (e as { code?: string }).code;
    if (code === '23505') throw new HttpError(409, 'A user with that email already exists', 'duplicate');
    if (code === '23503') throw new HttpError(404, 'Organization not found', 'not_found');
    throw e;
  }
});

import { z } from 'zod';
import { audit } from '@/lib/audit';
import { tx } from '@/lib/db';
import { body, clientIpOf, csrfOf, handle, uuidParam } from '@/lib/http';
import { authorize, HttpError } from '@/lib/session';

export const runtime = 'nodejs';

const Patch = z.strictObject({
  platformRole: z.enum(['super_admin', 'security_admin', 'support', 'auditor']).nullable().optional(),
  isActive: z.boolean().optional(),
  resetMfa: z.literal(true).optional(),
});

/** Role changes, deactivation and MFA reset. Each is audited; the last active Super Administrator can never be removed. */
export const PATCH = handle(async (req, ctx: { params: Promise<{ id: string }> }) => {
  const p = await authorize({ perm: 'user:manage_roles', csrf: csrfOf(req) });
  const id = uuidParam((await ctx.params).id);
  const b = await body(req, Patch);
  const isSelf = id === p.userId;

  await tx(async (c) => {
    const cur = await c.query<{ email: string; platform_role: string | null; is_active: boolean }>('SELECT email, platform_role::text, is_active FROM users WHERE id = $1 FOR UPDATE', [id]);
    const u = cur.rows[0];
    if (!u) throw new HttpError(404, 'Not found', 'not_found');

    const losingSuper = u.platform_role === 'super_admin' && ((b.platformRole !== undefined && b.platformRole !== 'super_admin') || b.isActive === false);
    if (isSelf && (b.platformRole !== undefined || b.isActive === false)) {
      throw new HttpError(409, 'You cannot change your own role or deactivate yourself', 'self_change');
    }
    if (losingSuper) {
      const n = await c.query<{ n: string }>("SELECT count(*) AS n FROM users WHERE platform_role = 'super_admin' AND is_active AND id <> $1", [id]);
      if (Number(n.rows[0].n) < 1) throw new HttpError(409, 'There must always be at least one active Super Administrator', 'last_super_admin');
    }

    if (b.platformRole !== undefined) await c.query('UPDATE users SET platform_role = $2, updated_at = now() WHERE id = $1', [id, b.platformRole]);
    if (b.isActive !== undefined) {
      await c.query('UPDATE users SET is_active = $2, updated_at = now() WHERE id = $1', [id, b.isActive]);
      if (!b.isActive) await c.query('DELETE FROM sessions WHERE user_id = $1', [id]);
    }
    if (b.resetMfa) {
      await c.query("UPDATE users SET mfa_enabled = false, mfa_secret = NULL, mfa_recovery = '{}', updated_at = now() WHERE id = $1", [id]);
      await c.query('DELETE FROM sessions WHERE user_id = $1', [id]);
    }
    await audit({ actorId: p.userId, actorEmail: p.email, action: 'user.update', target: id, detail: { email: u.email, change: b, previousRole: u.platform_role }, ip: clientIpOf(req) }, c);
  });
  return { ok: true };
});

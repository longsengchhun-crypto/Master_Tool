import { z } from 'zod';
import { audit } from '@/lib/audit';
import { safeEqual } from '@/lib/crypto';
import { q } from '@/lib/db';
import { body, clientIpOf, csrfOf, handle } from '@/lib/http';
import { verifyPassword } from '@/lib/password';
import { allow } from '@/lib/ratelimit';
import { currentPrincipal, HttpError } from '@/lib/session';

export const runtime = 'nodejs';

const Req = z.strictObject({ password: z.string().min(1).max(256) });

/** Re-enter the password to unlock sensitive actions (revocations, policy writes, release publishing) for 10 minutes. */
export const POST = handle(async (req) => {
  const p = await currentPrincipal();
  if (!p) throw new HttpError(401, 'Authentication required', 'unauthenticated');
  const t = csrfOf(req);
  if (!t || !safeEqual(t, p.csrf)) throw new HttpError(403, 'Bad CSRF token', 'csrf');
  if (!(await allow(`reauth:${p.userId}`, 6, 600))) throw new HttpError(429, 'Too many attempts', 'rate_limited');

  const { password } = await body(req, Req);
  const rows = await q<{ password_hash: string }>('SELECT password_hash FROM users WHERE id = $1', [p.userId]);
  if (!rows[0] || !(await verifyPassword(rows[0].password_hash, password))) {
    await audit({ actorId: p.userId, actorEmail: p.email, action: 'auth.reauth_failed', ip: clientIpOf(req) });
    throw new HttpError(401, 'Incorrect password.', 'invalid_credentials');
  }
  await q('UPDATE sessions SET reauth_at = now() WHERE id = $1', [p.sessionId]);
  await audit({ actorId: p.userId, actorEmail: p.email, action: 'auth.reauth', ip: clientIpOf(req) });
  return { ok: true };
});

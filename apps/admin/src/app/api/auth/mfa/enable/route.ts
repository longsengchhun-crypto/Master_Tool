import { z } from 'zod';
import { audit } from '@/lib/audit';
import { open, safeEqual } from '@/lib/crypto';
import { q } from '@/lib/db';
import { body, csrfOf, handle } from '@/lib/http';
import { allow } from '@/lib/ratelimit';
import { currentPrincipal, HttpError } from '@/lib/session';
import { newRecoveryCodes, totpValid } from '@/lib/totp';

export const runtime = 'nodejs';

const Req = z.strictObject({ token: z.string().regex(/^\d{6}$/) });

export const POST = handle(async (req) => {
  const p = await currentPrincipal();
  if (!p) throw new HttpError(401, 'Authentication required', 'unauthenticated');
  const t = csrfOf(req);
  if (!t || !safeEqual(t, p.csrf)) throw new HttpError(403, 'Bad CSRF token', 'csrf');
  if (p.mfaEnabled) throw new HttpError(409, 'MFA is already enabled.', 'mfa_already_enabled');
  if (!(await allow(`mfa-enable:${p.userId}`, 8, 600))) throw new HttpError(429, 'Too many attempts', 'rate_limited');

  const { token } = await body(req, Req);
  const rows = await q<{ mfa_secret: string | null }>('SELECT mfa_secret FROM users WHERE id = $1', [p.userId]);
  const sealed = rows[0]?.mfa_secret;
  if (!sealed) throw new HttpError(409, 'Start MFA setup first.', 'mfa_not_started');
  if (!(await totpValid(open(sealed), token))) throw new HttpError(400, 'That code is not correct.', 'invalid_mfa');

  const { plain, hashes } = newRecoveryCodes();
  await q('UPDATE users SET mfa_enabled = true, mfa_recovery = $2 WHERE id = $1', [p.userId, hashes]);
  await q('UPDATE sessions SET mfa_verified = true WHERE id = $1', [p.sessionId]);
  await audit({ actorId: p.userId, actorEmail: p.email, action: 'auth.mfa_enabled' });
  // Recovery codes are shown exactly once.
  return { ok: true, recoveryCodes: plain };
});

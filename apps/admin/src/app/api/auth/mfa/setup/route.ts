import { audit } from '@/lib/audit';
import { seal } from '@/lib/crypto';
import { q } from '@/lib/db';
import { csrfOf, handle } from '@/lib/http';
import { currentPrincipal, HttpError } from '@/lib/session';
import { safeEqual } from '@/lib/crypto';
import { newTotpSecret, totpUri } from '@/lib/totp';

export const runtime = 'nodejs';

/** Begin MFA enrollment: stores a *pending* sealed secret; MFA is only enabled once a valid code is presented. */
export const POST = handle(async (req) => {
  const p = await currentPrincipal();
  if (!p) throw new HttpError(401, 'Authentication required', 'unauthenticated');
  const t = csrfOf(req);
  if (!t || !safeEqual(t, p.csrf)) throw new HttpError(403, 'Bad CSRF token', 'csrf');
  if (p.mfaEnabled) throw new HttpError(409, 'MFA is already enabled. Ask a Super Administrator to reset it.', 'mfa_already_enabled');

  const secret = newTotpSecret();
  await q('UPDATE users SET mfa_secret = $2, mfa_enabled = false WHERE id = $1', [p.userId, seal(secret)]);
  await audit({ actorId: p.userId, actorEmail: p.email, action: 'auth.mfa_setup_started' });
  return { secret, uri: totpUri(secret, p.email) };
});

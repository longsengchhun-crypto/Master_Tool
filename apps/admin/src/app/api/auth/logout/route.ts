import { audit } from '@/lib/audit';
import { csrfOf, handle } from '@/lib/http';
import { currentPrincipal, destroySession, HttpError } from '@/lib/session';
import { safeEqual } from '@/lib/crypto';

export const runtime = 'nodejs';

export const POST = handle(async (req) => {
  const p = await currentPrincipal();
  if (p) {
    const t = csrfOf(req);
    if (!t || !safeEqual(t, p.csrf)) throw new HttpError(403, 'Bad CSRF token', 'csrf');
    await audit({ actorId: p.userId, actorEmail: p.email, action: 'auth.logout' });
  }
  await destroySession();
  return { ok: true };
});

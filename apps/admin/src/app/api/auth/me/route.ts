import { handle } from '@/lib/http';
import { currentPrincipal, HttpError } from '@/lib/session';

export const runtime = 'nodejs';

export const GET = handle(async () => {
  const p = await currentPrincipal();
  if (!p) throw new HttpError(401, 'Authentication required', 'unauthenticated');
  return { email: p.email, name: p.name, role: p.role, mfaEnabled: p.mfaEnabled, mfaVerified: p.mfaVerified, reauthFresh: p.reauthFresh, csrf: p.csrf };
});

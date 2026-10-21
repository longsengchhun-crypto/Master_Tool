import { LoginRequest } from '@sentrix/contracts';
import { audit } from '@/lib/audit';
import { q } from '@/lib/db';
import { body, clientIpOf, handle } from '@/lib/http';
import { burnVerify, verifyPassword } from '@/lib/password';
import { allow } from '@/lib/ratelimit';
import { createSession, HttpError } from '@/lib/session';
import { open } from '@/lib/crypto';
import { hashRecovery, totpValid } from '@/lib/totp';
import { sha256 } from '@/lib/crypto';

export const runtime = 'nodejs';

interface UserRow {
  id: string;
  email: string;
  name: string;
  password_hash: string;
  platform_role: string | null;
  is_active: boolean;
  mfa_enabled: boolean;
  mfa_secret: string | null;
  mfa_recovery: string[];
  is_org_admin: boolean;
}

const GENERIC = 'Invalid email or password.';

export const POST = handle(async (req) => {
  const { email, password, totp } = await body(req, LoginRequest);
  const ip = clientIpOf(req);
  const em = email.toLowerCase();

  // Limits apply whether or not the account exists, so lockout cannot be used to enumerate users.
  if (!(await allow(`login:ip:${ip ?? 'unknown'}`, 40, 600)) || !(await allow(`login:em:${sha256(em)}`, 8, 900))) {
    throw new HttpError(429, 'Too many sign-in attempts. Try again in a few minutes.', 'rate_limited');
  }

  const rows = await q<UserRow>(
    `SELECT u.id, u.email, u.name, u.password_hash, u.platform_role, u.is_active, u.mfa_enabled, u.mfa_secret, u.mfa_recovery,
            EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = u.id AND m.role = 'org_admin') AS is_org_admin
       FROM users u WHERE u.email = $1`,
    [em],
  );
  const u = rows[0];
  if (!u || !u.is_active) {
    await burnVerify(password);
    await audit({ action: 'auth.login_failed', actorEmail: em, detail: { reason: 'unknown_or_inactive' }, ip });
    throw new HttpError(401, GENERIC, 'invalid_credentials');
  }
  if (!(await verifyPassword(u.password_hash, password))) {
    await audit({ actorId: u.id, actorEmail: em, action: 'auth.login_failed', detail: { reason: 'bad_password' }, ip });
    throw new HttpError(401, GENERIC, 'invalid_credentials');
  }

  const isAdmin = !!u.platform_role || u.is_org_admin;
  if (!isAdmin) {
    // Customers without an administrative role have no console access.
    await audit({ actorId: u.id, actorEmail: em, action: 'auth.login_denied', detail: { reason: 'no_role' }, ip });
    throw new HttpError(403, 'This account does not have console access.', 'no_access');
  }

  let mfaVerified = false;
  if (u.mfa_enabled && u.mfa_secret) {
    if (!totp) return { mfaRequired: true };
    if (!(await allow(`login:mfa:${u.id}`, 6, 600))) throw new HttpError(429, 'Too many code attempts. Try again later.', 'rate_limited');
    const secret = open(u.mfa_secret);
    let ok = await totpValid(secret, totp);
    if (!ok && /^[0-9a-f]{4}(-[0-9a-f]{4}){3}$/i.test(totp)) {
      // Recovery code path: single use.
      const h = hashRecovery(totp);
      if (u.mfa_recovery.includes(h)) {
        await q('UPDATE users SET mfa_recovery = array_remove(mfa_recovery, $2) WHERE id = $1', [u.id, h]);
        ok = true;
        await audit({ actorId: u.id, actorEmail: em, action: 'auth.recovery_code_used', ip });
      }
    }
    if (!ok) {
      await audit({ actorId: u.id, actorEmail: em, action: 'auth.mfa_failed', ip });
      throw new HttpError(401, 'Invalid verification code.', 'invalid_mfa');
    }
    mfaVerified = true;
  }

  await createSession(u.id, mfaVerified, ip, req.headers.get('user-agent'));
  await audit({ actorId: u.id, actorEmail: em, action: 'auth.login', detail: { mfa: mfaVerified }, ip });
  return { ok: true, mfaSetupRequired: !u.mfa_enabled };
});

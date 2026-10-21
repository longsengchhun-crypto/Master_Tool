import { cookies, headers } from 'next/headers';
import { q } from './db';
import { randomToken, safeEqual, sha256 } from './crypto';
import { can, requiresMfa, SENSITIVE, type Permission, type Role } from './rbac';

const COOKIE = '__Host-sx_session';
const TTL_HOURS = 8;
const REAUTH_MINUTES = 10;

export interface Principal {
  sessionId: string;
  userId: string;
  email: string;
  name: string;
  role: Role | null;          // effective role for authorization
  orgIds: string[];           // organizations an org_admin may act on (platform roles ignore this)
  mfaEnabled: boolean;
  mfaVerified: boolean;
  reauthFresh: boolean;
  csrf: string;
}

export async function createSession(userId: string, mfaVerified: boolean, ip: string | null, ua: string | null) {
  const token = randomToken(32);
  const csrf = randomToken(24);
  await q(
    `INSERT INTO sessions(id, user_id, expires_at, mfa_verified, reauth_at, csrf_token, ip, user_agent)
     VALUES ($1,$2, now() + make_interval(hours => $3), $4, now(), $5, $6, $7)`,
    [sha256(token), userId, TTL_HOURS, mfaVerified, csrf, ip, ua?.slice(0, 300) ?? null],
  );
  const jar = await cookies();
  jar.set(COOKIE, token, { httpOnly: true, secure: true, sameSite: 'strict', path: '/', maxAge: TTL_HOURS * 3600 });
}

export async function destroySession() {
  const jar = await cookies();
  const t = jar.get(COOKIE)?.value;
  if (t) await q('DELETE FROM sessions WHERE id = $1', [sha256(t)]);
  jar.delete(COOKIE);
}

export async function currentPrincipal(): Promise<Principal | null> {
  const t = (await cookies()).get(COOKIE)?.value;
  if (!t) return null;
  const rows = await q<{
    id: string; user_id: string; email: string; name: string; platform_role: Role | null; mfa_enabled: boolean;
    mfa_verified: boolean; csrf_token: string; fresh: boolean; org_roles: { org_id: string; role: string }[];
  }>(
    `SELECT s.id, s.user_id, u.email, u.name, u.platform_role, u.mfa_enabled, s.mfa_verified, s.csrf_token,
            (s.reauth_at IS NOT NULL AND s.reauth_at > now() - make_interval(mins => $2)) AS fresh,
            COALESCE((SELECT json_agg(json_build_object('org_id', m.org_id, 'role', m.role)) FROM memberships m WHERE m.user_id = u.id), '[]') AS org_roles
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.id = $1 AND s.expires_at > now() AND u.is_active`,
    [sha256(t), REAUTH_MINUTES],
  );
  const r = rows[0];
  if (!r) return null;
  const adminOrgs = r.org_roles.filter((m) => m.role === 'org_admin').map((m) => m.org_id);
  const role: Role | null = r.platform_role ?? (adminOrgs.length ? 'org_admin' : null);
  return {
    sessionId: r.id, userId: r.user_id, email: r.email, name: r.name, role, orgIds: adminOrgs,
    mfaEnabled: r.mfa_enabled, mfaVerified: r.mfa_verified, reauthFresh: r.fresh, csrf: r.csrf_token,
  };
}

export class HttpError extends Error {
  constructor(public status: number, message: string, public code = 'error') { super(message); }
}

export interface AuthorizeOpts {
  perm: Permission;
  /** Resource's organization. If given, out-of-scope access is a 404 (not 403) so IDs cannot be probed across tenants. */
  orgId?: string | null;
  /** Value of the x-csrf-token header. Pass it (even if null) on every state-changing request. */
  csrf?: string | null;
}

/** Platform roles act across organizations; org_admin only inside organizations they administer. */
export function inScope(p: Principal, orgId: string | null | undefined): boolean {
  if (p.role !== 'org_admin') return true;
  return !!orgId && p.orgIds.includes(orgId);
}

/** Org ids a list query must be restricted to, or null for "all organizations". */
export function scopeIds(p: Principal): string[] | null {
  return p.role === 'org_admin' ? p.orgIds : null;
}

/**
 * Single choke-point for admin API authorization. Order matters: authenticate, MFA, role,
 * CSRF, re-authentication for sensitive permissions, then tenant scope.
 */
export async function authorize(o: AuthorizeOpts): Promise<Principal> {
  const p = await currentPrincipal();
  if (!p) throw new HttpError(401, 'Authentication required', 'unauthenticated');
  if (requiresMfa(p.role) && !(p.mfaEnabled && p.mfaVerified)) throw new HttpError(403, 'MFA required', 'mfa_required');
  if (!can(p.role, o.perm)) throw new HttpError(403, 'Forbidden', 'forbidden');
  if (o.csrf !== undefined && !(o.csrf && safeEqual(o.csrf, p.csrf))) throw new HttpError(403, 'Bad CSRF token', 'csrf');
  if (SENSITIVE.has(o.perm) && !p.reauthFresh) throw new HttpError(403, 'Re-enter your password to continue', 'reauth_required');
  if (o.orgId !== undefined && !inScope(p, o.orgId)) throw new HttpError(404, 'Not found', 'not_found');
  return p;
}

/** For handlers that load the resource first and learn its org afterwards. */
export function assertScope(p: Principal, orgId: string | null | undefined): void {
  if (!inScope(p, orgId)) throw new HttpError(404, 'Not found', 'not_found');
}

export async function clientIp(): Promise<string | null> {
  const h = await headers();
  return h.get('x-forwarded-for')?.split(',')[0]?.trim() || h.get('x-real-ip') || null;
}

import { randomBytes } from 'node:crypto';
import { describe, expect, it, beforeAll } from 'vitest';
import { rolloutBucket } from '@/lib/device-support';
import { totpNow } from '@/lib/totp';
import { Client, HEARTBEAT, enrollDevice, seedLicense, seedOrg, seedUser, signIn, sql, type SeedUser } from './helpers';

let orgA: string, orgB: string;
let superU: SeedUser, secU: SeedUser, supportU: SeedUser, auditorU: SeedUser, adminAU: SeedUser, adminBU: SeedUser, customerU: SeedUser, noMfaU: SeedUser;
let sup: Client, sec: Client, support: Client, auditor: Client, adminA: Client, adminB: Client;
let devA: Awaited<ReturnType<typeof enrollDevice>>, devB: Awaited<ReturnType<typeof enrollDevice>>;

beforeAll(async () => {
  orgA = await seedOrg('Org A');
  orgB = await seedOrg('Org B');
  await seedLicense(orgA, 5);
  await seedLicense(orgB, 5);
  superU = await seedUser({ name: 'Super', platformRole: 'super_admin' });
  secU = await seedUser({ name: 'Sec', platformRole: 'security_admin' });
  supportU = await seedUser({ name: 'Support', platformRole: 'support' });
  auditorU = await seedUser({ name: 'Auditor', platformRole: 'auditor' });
  adminAU = await seedUser({ name: 'AdminA', orgId: orgA, orgRole: 'org_admin' });
  adminBU = await seedUser({ name: 'AdminB', orgId: orgB, orgRole: 'org_admin' });
  customerU = await seedUser({ name: 'Customer', orgId: orgA, orgRole: 'member', mfa: false });
  noMfaU = await seedUser({ name: 'NoMfa', platformRole: 'support', mfa: false });
  [sup, sec, support, auditor, adminA, adminB] = await Promise.all([superU, secU, supportU, auditorU, adminAU, adminBU].map(signIn));
  devA = await enrollDevice(sup, orgA, 'PC-A');
  devB = await enrollDevice(sup, orgB, 'PC-B');
});

const ADMIN_GETS = ['/api/admin/overview', '/api/admin/devices', '/api/admin/orgs', '/api/admin/licenses', '/api/admin/policies', '/api/admin/releases', '/api/admin/users', '/api/admin/audit', '/api/admin/events'];

describe('authentication', () => {
  it('every admin endpoint rejects anonymous requests', async () => {
    const anon = new Client();
    for (const p of ADMIN_GETS) expect((await anon.req(p)).status, p).toBe(401);
    for (const [p, b] of [['/api/admin/orgs', { name: 'x' }], ['/api/admin/enrollments', { orgId: orgA }], ['/api/admin/licenses', {}], ['/api/admin/releases', {}], ['/api/admin/users', {}]] as const) {
      expect((await anon.req(p, { body: b })).status, p).toBe(401);
    }
  });

  it('wrong password and unknown email are indistinguishable', async () => {
    const c = new Client();
    const wrong = await c.req('/api/auth/login', { body: { email: superU.email, password: 'definitely-wrong-password' } });
    const unknown = await c.req('/api/auth/login', { body: { email: 'nobody@test.example', password: 'definitely-wrong-password' } });
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.json.error.message).toBe(unknown.json.error.message);
    expect(wrong.json.error.code).toBe(unknown.json.error.code);
  });

  it('brute force is rate-limited per account even when the attacker rotates IP addresses', async () => {
    const victim = await seedUser({ name: 'Victim', platformRole: 'support' });
    let limited = false;
    for (let i = 0; i < 14 && !limited; i++) {
      const c = new Client(); // new IP each attempt
      const r = await c.req('/api/auth/login', { body: { email: victim.email, password: `guess-${i}-xxxxxxxx` } });
      if (r.status === 429) limited = true;
    }
    expect(limited, 'account lockout never triggered').toBe(true);
    // Even the correct password is refused while limited.
    const ok = await new Client().req('/api/auth/login', { body: { email: victim.email, password: victim.password } });
    expect(ok.status).toBe(429);
  });

  it('SQL injection strings are inert', async () => {
    const c = new Client();
    for (const email of ["admin@test.example' OR '1'='1", "'; DROP TABLE users;--@x.io"]) {
      const r = await c.req('/api/auth/login', { body: { email, password: "' OR 1=1 --" } });
      expect([400, 401]).toContain(r.status);
    }
    const users = await sql('SELECT count(*)::int AS n FROM users');
    expect(users[0].n).toBeGreaterThan(5);
  });

  it('customers without an administrative role get no console access', async () => {
    const r = await new Client().login(customerU.email, customerU.password);
    expect(r.status).toBe(403);
    expect(r.json.error.code).toBe('no_access');
  });

  it('sessions are HttpOnly, Secure, SameSite=Strict and __Host- prefixed', async () => {
    const c = new Client();
    const res = await fetch(`${c.base}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': c.ip }, body: JSON.stringify({ email: secU.email, password: secU.password, totp: await totpNow(secU.totpSecret!) }) });
    const first = await res.json();
    const sc = (first.mfaRequired ? (await fetch(`${c.base}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': c.ip }, body: JSON.stringify({ email: secU.email, password: secU.password, totp: await totpNow(secU.totpSecret!) }) })).headers : res.headers).getSetCookie().join(';');
    expect(sc).toMatch(/__Host-sx_session=/);
    expect(sc).toMatch(/HttpOnly/i);
    expect(sc).toMatch(/Secure/i);
    expect(sc).toMatch(/SameSite=strict/i);
    expect(sc).toMatch(/Path=\//);
    expect(sc).not.toMatch(/Domain=/i);
  });

  it('logout destroys the server-side session', async () => {
    const u = await seedUser({ name: 'Logout', platformRole: 'auditor' });
    const c = await signIn(u);
    expect((await c.req('/api/admin/audit')).status).toBe(200);
    const stolen = c.cookie;
    expect((await c.req('/api/auth/logout', { body: {} })).status).toBe(200);
    const replay = new Client();
    replay.cookie = stolen;
    expect((await replay.req('/api/admin/audit')).status).toBe(401);
  });

  it('forged or garbage session cookies are rejected', async () => {
    for (const v of ['x', randomBytes(32).toString('base64url'), "' OR 1=1", 'a'.repeat(5000)]) {
      const c = new Client();
      c.cookie = v;
      expect((await c.req('/api/admin/overview')).status).toBe(401);
    }
  });

  it('deactivating a user kills their sessions immediately', async () => {
    const u = await seedUser({ name: 'Doomed', platformRole: 'auditor' });
    const c = await signIn(u);
    expect((await c.req('/api/admin/audit')).status).toBe(200);
    const r = await sup.req(`/api/admin/users/${u.id}`, { method: 'PATCH', body: { isActive: false } });
    expect(r.status).toBe(200);
    expect((await c.req('/api/admin/audit')).status).toBe(401);
  });
});

describe('multi-factor authentication', () => {
  it('an administrator without MFA is blocked from every admin API until they enroll', async () => {
    const c = new Client();
    const r = await c.login(noMfaU.email, noMfaU.password);
    expect(r.status).toBe(200);
    expect(r.json.mfaSetupRequired).toBe(true);
    for (const p of ADMIN_GETS) {
      const x = await c.req(p);
      expect(x.status, p).toBe(403);
      expect(x.json.error.code, p).toBe('mfa_required');
    }
  });

  it('full enrollment flow: setup, wrong code rejected, correct code enables, recovery codes shown once', async () => {
    const u = await seedUser({ name: 'Enroll', platformRole: 'auditor', mfa: false });
    const c = new Client();
    await c.login(u.email, u.password);
    const setup = await c.req('/api/auth/mfa/setup', { body: {} });
    expect(setup.status).toBe(200);
    expect(setup.json.secret).toMatch(/^[A-Z2-7]{16,}$/);
    expect((await c.req('/api/auth/mfa/enable', { body: { token: '000000' } })).status).toBe(400);
    const en = await c.req('/api/auth/mfa/enable', { body: { token: await totpNow(setup.json.secret) } });
    expect(en.status).toBe(200);
    expect(en.json.recoveryCodes).toHaveLength(10);
    expect((await c.req('/api/admin/audit')).status).toBe(200);
    // Secret is stored sealed, not in clear.
    const [row] = await sql('SELECT mfa_secret, mfa_recovery FROM users WHERE id = $1', [u.id]);
    expect(row.mfa_secret).not.toContain(setup.json.secret);
    expect(row.mfa_secret.startsWith('v1.')).toBe(true);
    expect(JSON.stringify(row.mfa_recovery)).not.toContain(en.json.recoveryCodes[0]);
    // Cannot re-run setup to replace an active secret.
    expect((await c.req('/api/auth/mfa/setup', { body: {} })).status).toBe(409);
  });

  it('login with MFA enrolled requires a valid code; recovery codes work exactly once', async () => {
    const u = await seedUser({ name: 'Rec', platformRole: 'auditor', mfa: false });
    const e = new Client();
    await e.login(u.email, u.password);
    const setup = await e.req('/api/auth/mfa/setup', { body: {} });
    const en = await e.req('/api/auth/mfa/enable', { body: { token: await totpNow(setup.json.secret) } });
    const rc: string = en.json.recoveryCodes[0];

    const c = new Client();
    const step1 = await c.login(u.email, u.password);
    expect(step1.json.mfaRequired).toBe(true);
    expect((await c.req('/api/admin/audit')).status, 'no session before MFA').toBe(401);
    expect((await c.login(u.email, u.password, '123456')).status).toBe(401);
    expect((await c.login(u.email, u.password, rc)).status).toBe(200);
    expect((await new Client().login(u.email, u.password, rc)).status, 'recovery code reuse').toBe(401);
  });
});

describe('CSRF and cross-origin protection', () => {
  it('state-changing requests without the CSRF token are rejected', async () => {
    const r = await sup.req('/api/admin/orgs', { body: { name: 'Nope Inc' }, csrf: false });
    expect(r.status).toBe(403);
    expect(r.json.error.code).toBe('csrf');
  });
  it('a wrong CSRF token is rejected', async () => {
    const r = await sup.req('/api/admin/orgs', { body: { name: 'Nope Inc' }, csrf: 'not-the-token' });
    expect(r.status).toBe(403);
  });
  it('another user\'s CSRF token is rejected', async () => {
    const r = await sup.req('/api/admin/orgs', { body: { name: 'Nope Inc' }, csrf: sec.csrf! });
    expect(r.status).toBe(403);
  });
  it('requests from a foreign Origin are rejected even with valid cookie + token', async () => {
    const r = await sup.req('/api/admin/orgs', { body: { name: 'Evil Inc' }, headers: { origin: 'https://evil.example' } });
    expect(r.status).toBe(403);
    expect(r.json.error.code).toBe('cross_origin');
    expect((await sql('SELECT 1 FROM organizations WHERE name = $1', ['Evil Inc'])).length).toBe(0);
  });
  it('GET endpoints never change state', async () => {
    const before = (await sql('SELECT count(*)::int AS n FROM audit_events'))[0].n;
    for (const p of ADMIN_GETS) await sup.req(p);
    expect((await sql('SELECT count(*)::int AS n FROM audit_events'))[0].n).toBe(before);
  });
});

describe('role-based access control', () => {
  it('auditor can read audit and devices but cannot change anything', async () => {
    expect((await auditor.req('/api/admin/audit')).status).toBe(200);
    expect((await auditor.req('/api/admin/devices')).status).toBe(200);
    expect((await auditor.req('/api/admin/orgs', { body: { name: 'x1' } })).status).toBe(403);
    expect((await auditor.req('/api/admin/enrollments', { body: { orgId: orgA } })).status).toBe(403);
    expect((await auditor.req(`/api/admin/devices/${devA.deviceId}/jobs`, { body: { kind: 'scan_quick' } })).status).toBe(403);
    expect((await auditor.req(`/api/admin/devices/${devA.deviceId}/revoke`, { body: {} })).status).toBe(403);
    expect((await auditor.req('/api/admin/users')).status).toBe(403);
  });

  it('support operator can view but not manage', async () => {
    expect((await support.req('/api/admin/devices')).status).toBe(200);
    expect((await support.req('/api/admin/audit')).status).toBe(403);
    expect((await support.req('/api/admin/enrollments', { body: { orgId: orgA } })).status).toBe(403);
    expect((await support.req('/api/admin/policies', { method: 'PUT', body: { orgId: orgA, config: {} } })).status).toBe(403);
  });

  it('security administrator cannot manage users, licenses, orgs or release publishing', async () => {
    expect((await sec.req('/api/admin/users')).status).toBe(403);
    expect((await sec.req('/api/admin/licenses', { body: { orgId: orgA, seats: 1 } })).status).toBe(403);
    expect((await sec.req('/api/admin/orgs', { body: { name: 'x2' } })).status).toBe(403);
    expect((await sec.req('/api/admin/releases', { body: { version: '9.9.9', platform: 'windows-x64' } })).status).toBe(403);
  });

  it('org administrator cannot reach platform-only areas', async () => {
    for (const p of ['/api/admin/users', '/api/admin/releases']) expect((await adminA.req(p)).status, p).toBe(403);
    expect((await adminA.req('/api/admin/orgs', { body: { name: 'x3' } })).status).toBe(403);
    expect((await adminA.req('/api/admin/licenses', { body: { orgId: orgA, seats: 99 } })).status).toBe(403);
  });
});

describe('cross-organization isolation', () => {
  it('lists only show the caller\'s organization', async () => {
    const a = await adminA.req('/api/admin/devices');
    expect(a.status).toBe(200);
    const ids = a.json.devices.map((d: any) => d.id);
    expect(ids).toContain(devA.deviceId);
    expect(ids).not.toContain(devB.deviceId);
    const orgs = (await adminA.req('/api/admin/orgs')).json.organizations.map((o: any) => o.id);
    expect(orgs).toEqual([orgA]);
    const lic = (await adminA.req('/api/admin/licenses')).json.licenses;
    expect(lic.every((l: any) => l.org_id === orgA)).toBe(true);
    const audit = (await adminA.req('/api/admin/audit?limit=500')).json.events;
    expect(audit.every((e: any) => e.org_id === orgA)).toBe(true);
  });

  it('another organization\'s device is a 404, not a 403 (no existence oracle)', async () => {
    expect((await adminA.req(`/api/admin/devices/${devB.deviceId}`)).status).toBe(404);
    expect((await adminA.req(`/api/admin/devices/${'0'.repeat(8)}-0000-4000-8000-${'0'.repeat(12)}`)).status).toBe(404);
  });

  it('cannot revoke, command, enroll into, or write policy for another organization', async () => {
    expect((await adminA.req(`/api/admin/devices/${devB.deviceId}/revoke`, { body: {} })).status).toBe(404);
    expect((await adminA.req(`/api/admin/devices/${devB.deviceId}/jobs`, { body: { kind: 'scan_quick' } })).status).toBe(404);
    expect((await adminA.req('/api/admin/enrollments', { body: { orgId: orgB } })).status).toBe(404);
    expect((await adminA.req('/api/admin/policies', { method: 'PUT', body: { orgId: orgB, config: {} } })).status).toBe(404);
    const [d] = await sql('SELECT status FROM devices WHERE id = $1', [devB.deviceId]);
    expect(d.status).toBe('enrolled');
  });

  it('an org admin can manage their own organization', async () => {
    expect((await adminA.req(`/api/admin/devices/${devA.deviceId}`)).status).toBe(200);
    expect((await adminA.req('/api/admin/enrollments', { body: { orgId: orgA } })).status).toBe(200);
    const p = await adminA.req('/api/admin/policies', { method: 'PUT', body: { orgId: orgA, config: { autoQuarantine: 'off' } } });
    expect(p.status).toBe(200);
  });

  it('overview metrics are scoped too', async () => {
    const a = (await adminA.req('/api/admin/overview')).json;
    const all = (await sup.req('/api/admin/overview')).json;
    expect(Number(a.operational.fleet.enrolled)).toBeLessThan(Number(all.operational.fleet.enrolled));
    expect(a.releases).toEqual([]);
  });
});

describe('re-authentication for sensitive actions', () => {
  it('a stale session cannot revoke devices, publish releases or create licenses until the password is re-entered', async () => {
    const u = await seedUser({ name: 'Stale', platformRole: 'super_admin' });
    const c = await signIn(u);
    await sql(`UPDATE sessions SET reauth_at = now() - interval '2 hours' WHERE user_id = $1`, [u.id]);
    const r1 = await c.req('/api/admin/licenses', { body: { orgId: orgA, seats: 1 } });
    expect(r1.status).toBe(403);
    expect(r1.json.error.code).toBe('reauth_required');
    expect((await c.req('/api/admin/releases', { body: { version: '7.7.7', platform: 'windows-x64' } })).json.error.code).toBe('reauth_required');
    // Wrong password does not unlock.
    expect((await c.req('/api/auth/reauth', { body: { password: 'wrong-password-123' } })).status).toBe(401);
    expect((await c.req('/api/admin/licenses', { body: { orgId: orgA, seats: 1 } })).status).toBe(403);
    // Correct password does.
    expect((await c.req('/api/auth/reauth', { body: { password: u.password } })).status).toBe(200);
    expect((await c.req('/api/admin/licenses', { body: { orgId: orgA, seats: 1 } })).status).toBe(200);
  });
});

describe('input validation', () => {
  it('rejects malformed JSON, unknown fields, wrong types and oversized bodies', async () => {
    expect((await sup.req('/api/admin/orgs', { rawBody: '{not json' })).status).toBe(400);
    expect((await sup.req('/api/admin/orgs', { body: { name: 'ok', isAdmin: true } })).status).toBe(400);
    expect((await sup.req('/api/admin/orgs', { body: { name: 123 } })).status).toBe(400);
    expect((await sup.req('/api/admin/orgs', { body: { name: 'a'.repeat(400_000) } })).status).toBe(413);
  });

  it('malformed ids are treated as not found, never reaching the database', async () => {
    for (const id of ['abc', '1; DROP TABLE devices', '../../etc/passwd', '%00']) {
      expect((await sup.req(`/api/admin/devices/${encodeURIComponent(id)}`)).status, id).toBe(404);
    }
  });

  it('policy writes reject anything outside the closed schema', async () => {
    for (const config of [{ runCommand: 'calc.exe' }, { autoQuarantine: 'all' }, { maxFileSizeMb: 99999 }, { monitoredFolders: ['C:/Windows'] }]) {
      expect((await sup.req('/api/admin/policies', { method: 'PUT', body: { orgId: orgA, config } })).status, JSON.stringify(config)).toBe(400);
    }
  });

  it('weak passwords are refused when creating administrators', async () => {
    const r = await sup.req('/api/admin/users', { body: { email: 'weak@test.example', name: 'Weak', password: 'short', platformRole: 'auditor' } });
    expect(r.status).toBe(400);
  });

  it('error responses never leak stack traces or SQL', async () => {
    const r = await sup.req('/api/admin/licenses', { body: { orgId: '00000000-0000-4000-8000-000000000000', seats: 1 } });
    expect(JSON.stringify(r.json)).not.toMatch(/at .*\.(js|ts)|SELECT |INSERT |violates|constraint|pg_/i);
  });
});

describe('user administration safeguards', () => {
  it('nobody can demote or deactivate themselves', async () => {
    for (const body of [{ isActive: false }, { platformRole: 'auditor' }, { platformRole: null }]) {
      const r = await sup.req(`/api/admin/users/${superU.id}`, { method: 'PATCH', body });
      expect(r.status, JSON.stringify(body)).toBe(409);
      expect(r.json.error.code).toBe('self_change');
    }
    const [u] = await sql('SELECT platform_role, is_active FROM users WHERE id = $1', [superU.id]);
    expect(u).toMatchObject({ platform_role: 'super_admin', is_active: true });
  });

  it('one Super Administrator can demote another while at least one stays active', async () => {
    const other = await seedUser({ name: 'Other', platformRole: 'super_admin' });
    const r = await sup.req(`/api/admin/users/${other.id}`, { method: 'PATCH', body: { platformRole: 'auditor' } });
    expect(r.status).toBe(200);
    const left = await sql(`SELECT count(*)::int AS n FROM users WHERE platform_role = 'super_admin' AND is_active`);
    expect(left[0].n).toBeGreaterThanOrEqual(1);
  });

  it('creating a user with both a platform role and an org role is refused', async () => {
    const r = await sup.req('/api/admin/users', { body: { email: 'both@test.example', name: 'Both', password: 'a-long-enough-password', platformRole: 'auditor', orgId: orgA, orgRole: 'org_admin' } });
    expect(r.status).toBe(400);
  });

  it('resetting MFA signs the user out and forces re-enrollment', async () => {
    const u = await seedUser({ name: 'Reset', platformRole: 'auditor' });
    const c = await signIn(u);
    expect((await c.req('/api/admin/audit')).status).toBe(200);
    expect((await sup.req(`/api/admin/users/${u.id}`, { method: 'PATCH', body: { resetMfa: true } })).status).toBe(200);
    expect((await c.req('/api/admin/audit')).status).toBe(401);
    const again = new Client();
    const r = await again.login(u.email, u.password);
    expect(r.json.mfaSetupRequired).toBe(true);
    expect((await again.req('/api/admin/audit')).status).toBe(403);
  });
});

describe('device lifecycle and authentication', () => {
  it('enrollment codes are single-use, and invalid codes give a generic error', async () => {
    const reuse = await new Client().req('/api/device/enroll', { body: { code: devA.code, hostname: 'REUSE', os: 'windows', appVersion: '0.1.0' } });
    expect(reuse.status).toBe(400);
    expect(reuse.json.error.code).toBe('invalid_code');
    const bogus = await new Client().req('/api/device/enroll', { body: { code: 'SX-AAAA-BBBB-CCCC-DDDD', hostname: 'X', os: 'windows', appVersion: '0.1.0' } });
    expect(bogus.status).toBe(400);
    expect(bogus.json.error.message).toBe(reuse.json.error.message);
  });

  it('expired enrollment codes are refused', async () => {
    const code = (await sup.req('/api/admin/enrollments', { body: { orgId: orgA } })).json.code;
    await sql(`UPDATE device_enrollments SET expires_at = now() - interval '1 minute'`);
    const r = await new Client().req('/api/device/enroll', { body: { code, hostname: 'LATE', os: 'windows', appVersion: '0.1.0' } });
    expect(r.status).toBe(400);
  });

  it('enrollment is refused (402) when the organization has no free license seat', async () => {
    const o = await seedOrg('Unlicensed');
    const code = (await sup.req('/api/admin/enrollments', { body: { orgId: o } })).json.code;
    const r = await new Client().req('/api/device/enroll', { body: { code, hostname: 'NOSEAT', os: 'windows', appVersion: '0.1.0' } });
    expect(r.status).toBe(402);
    expect(r.json.error.code).toBe('no_license_seat');
    // The code is not burned by a failed enrollment: adding a seat lets it work.
    await seedLicense(o, 1);
    const r2 = await new Client().req('/api/device/enroll', { body: { code, hostname: 'NOSEAT', os: 'windows', appVersion: '0.1.0' } });
    expect(r2.status).toBe(200);
  });

  it('expired and revoked licenses do not grant seats', async () => {
    const o = await seedOrg('BadLicenses');
    await seedLicense(o, 5, { status: 'revoked' });
    await seedLicense(o, 5, { expiresInDays: -1 });
    const code = (await sup.req('/api/admin/enrollments', { body: { orgId: o } })).json.code;
    expect((await new Client().req('/api/device/enroll', { body: { code, hostname: 'X', os: 'windows', appVersion: '0.1.0' } })).status).toBe(402);
  });

  it('seat limit is enforced', async () => {
    const o = await seedOrg('OneSeat');
    await seedLicense(o, 1);
    const first = await enrollDevice(sup, o, 'S1');
    expect(first.res.status).toBe(200);
    const second = await enrollDevice(sup, o, 'S2');
    expect(second.res.status).toBe(402);
  });

  it('device credentials are returned once and stored only as an HMAC', async () => {
    expect(devA.token).toMatch(/^dev_[0-9a-f-]{36}\.[A-Za-z0-9_-]{40,}$/);
    const [d] = await sql('SELECT token_hash FROM devices WHERE id = $1', [devA.deviceId]);
    expect(d.token_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(d.token_hash).not.toContain(devA.token.split('.')[1]);
  });

  it('heartbeat requires a valid device token; tampering with any part fails', async () => {
    const c = new Client();
    expect((await c.req('/api/device/heartbeat', { body: HEARTBEAT })).status).toBe(401);
    expect((await c.req('/api/device/heartbeat', { body: HEARTBEAT, bearer: 'dev_x.y' })).status).toBe(401);
    const bad = devA.token.slice(0, -2) + (devA.token.endsWith('aa') ? 'bb' : 'aa');
    expect((await c.req('/api/device/heartbeat', { body: HEARTBEAT, bearer: bad })).status).toBe(401);
    // Device A's secret on device B's id must fail.
    const cross = `dev_${devB.deviceId}.${devA.token.split('.')[1]}`;
    expect((await c.req('/api/device/heartbeat', { body: HEARTBEAT, bearer: cross })).status).toBe(401);
    // Admin session cookies are not device credentials.
    expect((await sup.req('/api/device/heartbeat', { body: HEARTBEAT })).status).toBe(401);
  });

  it('heartbeat returns policy, license state and records reported protection', async () => {
    const r = await devA.client.req('/api/device/heartbeat', { body: HEARTBEAT, bearer: devA.token });
    expect(r.status).toBe(200);
    expect(r.json.license.state).toBe('valid');
    expect(r.json.policy.autoQuarantine).toBeDefined();
    const [d] = await sql('SELECT protection, app_version FROM devices WHERE id = $1', [devA.deviceId]);
    expect(d.protection.engineState).toBe('running');
  });

  it('heartbeat rejects unknown or malformed fields', async () => {
    const r = await devA.client.req('/api/device/heartbeat', { body: { ...HEARTBEAT, shellCommand: 'whoami' }, bearer: devA.token });
    expect(r.status).toBe(400);
  });

  it('each organization\'s device receives its own policy and never another\'s', async () => {
    await sup.req('/api/admin/policies', { method: 'PUT', body: { orgId: orgB, config: { maxFileSizeMb: 77 } } });
    await adminA.req('/api/admin/policies', { method: 'PUT', body: { orgId: orgA, config: { maxFileSizeMb: 33 } } });
    const a = (await devA.client.req('/api/device/heartbeat', { body: HEARTBEAT, bearer: devA.token })).json.policy;
    const b = (await devB.client.req('/api/device/heartbeat', { body: HEARTBEAT, bearer: devB.token })).json.policy;
    expect(a.maxFileSizeMb).toBe(33);
    expect(b.maxFileSizeMb).toBe(77);
  });

  it('scan uploads store metadata only, and file names only when policy allows', async () => {
    const sha = 'a'.repeat(64);
    const body = { kind: 'file', startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(), filesTotal: 1, filesFailed: 0, complete: true, findings: [{ sha256: sha, fileName: 'secret-plans.docx', verdict: 'SUSPICIOUS', source: 'heuristic.pe' }] };
    expect((await devA.client.req('/api/device/scans', { body, bearer: devA.token })).status).toBe(200);
    let [f] = await sql('SELECT file_name FROM scan_findings WHERE device_id = $1 AND sha256 = $2', [devA.deviceId, sha]);
    expect(f.file_name, 'file name must be dropped when policy does not allow it').toBeNull();
    await sup.req('/api/admin/policies', { method: 'PUT', body: { orgId: orgA, config: { allowFileNameTelemetry: true } } });
    expect((await devA.client.req('/api/device/scans', { body: { ...body, findings: [{ ...body.findings[0], sha256: 'b'.repeat(64) }] }, bearer: devA.token })).status).toBe(200);
    [f] = await sql('SELECT file_name FROM scan_findings WHERE device_id = $1 AND sha256 = $2', [devA.deviceId, 'b'.repeat(64)]);
    expect(f.file_name).toBe('secret-plans.docx');
    await sup.req('/api/admin/policies', { method: 'PUT', body: { orgId: orgA, config: { allowFileNameTelemetry: false } } });
  });

  it('scan uploads reject non-hash identifiers and upload attempts of file content', async () => {
    const bad = { kind: 'file', startedAt: new Date().toISOString(), finishedAt: null, filesTotal: 1, filesFailed: 0, complete: false, findings: [{ sha256: 'not-a-hash', verdict: 'CLEAN', source: 's' }] };
    expect((await devA.client.req('/api/device/scans', { body: bad, bearer: devA.token })).status).toBe(400);
    const withContent = { ...bad, findings: [{ sha256: 'c'.repeat(64), verdict: 'CLEAN', source: 's', content: 'MZ....' }] };
    expect((await devA.client.req('/api/device/scans', { body: withContent, bearer: devA.token })).status).toBe(400);
  });
});

describe('remote actions are a closed, audited set', () => {
  it('only the three fixed kinds are accepted; arbitrary commands are impossible', async () => {
    for (const kind of ['shell', 'powershell', 'run', 'cmd.exe /c calc', '', 'scan_full']) {
      expect((await sup.req(`/api/admin/devices/${devA.deviceId}/jobs`, { body: { kind } })).status, kind).toBe(400);
    }
    expect((await sup.req(`/api/admin/devices/${devA.deviceId}/jobs`, { body: { kind: 'scan_quick', command: 'calc.exe' } })).status).toBe(400);
  });

  it('request, delivery on heartbeat, result, and duplicate suppression', async () => {
    const r = await sup.req(`/api/admin/devices/${devA.deviceId}/jobs`, { body: { kind: 'intel_update' } });
    expect(r.status).toBe(200);
    expect((await sup.req(`/api/admin/devices/${devA.deviceId}/jobs`, { body: { kind: 'intel_update' } })).status, 'duplicate').toBe(409);
    const hb = await devA.client.req('/api/device/heartbeat', { body: HEARTBEAT, bearer: devA.token });
    expect(hb.json.jobs.map((j: any) => j.kind)).toEqual(['intel_update']);
    expect((await devA.client.req('/api/device/heartbeat', { body: HEARTBEAT, bearer: devA.token })).json.jobs).toEqual([]);
    const jobId = hb.json.jobs[0].id;
    // Another device cannot report on it.
    expect((await devB.client.req(`/api/device/jobs/${jobId}/result`, { body: { state: 'succeeded' }, bearer: devB.token })).status).toBe(404);
    expect((await devA.client.req(`/api/device/jobs/${jobId}/result`, { body: { state: 'succeeded', result: 'ok' }, bearer: devA.token })).status).toBe(200);
    expect((await devA.client.req(`/api/device/jobs/${jobId}/result`, { body: { state: 'failed' }, bearer: devA.token })).status, 'cannot report twice').toBe(404);
  });
});

describe('license and device revocation', () => {
  it('revoking a license is reported to its devices at the next heartbeat', async () => {
    const o = await seedOrg('LicRevoke');
    const lic = await seedLicense(o, 2);
    const d = await enrollDevice(sup, o, 'LR');
    expect((await d.client.req('/api/device/heartbeat', { body: HEARTBEAT, bearer: d.token })).json.license.state).toBe('valid');
    expect((await sup.req(`/api/admin/licenses/${lic}/revoke`, { body: {} })).status).toBe(200);
    expect((await d.client.req('/api/device/heartbeat', { body: HEARTBEAT, bearer: d.token })).json.license.state).toBe('revoked');
  });

  it('revoking a device invalidates its token instantly, frees the seat and cancels jobs', async () => {
    const o = await seedOrg('DevRevoke');
    const lic = await seedLicense(o, 1);
    const d = await enrollDevice(sup, o, 'DR');
    await sup.req(`/api/admin/devices/${d.deviceId}/jobs`, { body: { kind: 'scan_quick' } });
    expect((await sup.req(`/api/admin/devices/${d.deviceId}/revoke`, { body: {} })).status).toBe(200);
    expect((await d.client.req('/api/device/heartbeat', { body: HEARTBEAT, bearer: d.token })).status).toBe(401);
    expect((await sql('SELECT count(*)::int AS n FROM license_activations WHERE license_id = $1', [lic]))[0].n).toBe(0);
    expect((await sql(`SELECT count(*)::int AS n FROM update_jobs WHERE device_id = $1 AND state IN ('pending','delivered')`, [d.deviceId]))[0].n).toBe(0);
    const again = await enrollDevice(sup, o, 'DR2');
    expect(again.res.status, 'seat is reusable').toBe(200);
  });

  it('a device can unenroll itself', async () => {
    const o = await seedOrg('SelfRemove');
    await seedLicense(o, 1);
    const d = await enrollDevice(sup, o, 'SR');
    expect((await d.client.req('/api/device/unenroll', { body: {}, bearer: d.token })).status).toBe(200);
    expect((await d.client.req('/api/device/heartbeat', { body: HEARTBEAT, bearer: d.token })).status).toBe(401);
  });
});

describe('release and update safety', () => {
  const art = { artifactUrl: 'https://downloads.example.test/SENTRIX_0.2.0_x64-setup.exe', sha256: 'd'.repeat(64), signature: 'dW50cnVzdGVkIGNvbW1lbnQ6IHRlc3Q=', sizeBytes: 17_000_000 };

  async function feed(version: string, id: string, platform = 'windows-x64') {
    return new Client().req(`/api/updates/${platform}/${version}?id=${encodeURIComponent(id)}`);
  }

  it('a release without artifact, hash and signature can never be staged or published', async () => {
    const r = await sup.req('/api/admin/releases', { body: { version: '0.2.0', platform: 'windows-x64' } });
    expect(r.status).toBe(200);
    const id = r.json.release.id;
    for (const action of ['stage', 'publish']) {
      const x = await sup.req(`/api/admin/releases/${id}/action`, { body: { action } });
      expect(x.status, action).toBe(409);
      expect(x.json.error.code).toBe('unsigned_release');
    }
    expect((await feed('0.1.0', 'any-device')).status, 'drafts are never offered').toBe(204);
    expect((await new Client().req('/api/public/releases')).json.releases).toEqual([]);
  });

  it('plain-http artifact URLs are refused outright', async () => {
    const r = await sup.req('/api/admin/releases', { body: { version: '0.3.0', platform: 'windows-x64', artifactUrl: 'http://x.test/a.exe' } });
    expect(r.status).toBe(400);
  });

  it('staged rollout reaches only the matching cohort; publish reaches everyone; rollback withdraws it', async () => {
    const r = await sup.req('/api/admin/releases', { body: { version: '0.4.0', platform: 'windows-x64', notes: 'test', codeSigned: false, ...art } });
    const id = r.json.release.id;
    expect((await sup.req(`/api/admin/releases/${id}/action`, { body: { action: 'stage', rolloutPct: 100 } })).status, '100% must use publish').toBe(400);
    expect((await sup.req(`/api/admin/releases/${id}/action`, { body: { action: 'stage', rolloutPct: 10 } })).status).toBe(200);

    let inCohort = '', outCohort = '';
    for (let i = 0; !inCohort || !outCohort; i++) (rolloutBucket(`probe-${i}`, '0.4.0') < 10 ? (inCohort ||= `probe-${i}`) : (outCohort ||= `probe-${i}`));
    const offered = await feed('0.1.0', inCohort);
    expect(offered.status).toBe(200);
    expect(offered.json.version).toBe('0.4.0');
    expect(offered.json.signature).toBe(art.signature);
    expect(offered.json.url).toBe(art.artifactUrl);
    expect((await feed('0.1.0', outCohort)).status, 'outside the 10% cohort').toBe(204);
    expect((await feed('0.4.0', inCohort)).status, 'already current').toBe(204);

    expect((await sup.req(`/api/admin/releases/${id}/action`, { body: { action: 'publish' } })).status).toBe(200);
    expect((await feed('0.1.0', outCohort)).status).toBe(200);
    const pub = (await new Client().req('/api/public/releases')).json.releases;
    expect(pub).toHaveLength(1);
    expect(pub[0]).toMatchObject({ version: '0.4.0', platform: 'windows-x64', sha256: art.sha256, codeSigned: false });
    expect(Object.keys(pub[0])).not.toContain('id');

    expect((await sup.req(`/api/admin/releases/${id}/action`, { body: { action: 'rollback' } })).status).toBe(200);
    expect((await feed('0.1.0', outCohort)).status, 'rolled-back builds are no longer offered').toBe(204);
    expect((await new Client().req('/api/public/releases')).json.releases).toEqual([]);
  });

  it('release state machine rejects impossible transitions', async () => {
    const r = await sup.req('/api/admin/releases', { body: { version: '0.5.0', platform: 'windows-x64', ...art } });
    const id = r.json.release.id;
    expect((await sup.req(`/api/admin/releases/${id}/action`, { body: { action: 'rollback' } })).status).toBe(409);
    expect((await sup.req(`/api/admin/releases/${id}/action`, { body: { action: 'cancel' } })).status).toBe(200);
    expect((await sup.req(`/api/admin/releases/${id}/action`, { body: { action: 'publish' } })).status).toBe(409);
    expect((await sup.req('/api/admin/releases', { body: { version: '0.5.0', platform: 'windows-x64', ...art } })).status, 'duplicate version').toBe(409);
  });

  it('the update feed validates its parameters and never reflects them', async () => {
    expect((await feed('abc', 'x')).status).toBe(400);
    expect((await feed('0.1.0', 'x', 'solaris')).status).toBe(400);
    expect((await feed('0.1.0', '<script>alert(1)</script>')).status).toBe(204);
  });

  it('a heartbeat carries an update offer for signed releases only', async () => {
    const r = await sup.req('/api/admin/releases', { body: { version: '0.6.0', platform: 'windows-x64', ...art } });
    await sup.req(`/api/admin/releases/${r.json.release.id}/action`, { body: { action: 'publish' } });
    const hb = await devA.client.req('/api/device/heartbeat', { body: HEARTBEAT, bearer: devA.token });
    expect(hb.json.update?.version).toBe('0.6.0');
    expect(hb.json.update.signature).toBeTruthy();
  });
});

describe('audit log', () => {
  it('records privileged actions with the actor', async () => {
    const rows = await sql(`SELECT action FROM audit_events`);
    const actions = new Set(rows.map((r: any) => r.action));
    for (const a of ['auth.login', 'auth.login_failed', 'device.enroll', 'device.revoke', 'device.job_requested', 'license.revoke', 'policy.write', 'release.create', 'release.publish', 'user.update', 'enrollment.create']) {
      expect(actions.has(a), `missing audit action ${a}`).toBe(true);
    }
  });

  it('never stores passwords, tokens or secrets', async () => {
    const all = JSON.stringify(await sql('SELECT detail, target, actor_email FROM audit_events'));
    expect(all).not.toMatch(/Pw-[A-Za-z0-9_-]{8,}-ok/);
    expect(all).not.toMatch(/dev_[0-9a-f-]{36}\./);
    expect(all).not.toMatch(/\bSX-[A-Z2-9]{4}-/);
  });

  it('the append-only trigger blocks UPDATE and DELETE', async () => {
    await expect(sql(`UPDATE audit_events SET action = 'forged' WHERE seq = 1`)).rejects.toThrow(/append-only/);
    await expect(sql(`DELETE FROM audit_events WHERE seq = 1`)).rejects.toThrow(/append-only/);
  });

  it('chain verification passes on the real log and detects a tampered entry', async () => {
    const intact = await sup.req('/api/admin/audit?verify=1');
    expect(intact.json.intact).toBe(true);
    // An attacker with database superuser rights disables the trigger and edits history.
    await sql(`ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_update`);
    try {
      const [victim] = await sql(`SELECT seq, target FROM audit_events WHERE action = 'device.revoke' ORDER BY seq LIMIT 1`);
      await sql(`UPDATE audit_events SET target = 'tampered' WHERE seq = $1`, [victim.seq]);
      try {
        const broken = await sup.req('/api/admin/audit?verify=1');
        expect(broken.json.intact).toBe(false);
        expect(broken.json.firstBrokenSeq).toBe(Number(victim.seq));
        // Org-scoped admins learn only that it broke, not where.
        expect((await adminA.req('/api/admin/audit?verify=1')).json.firstBrokenSeq).toBeUndefined();
      } finally {
        // Restore the row so later tests share an intact chain.
        await sql(`UPDATE audit_events SET target = $2 WHERE seq = $1`, [victim.seq, victim.target]);
      }
      expect((await sup.req('/api/admin/audit?verify=1')).json.intact, 'restoring the original value heals the chain').toBe(true);
    } finally {
      await sql(`ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_update`);
    }
  });
});

describe('information exposure', () => {
  it('health check reveals nothing about the deployment', async () => {
    const r = await new Client().req('/api/health');
    expect(r.json).toEqual({ status: 'ok' });
  });

  it('security headers are present on pages and APIs', async () => {
    for (const p of ['/', '/login', '/download', '/api/health']) {
      const r = await new Client().req(p);
      expect(r.headers.get('content-security-policy'), p).toContain("default-src 'self'");
      expect(r.headers.get('content-security-policy'), p).toContain("frame-ancestors 'none'");
      expect(r.headers.get('x-content-type-options'), p).toBe('nosniff');
      expect(r.headers.get('x-frame-options'), p).toBe('DENY');
      expect(r.headers.get('strict-transport-security'), p).toMatch(/max-age=\d+/);
      expect(r.headers.get('x-powered-by'), p).toBeNull();
    }
    expect((await new Client().req('/api/health')).headers.get('cache-control')).toContain('no-store');
  });

  it('console pages redirect anonymous visitors to sign-in and never render data', async () => {
    const res = await fetch(`${new Client().base}/console/devices`, { redirect: 'manual' });
    expect([302, 303, 307, 308]).toContain(res.status);
    expect(res.headers.get('location')).toContain('/login');
  });

  it('public pages never expose admin routes or internals', async () => {
    const html = await (await fetch(`${new Client().base}/download`)).text();
    expect(html).not.toMatch(/\/api\/admin|DATABASE_URL|SESSION_SECRET|token_hash/);
  });

  it('unknown API routes return a plain JSON 404 with no framework internals', async () => {
    for (const method of ['GET', 'POST']) {
      const r = await new Client().req('/api/admin/does-not-exist', { method, ...(method === 'POST' ? { body: {} } : {}) });
      expect(r.status).toBe(404);
      expect(r.json).toEqual({ error: { code: 'not_found', message: 'Not found' } });
    }
  });
});


describe('Phase 2 health reporting and Telegram privacy', () => {
  const hb = (over: Record<string, unknown>) => ({ ...HEARTBEAT, ...over });

  it('accepts operational counts and stores exactly those, nothing else', async () => {
    const r = await devA.client.req('/api/device/heartbeat', { bearer: devA.token, body: hb({ queue: { queued: 3, failed: 2, stuck: 1 }, telegram: { botConnected: true, deliveryFailures24h: 4, accountState: 'not_available' } }) });
    expect(r.status).toBe(200);
    const [d] = await sql('SELECT queue, telegram FROM devices WHERE id = $1', [devA.deviceId]);
    expect(d.queue).toEqual({ queued: 3, failed: 2, stuck: 1 });
    expect(d.telegram).toEqual({ botConnected: true, deliveryFailures24h: 4, accountState: 'not_available' });
  });

  it('rejects any attempt to send tokens, chat ids, file names or message text', async () => {
    for (const telegram of [
      { botConnected: true, deliveryFailures24h: 0, accountState: 'not_available', botToken: '123456789:AAHkq3Zr0pXxJ2mN8sVbT5wYcLdEfGh1Ijk' },
      { botConnected: true, deliveryFailures24h: 0, accountState: 'not_available', chatId: 42 },
      { botConnected: true, deliveryFailures24h: 0, accountState: 'not_available', lastMessage: 'secret plans.docx' },
      { botConnected: true, deliveryFailures24h: 0, accountState: 'weird-state' },
      { botConnected: 'yes', deliveryFailures24h: 0, accountState: 'connected' },
      { botConnected: true, deliveryFailures24h: -1, accountState: 'connected' },
    ]) {
      const r = await devA.client.req('/api/device/heartbeat', { bearer: devA.token, body: hb({ telegram }) });
      expect(r.status, JSON.stringify(telegram)).toBe(400);
    }
    for (const queue of [{ queued: 0, failed: 0, stuck: 0, files: ['a.exe'] }, { queued: 0, failed: 0 }, { queued: 'many', failed: 0, stuck: 0 }]) {
      expect((await devA.client.req('/api/device/heartbeat', { bearer: devA.token, body: hb({ queue }) })).status, JSON.stringify(queue)).toBe(400);
    }
    const [d] = await sql('SELECT telegram::text AS t FROM devices WHERE id = $1', [devA.deviceId]);
    expect(d.t).not.toMatch(/AAHkq3Zr|chatId|secret plans/);
  });

  it('older clients that do not send the new fields still work', async () => {
    expect((await devB.client.req('/api/device/heartbeat', { bearer: devB.token, body: HEARTBEAT })).status).toBe(200);
    const [d] = await sql('SELECT queue, telegram FROM devices WHERE id = $1', [devB.deviceId]);
    expect(d.queue).toEqual({});
    expect(d.telegram).toEqual({});
  });

  it('shows the status to authorized administrators only, within their organization', async () => {
    const own = await adminA.req(`/api/admin/devices/${devA.deviceId}`);
    expect(own.status).toBe(200);
    expect(own.json.device.queue.failed).toBe(2);
    expect(own.json.device.telegram.botConnected).toBe(true);
    expect(JSON.stringify(own.json)).not.toMatch(/token|chat_?id/i);
    expect((await adminB.req(`/api/admin/devices/${devA.deviceId}`)).status, 'another organization sees nothing').toBe(404);
  });

  it('fleet aggregates are correct and tenant-scoped', async () => {
    const a = (await adminA.req('/api/admin/overview')).json.operational.fleet;
    const b = (await adminB.req('/api/admin/overview')).json.operational.fleet;
    expect(Number(a.devices_with_unchecked_files)).toBeGreaterThanOrEqual(1);
    expect(Number(a.devices_with_stuck_scans)).toBeGreaterThanOrEqual(1);
    expect(Number(a.telegram_bots_connected)).toBeGreaterThanOrEqual(1);
    expect(Number(a.telegram_delivery_failures)).toBeGreaterThanOrEqual(1);
    expect(Number(b.devices_with_unchecked_files), "organization B's device reported no failures, and must not see A's").toBe(0);
    expect(Number(b.telegram_bots_connected)).toBe(0);
    const all = (await sup.req('/api/admin/overview')).json.operational.fleet;
    expect(Number(all.devices_with_unchecked_files)).toBeGreaterThanOrEqual(Number(a.devices_with_unchecked_files));
  });

  it('an organization can switch the Telegram integrations off, validated and delivered in the heartbeat', async () => {
    expect((await sup.req('/api/admin/policies', { method: 'PUT', body: { orgId: orgA, config: { telegramBotAllowed: false } } })).status).toBe(200);
    const pol = (await devA.client.req('/api/device/heartbeat', { bearer: devA.token, body: HEARTBEAT })).json.policy;
    expect(pol.telegramBotAllowed).toBe(false);
    expect(pol.telegramAccountAllowed).toBe(true);
    for (const config of [{ telegramBotAllowed: 'no' }, { telegramToken: 'x' }, { telegramBotAllowed: null }]) {
      expect((await sup.req('/api/admin/policies', { method: 'PUT', body: { orgId: orgA, config } })).status, JSON.stringify(config)).toBe(400);
    }
    // Another organization is unaffected.
    expect((await devB.client.req('/api/device/heartbeat', { bearer: devB.token, body: HEARTBEAT })).json.policy.telegramBotAllowed).toBe(true);
    await sup.req('/api/admin/policies', { method: 'PUT', body: { orgId: orgA, config: {} } });
  });

  it('devices table has no column that could hold a token or chat id', async () => {
    const cols = (await sql(`SELECT column_name FROM information_schema.columns WHERE table_name = 'devices' AND table_schema = current_schema()`)).map((r: any) => r.column_name);
    expect(cols.filter((c: string) => /bot|chat|session/i.test(c)), 'no bot/chat/session column may exist on devices').toEqual([]);
    expect(cols).toContain('telegram');
    expect(cols.filter((c: string) => /token/.test(c))).toEqual(['token_hash']);
  });
});

describe('Group Shield reporting, privacy and isolation', () => {
  const hb = (over: Record<string, unknown>) => ({ ...HEARTBEAT, ...over });
  const A = { registered: 3, protected: 2, autoDelete: 1, scans24h: 40, threats24h: 2, errors24h: 1 };
  const B = { registered: 7, protected: 7, autoDelete: 0, scans24h: 90, threats24h: 0, errors24h: 0 };

  it('stores exactly the reported counts', async () => {
    expect((await devA.client.req('/api/device/heartbeat', { bearer: devA.token, body: hb({ groups: A }) })).status).toBe(200);
    expect((await devB.client.req('/api/device/heartbeat', { bearer: devB.token, body: hb({ groups: B }) })).status).toBe(200);
    const [d] = await sql('SELECT tg_groups FROM devices WHERE id = $1', [devA.deviceId]);
    expect(d.tg_groups).toEqual(A);
  });

  it('rejects group names, chat ids, member names, file names and malformed numbers', async () => {
    for (const groups of [
      { ...A, title: 'Finance team' },
      { ...A, chatId: -1001234567890 },
      { ...A, members: ['alice'] },
      { ...A, lastFile: 'salaries.xlsx' },
      { ...A, registered: -1 },
      { ...A, threats24h: 'many' },
      { registered: 1 },
    ]) {
      expect((await devA.client.req('/api/device/heartbeat', { bearer: devA.token, body: hb({ groups }) })).status, JSON.stringify(groups)).toBe(400);
    }
    const [d] = await sql('SELECT tg_groups::text AS t FROM devices WHERE id = $1', [devA.deviceId]);
    expect(d.t).not.toMatch(/Finance|salaries|alice|1001234567890/);
  });

  it('aggregates are tenant-scoped: an organization never sees another organization\'s groups', async () => {
    const a = (await adminA.req('/api/admin/overview')).json.operational.fleet;
    const b = (await adminB.req('/api/admin/overview')).json.operational.fleet;
    expect(Number(a.tg_groups_registered)).toBe(A.registered);
    expect(Number(a.tg_group_threats_24h)).toBe(A.threats24h);
    expect(Number(b.tg_groups_registered)).toBe(B.registered);
    expect(Number(b.tg_group_threats_24h)).toBe(0);
    const all = (await sup.req('/api/admin/overview')).json.operational.fleet;
    expect(Number(all.tg_groups_registered)).toBeGreaterThanOrEqual(A.registered + B.registered);
    expect(JSON.stringify([a, b])).not.toMatch(/title|chat_?id|member/i);
  });

  it('device detail shows the counts to the owning organization only', async () => {
    const own = await adminA.req(`/api/admin/devices/${devA.deviceId}`);
    expect(own.status).toBe(200);
    expect(own.json.device.tg_groups).toEqual(A);
    expect((await adminB.req(`/api/admin/devices/${devA.deviceId}`)).status).toBe(404);
  });

  it('an organization can forbid group protection; the flag is validated and delivered', async () => {
    expect((await sup.req('/api/admin/policies', { method: 'PUT', body: { orgId: orgA, config: { telegramGroupsAllowed: false } } })).status).toBe(200);
    expect((await devA.client.req('/api/device/heartbeat', { bearer: devA.token, body: hb({}) })).json.policy.telegramGroupsAllowed).toBe(false);
    expect((await sup.req('/api/admin/policies', { method: 'PUT', body: { orgId: orgA, config: { telegramGroupsAllowed: 'no' } } })).status).toBe(400);
    expect((await devB.client.req('/api/device/heartbeat', { bearer: devB.token, body: hb({}) })).json.policy.telegramGroupsAllowed).toBe(true);
    await sup.req('/api/admin/policies', { method: 'PUT', body: { orgId: orgA, config: {} } });
  });
});

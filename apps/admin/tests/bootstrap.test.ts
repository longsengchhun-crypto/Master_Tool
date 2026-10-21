import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { describe, expect, it, inject } from 'vitest';
import { totpNow } from '@/lib/totp';
import { Client, sql } from './helpers';

const root = join(__dirname, '..');
const env = () => ({ ...process.env, DATABASE_URL: inject('dbUrl') });

describe('bootstrap-admin script', () => {
  it('creates exactly one Super Administrator, with a chain-valid audit entry, and then refuses to run again', async () => {
    const run = (extra: Record<string, string>) => spawnSync(process.execPath, ['scripts/bootstrap-admin.mjs'], { cwd: root, env: { ...env(), ...extra }, encoding: 'utf8' });

    // No email, bad password: refused without touching the database.
    expect(run({}).status).toBe(2);
    expect(run({ SENTRIX_ADMIN_EMAIL: 'boot@test.example', SENTRIX_ADMIN_PASSWORD: 'short' }).status).toBe(2);
    expect((await sql(`SELECT count(*)::int AS n FROM users WHERE email = 'boot@test.example'`))[0].n).toBe(0);

    // Make sure this test starts from "no super admin" regardless of other suites sharing the schema.
    const existing = await sql(`SELECT id FROM users WHERE platform_role = 'super_admin'`);
    if (existing.length) await sql(`UPDATE users SET platform_role = 'auditor' WHERE platform_role = 'super_admin'`);

    const ok = run({ SENTRIX_ADMIN_EMAIL: 'Boot@Test.Example', SENTRIX_ADMIN_NAME: 'Boot Admin' });
    expect(ok.status, ok.stderr).toBe(0);
    const pw = /One-time password \(shown once[^)]*\): (\S+)/.exec(ok.stdout)?.[1];
    expect(pw, 'a generated password must be printed once').toBeTruthy();
    expect(pw!.length).toBeGreaterThanOrEqual(20);

    const [u] = await sql(`SELECT id, email, platform_role, mfa_enabled, password_hash FROM users WHERE email = 'boot@test.example'`);
    expect(u).toMatchObject({ platform_role: 'super_admin', mfa_enabled: false });
    expect(u.password_hash.startsWith('$argon2id$')).toBe(true);
    expect(u.password_hash).not.toContain(pw!);

    // A second run must refuse.
    const again = run({ SENTRIX_ADMIN_EMAIL: 'second@test.example' });
    expect(again.status).toBe(3);
    expect((await sql(`SELECT count(*)::int AS n FROM users WHERE email = 'second@test.example'`))[0].n).toBe(0);

    // The new admin can sign in, is forced through MFA setup, and the audit chain (script + server entries) verifies.
    const c = new Client();
    const login = await c.login('boot@test.example', pw!);
    expect(login.json.mfaSetupRequired).toBe(true);
    expect((await c.req('/api/admin/overview')).json.error.code).toBe('mfa_required');
    const setup = await c.req('/api/auth/mfa/setup', { body: {} });
    expect((await c.req('/api/auth/mfa/enable', { body: { token: await totpNow(setup.json.secret) } })).status).toBe(200);
    const verify = await c.req('/api/admin/audit?verify=1');
    expect(verify.json.intact, 'script-written audit entries must chain correctly with the server\'s').toBe(true);
    const actions = (await sql(`SELECT action FROM audit_events`)).map((r: any) => r.action);
    expect(actions).toContain('user.bootstrap_super_admin');

    // Restore any super admins we demoted for the test.
    for (const r of existing) await sql(`UPDATE users SET platform_role = 'super_admin' WHERE id = $1`, [r.id]);
  }, 240_000);
});

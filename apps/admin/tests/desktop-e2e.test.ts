/**
 * Real desktop client <-> real console <-> real Postgres. Opt-in because it compiles and runs Rust tests:
 *   SENTRIX_E2E_DESKTOP=1 npx vitest run tests/desktop-e2e.test.ts
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, inject } from 'vitest';
import { seedLicense, seedOrg, seedUser, signIn, sql } from './helpers';

const enabled = process.env.SENTRIX_E2E_DESKTOP === '1';
const repo = join(__dirname, '..', '..', '..');

function rust(test: string, env: Record<string, string>) {
  return execFileSync('cargo', ['test', '-p', 'sentrix-desktop', '--test', 'portal_e2e', test, '--', '--exact', '--ignored', '--nocapture'], {
    cwd: repo,
    env: { ...process.env, ...env },
    encoding: 'utf8',
    timeout: 600_000,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

describe.skipIf(!enabled)('desktop client against the live console', () => {
  it('enroll, survive a restart, receive a console job exactly once, then be dropped when revoked', async () => {
    const orgId = await seedOrg('Desktop E2E');
    await seedLicense(orgId, 3);
    const admin = await signIn(await seedUser({ name: 'E2E Super', platformRole: 'super_admin' }));
    const code = (await admin.req('/api/admin/enrollments', { body: { orgId } })).json.code as string;
    const dir = mkdtempSync(join(tmpdir(), 'sentrix-e2e-'));
    const env = { SENTRIX_E2E_URL: inject('baseUrl'), SENTRIX_E2E_DIR: dir, SENTRIX_E2E_CODE: code };
    try {
      // Phase 1: enrollment from the Rust client.
      rust('phase1_enroll', env);
      const [dev] = await sql(`SELECT id, hostname, protection, status FROM devices WHERE org_id = $1`, [orgId]);
      expect(dev.hostname).toBe('E2E-PC');
      expect(dev.status).toBe('enrolled');
      expect(dev.protection.engineState).toBe('running');
      expect((await sql('SELECT count(*)::int AS n FROM license_activations WHERE device_id = $1', [dev.id]))[0].n).toBe(1);

      // The console requests a fixed-kind job.
      expect((await admin.req(`/api/admin/devices/${dev.id}/jobs`, { body: { kind: 'intel_update' } })).status).toBe(200);

      // Phase 2: a fresh process (simulated restart) picks it up and reports back.
      rust('phase2_job_roundtrip_after_restart', env);
      const [job] = await sql(`SELECT state, result FROM update_jobs WHERE device_id = $1`, [dev.id]);
      expect(job).toMatchObject({ state: 'succeeded', result: 'ok-from-rust' });
      expect((await sql(`SELECT kind FROM security_events WHERE device_id = $1`, [dev.id])).map((e: any) => e.kind)).toContain('engine_degraded');

      // The admin revokes the device; the client must notice and discard its credential.
      expect((await admin.req(`/api/admin/devices/${dev.id}/revoke`, { body: {} })).status).toBe(200);
      rust('phase3_revoked_device_is_dropped', env);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 900_000);
});

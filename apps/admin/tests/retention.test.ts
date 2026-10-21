import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { describe, expect, it, inject } from 'vitest';
import { seedLicense, seedOrg, sql } from './helpers';

const root = join(__dirname, '..');
const run = (args: string[] = [], extra: Record<string, string> = {}) =>
  spawnSync(process.execPath, ['scripts/retention.mjs', ...args], { cwd: root, env: { ...process.env, DATABASE_URL: inject('dbUrl'), ...extra }, encoding: 'utf8' });

describe('retention job', () => {
  it('deletes only data past its retention window, never the audit log, users, orgs or licenses', async () => {
    const org = await seedOrg('Retention');
    await seedLicense(org, 5);
    const mkDevice = async (name: string, status: string, revokedDaysAgo: number | null) => {
      const [d] = await sql(
        `INSERT INTO devices(org_id, hostname, os, token_hash, status, revoked_at) VALUES ($1,$2,'windows',$3,$4, CASE WHEN $5::int IS NULL THEN NULL ELSE now() - make_interval(days => $5::int) END) RETURNING id`,
        [org, name, 'a'.repeat(64), status, revokedDaysAgo],
      );
      return d.id as string;
    };
    const live = await mkDevice('live', 'enrolled', null);
    const oldRevoked = await mkDevice('old-revoked', 'revoked', 200);
    const freshRevoked = await mkDevice('fresh-revoked', 'revoked', 5);

    const sha = 'e'.repeat(64);
    const mkSession = async (device: string, daysAgo: number) => {
      const [s] = await sql(`INSERT INTO scan_sessions(device_id, started_at, kind, files_total, complete) VALUES ($1, now() - make_interval(days => $2), 'file', 1, true) RETURNING id`, [device, daysAgo]);
      await sql(`INSERT INTO scan_findings(session_id, device_id, sha256, verdict, source, found_at) VALUES ($1,$2,$3,'SUSPICIOUS','heuristic.pe', now() - make_interval(days => $4))`, [s.id, device, sha, daysAgo]);
      return s.id as string;
    };
    const oldSession = await mkSession(live, 400);
    const newSession = await mkSession(live, 3);
    await sql(`INSERT INTO security_events(device_id, kind, severity, created_at) VALUES ($1,'old','info', now() - interval '400 days'), ($1,'new','info', now())`, [live]);
    await sql(`INSERT INTO sessions(id, user_id, expires_at, csrf_token) SELECT 'expired-' || gen_random_uuid()::text, id, now() - interval '1 day', 'x' FROM users LIMIT 1`);
    await sql(`INSERT INTO rate_limits(bucket, count, window_end) VALUES ('retention:old', 1, now() - interval '3 days'), ('retention:new', 1, now() + interval '1 hour')`);

    const auditBefore = (await sql('SELECT count(*)::int AS n FROM audit_events'))[0].n;
    const usersBefore = (await sql('SELECT count(*)::int AS n FROM users'))[0].n;

    // Dry run reports but deletes nothing.
    const dry = run(['--dry-run']);
    expect(dry.status, dry.stderr).toBe(0);
    const dryOut = JSON.parse(dry.stdout);
    expect(dryOut.dryRun).toBe(true);
    expect(dryOut.deleted.revoked_devices).toBeGreaterThanOrEqual(1);
    expect((await sql('SELECT 1 FROM devices WHERE id = $1', [oldRevoked])).length).toBe(1);

    const real = run();
    expect(real.status, real.stderr).toBe(0);
    expect((await sql('SELECT 1 FROM devices WHERE id = $1', [oldRevoked])).length, 'old revoked device purged').toBe(0);
    expect((await sql('SELECT 1 FROM devices WHERE id = $1', [freshRevoked])).length, 'recently revoked device kept').toBe(1);
    expect((await sql('SELECT 1 FROM devices WHERE id = $1', [live])).length, 'enrolled device never purged').toBe(1);
    expect((await sql('SELECT 1 FROM scan_sessions WHERE id = $1', [oldSession])).length).toBe(0);
    expect((await sql('SELECT 1 FROM scan_sessions WHERE id = $1', [newSession])).length).toBe(1);
    expect((await sql(`SELECT count(*)::int AS n FROM scan_findings WHERE device_id = $1`, [live]))[0].n).toBe(1);
    expect((await sql(`SELECT kind FROM security_events WHERE device_id = $1`, [live])).map((r: any) => r.kind)).toEqual(['new']);
    expect((await sql(`SELECT 1 FROM rate_limits WHERE bucket = 'retention:old'`)).length).toBe(0);
    expect((await sql(`SELECT 1 FROM rate_limits WHERE bucket = 'retention:new'`)).length).toBe(1);
    expect((await sql(`SELECT 1 FROM sessions WHERE id LIKE 'expired-%'`)).length).toBe(0);

    expect((await sql('SELECT count(*)::int AS n FROM audit_events'))[0].n, 'audit log untouched').toBe(auditBefore);
    expect((await sql('SELECT count(*)::int AS n FROM users'))[0].n).toBe(usersBefore);
    expect((await sql('SELECT 1 FROM organizations WHERE id = $1', [org])).length).toBe(1);
    expect((await sql('SELECT 1 FROM licenses WHERE org_id = $1', [org])).length).toBe(1);
  }, 240_000); // ~40 sequential round-trips to a remote database

  it('rejects nonsense configuration instead of deleting more than intended', () => {
    for (const bad of ['-1', 'abc', '1.5']) {
      const r = run([], { RETENTION_DAYS_FINDINGS: bad });
      expect(r.status, bad).toBe(2);
    }
  });
});

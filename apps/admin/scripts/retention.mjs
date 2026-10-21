// Enforces data-retention limits. Run daily from a scheduler:  node scripts/retention.mjs [--dry-run]
//
//   RETENTION_DAYS_FINDINGS          scan findings + scan sessions        (default 180)
//   RETENTION_DAYS_EVENTS            device security events               (default 180)
//   RETENTION_DAYS_QUARANTINE        quarantine metadata records          (default 365)
//   RETENTION_DAYS_REVOKED_DEVICES   revoked devices and dependent rows   (default 90)
//
// The audit log is intentionally NOT touched: it is append-only and hash-chained. Archiving it needs a documented,
// audited procedure (docs/OPERATIONS.md). Nothing here deletes users, organizations, licenses or releases.
import { existsSync, readFileSync } from 'node:fs';
import pg from 'pg';

if (!process.env.DATABASE_URL && existsSync('.env')) {
  for (const l of readFileSync('.env', 'utf8').split(/\r?\n/)) {
    const m = l.match(/^([A-Z_]+)=(.*)$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
  }
}
if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set.');
  process.exit(2);
}
const days = (name, dflt) => {
  const v = process.env[name];
  if (v === undefined || v === '') return dflt;
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0 || !Number.isInteger(n)) {
    console.error(`${name} must be a non-negative integer`);
    process.exit(2);
  }
  return n;
};
const cfg = {
  findings: days('RETENTION_DAYS_FINDINGS', 180),
  events: days('RETENTION_DAYS_EVENTS', 180),
  quarantine: days('RETENTION_DAYS_QUARANTINE', 365),
  revoked: days('RETENTION_DAYS_REVOKED_DEVICES', 90),
};
const dry = process.argv.includes('--dry-run');

const c = new pg.Client({ connectionString: process.env.DATABASE_URL });
await c.connect();
const report = {};
try {
  await c.query('BEGIN');
  // Each step: [label, count query, delete query]. The cutoff is computed in SQL so there is no clock skew with the app.
  const steps = [
    ['scan_findings', `FROM scan_findings WHERE found_at < now() - make_interval(days => $1)`, cfg.findings],
    ['scan_sessions', `FROM scan_sessions WHERE started_at < now() - make_interval(days => $1)`, cfg.findings],
    ['security_events', `FROM security_events WHERE created_at < now() - make_interval(days => $1)`, cfg.events],
    ['quarantine_records', `FROM quarantine_records WHERE created_at < now() - make_interval(days => $1)`, cfg.quarantine],
    ['revoked_devices', `FROM devices WHERE status = 'revoked' AND revoked_at IS NOT NULL AND revoked_at < now() - make_interval(days => $1)`, cfg.revoked],
    ['expired_sessions', `FROM sessions WHERE expires_at < now()`, null],
    ['spent_enrollment_codes', `FROM device_enrollments WHERE (used_at IS NOT NULL OR expires_at < now()) AND COALESCE(used_at, expires_at) < now() - interval '7 days'`, null],
    ['stale_rate_limits', `FROM rate_limits WHERE window_end < now() - interval '1 day'`, null],
  ];
  for (const [label, from, param] of steps) {
    const args = param === null ? [] : [param];
    const n = (await c.query(`SELECT count(*)::int AS n ${from}`, args)).rows[0].n;
    report[label] = n;
    if (!dry && n > 0) await c.query(`DELETE ${from}`, args);
  }
  await (dry ? c.query('ROLLBACK') : c.query('COMMIT'));
  console.log(JSON.stringify({ dryRun: dry, retentionDays: cfg, deleted: report }, null, 2));
} catch (e) {
  await c.query('ROLLBACK').catch(() => undefined);
  console.error(`Retention failed: ${e.message}`);
  process.exit(1);
} finally {
  await c.end();
}

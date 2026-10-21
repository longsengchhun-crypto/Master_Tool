// Creates the FIRST Super Administrator. Refuses to run if one already exists.
//
//   SENTRIX_ADMIN_EMAIL=you@example.com node scripts/bootstrap-admin.mjs
//   (optional) SENTRIX_ADMIN_NAME="Your Name"  SENTRIX_ADMIN_PASSWORD=...   (>= 12 chars; generated if omitted)
//
// The account has no MFA yet: at first sign-in the console forces two-step setup before showing anything.
// A generated password is printed once and never stored in clear text.
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { hash } from '@node-rs/argon2';
import pg from 'pg';

if (!process.env.DATABASE_URL && existsSync('.env')) {
  for (const l of readFileSync('.env', 'utf8').split(/\r?\n/)) {
    const m = l.match(/^([A-Z_]+)=(.*)$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
  }
}
const email = process.env.SENTRIX_ADMIN_EMAIL?.trim().toLowerCase();
if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
  console.error('Set SENTRIX_ADMIN_EMAIL to a valid email address.');
  process.exit(2);
}
if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set.');
  process.exit(2);
}
const name = process.env.SENTRIX_ADMIN_NAME?.trim() || 'Administrator';
let password = process.env.SENTRIX_ADMIN_PASSWORD;
let generated = false;
if (!password) {
  password = randomBytes(18).toString('base64url');
  generated = true;
}
if (password.length < 12) {
  console.error('The password must be at least 12 characters.');
  process.exit(2);
}

// Same canonical form and chaining as src/lib/audit.ts (verified by tests/bootstrap.test.ts).
const canonical = (v) => {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  return JSON.stringify(v ?? null);
};

const c = new pg.Client({ connectionString: process.env.DATABASE_URL });
await c.connect();
try {
  await c.query('BEGIN');
  await c.query('SELECT pg_advisory_xact_lock(7471001)');
  const existing = await c.query("SELECT 1 FROM users WHERE platform_role = 'super_admin' LIMIT 1");
  if (existing.rowCount) {
    await c.query('ROLLBACK');
    console.error('A Super Administrator already exists. Use the console to manage users.');
    process.exit(3);
  }
  const pw = await hash(password, { memoryCost: 65536, timeCost: 3, parallelism: 1 });
  const u = await c.query(`INSERT INTO users(email, name, password_hash, platform_role) VALUES ($1,$2,$3,'super_admin') RETURNING id`, [email, name, pw]);

  const last = await c.query('SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1');
  const prev = last.rows[0]?.hash ?? '0'.repeat(64);
  const at = new Date().toISOString();
  const detail = { email, via: 'bootstrap-admin.mjs' };
  const h = createHash('sha256').update(canonical([prev, at, u.rows[0].id, null, 'user.bootstrap_super_admin', u.rows[0].id, detail])).digest('hex');
  await c.query(
    `INSERT INTO audit_events(at, actor_id, actor_email, org_id, action, target, detail, ip, prev_hash, hash) VALUES ($1,$2,$3,NULL,'user.bootstrap_super_admin',$4,$5,NULL,$6,$7)`,
    [at, u.rows[0].id, email, u.rows[0].id, JSON.stringify(detail), prev, h],
  );
  await c.query('COMMIT');
  console.log(`Created Super Administrator ${email}`);
  if (generated) console.log(`One-time password (shown once, change it after signing in): ${password}`);
  console.log('Sign in to the console; you will be asked to set up two-step verification first.');
} catch (e) {
  await c.query('ROLLBACK').catch(() => undefined);
  console.error(`Bootstrap failed: ${e.message}`);
  process.exit(1);
} finally {
  await c.end();
}

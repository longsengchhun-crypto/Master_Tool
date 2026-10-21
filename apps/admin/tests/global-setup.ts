/**
 * Integration harness: creates a throwaway Postgres schema on the configured database (never touching real tables),
 * applies the real migrations into it, and starts the PRODUCTION build (`next start`) against it. Everything is
 * removed afterwards. Requires a prior `next build` and DATABASE_URL (apps/admin/.env).
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import type { TestProject } from 'vitest/node';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 3199;

let server: ChildProcess | null = null;
let schema = '';
let adminUrl = '';

function loadEnv() {
  const f = join(root, '.env');
  if (!existsSync(f)) return;
  for (const l of readFileSync(f, 'utf8').split(/\r?\n/)) {
    const m = l.match(/^([A-Z_]+)=(.*)$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
  }
}

export async function setup(project: TestProject) {
  loadEnv();
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required for integration tests');
  if (!existsSync(join(root, '.next', 'BUILD_ID'))) throw new Error('Run `npm run build` in apps/admin first: tests run against the production build');

  // Direct (non-pooled) endpoint: the pooler rejects the startup option we use to pin the schema.
  adminUrl = process.env.DATABASE_URL.replace('-pooler', '');
  schema = `sx_test_${randomBytes(4).toString('hex')}`;
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  await admin.query(`CREATE SCHEMA ${schema}`);
  await admin.end();

  const u = new URL(adminUrl);
  u.searchParams.set('options', `-c search_path=${schema},public`);
  const testUrl = u.toString();

  const c = new pg.Client({ connectionString: testUrl });
  await c.connect();
  for (const f of readdirSync(join(root, 'migrations')).filter((x) => x.endsWith('.sql')).sort()) {
    await c.query(readFileSync(join(root, 'migrations', f), 'utf8'));
  }
  await c.end();

  const secrets = { SESSION_SECRET: randomBytes(48).toString('base64url'), DEVICE_TOKEN_PEPPER: randomBytes(32).toString('base64url') };
  const nextBin = join(root, '..', '..', 'node_modules', 'next', 'dist', 'bin', 'next');
  server = spawn(process.execPath, [nextBin, 'start', '-p', String(PORT)], {
    cwd: root,
    env: { ...process.env, NODE_ENV: 'production', DATABASE_URL: testUrl, ...secrets, NEXT_TELEMETRY_DISABLED: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let log = '';
  server.stdout?.on('data', (d) => (log += d));
  server.stderr?.on('data', (d) => (log += d));

  const base = `http://127.0.0.1:${PORT}`;
  const deadline = Date.now() + 90_000;
  for (;;) {
    try {
      const r = await fetch(`${base}/api/health`);
      if (r.ok) break;
    } catch {
      /* not up yet */
    }
    if (server.exitCode !== null) throw new Error(`next start exited early:\n${log}`);
    if (Date.now() > deadline) throw new Error(`next start did not become healthy:\n${log}`);
    await new Promise((r) => setTimeout(r, 500));
  }

  project.provide('baseUrl', base);
  project.provide('dbUrl', testUrl);
  project.provide('secrets', secrets);
  project.provide('schema', schema);
}

export async function teardown() {
  if (server && server.exitCode === null) {
    server.kill();
    await new Promise((r) => setTimeout(r, 500));
  }
  if (schema) {
    const admin = new pg.Client({ connectionString: adminUrl });
    await admin.connect();
    await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await admin.end();
  }
}

declare module 'vitest' {
  export interface ProvidedContext {
    baseUrl: string;
    dbUrl: string;
    secrets: { SESSION_SECRET: string; DEVICE_TOKEN_PEPPER: string };
    schema: string;
  }
}

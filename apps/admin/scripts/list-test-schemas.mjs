// Lists (and with --drop removes) leftover throwaway test schemas (sx_test_*, sx_probe_*). Never touches `public`.
import { readFileSync, existsSync } from 'node:fs';
import pg from 'pg';

if (!process.env.DATABASE_URL && existsSync('.env')) {
  for (const l of readFileSync('.env', 'utf8').split(/\r?\n/)) {
    const m = l.match(/^([A-Z_]+)=(.*)$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
  }
}
const c = new pg.Client({ connectionString: process.env.DATABASE_URL.replace('-pooler', '') });
await c.connect();
const { rows } = await c.query(`SELECT schema_name FROM information_schema.schemata WHERE schema_name ~ '^sx_(test|probe)_[0-9a-f]+$'`);
console.log(rows.length ? `leftover test schemas: ${rows.map((r) => r.schema_name).join(', ')}` : 'no leftover test schemas');
if (process.argv.includes('--drop')) {
  for (const r of rows) await c.query(`DROP SCHEMA ${r.schema_name} CASCADE`);
  if (rows.length) console.log('dropped');
}
const pub = await c.query(`SELECT count(*)::int AS n FROM information_schema.tables WHERE table_schema = 'public'`);
console.log(`public tables: ${pub.rows[0].n}`);
const u = await c.query(`SELECT count(*)::int AS n FROM public.users`);
console.log(`rows in public.users (real data untouched): ${u.rows[0].n}`);
await c.end();

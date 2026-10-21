// Read-only connectivity/contents check. Usage: node scripts/dbcheck.mjs
import { readFileSync, existsSync } from 'node:fs';
import pg from 'pg';

if (!process.env.DATABASE_URL && existsSync('.env')) {
  for (const l of readFileSync('.env', 'utf8').split(/\r?\n/)) {
    const m = l.match(/^([A-Z_]+)=(.*)$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
  }
}
const c = new pg.Client({ connectionString: process.env.DATABASE_URL });
await c.connect();
console.log((await c.query('select version()')).rows[0].version);
const t = await c.query(
  "select table_schema, table_name from information_schema.tables where table_schema not in ('pg_catalog','information_schema') order by 1,2",
);
console.log('tables:', t.rows.length ? t.rows : '(none)');
await c.end();

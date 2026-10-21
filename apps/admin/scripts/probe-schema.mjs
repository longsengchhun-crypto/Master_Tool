// Verifies that an isolated, throwaway schema can be created and used via a direct (non-pooled) Neon connection.
import { readFileSync } from 'node:fs';
import pg from 'pg';

for (const l of readFileSync('.env', 'utf8').split(/\r?\n/)) {
  const m = l.match(/^([A-Z_]+)=(.*)$/);
  if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
}
const direct = process.env.DATABASE_URL.replace('-pooler', '');
const schema = `sx_probe_${Math.random().toString(16).slice(2, 8)}`;
const admin = new pg.Client({ connectionString: direct });
await admin.connect();
await admin.query(`CREATE SCHEMA ${schema}`);
const url = new URL(direct);
url.searchParams.set('options', `-c search_path=${schema},public`);
const c = new pg.Client({ connectionString: url.toString() });
await c.connect();
await c.query('CREATE TABLE t(x int)');
const where = await admin.query(`SELECT table_schema FROM information_schema.tables WHERE table_name = 't' AND table_schema = $1`, [schema]);
console.log('table landed in schema:', where.rows[0]?.table_schema === schema);
const citext = await c.query(`SELECT 'A'::citext = 'a'::citext AS ok`);
console.log('citext resolvable via search_path:', citext.rows[0].ok);
await c.end();
await admin.query(`DROP SCHEMA ${schema} CASCADE`);
await admin.end();
console.log('probe schema dropped');

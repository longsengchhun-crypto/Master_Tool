import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { pool } from './db';

export interface AuditInput {
  actorId?: string | null;
  actorEmail?: string | null;
  orgId?: string | null;
  action: string;
  target?: string | null;
  detail?: Record<string, unknown>;
  ip?: string | null;
}

const GENESIS = '0'.repeat(64);

/** Key-sorted JSON: jsonb does not preserve key order, so the hash input must be canonical. */
export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(',')}}`;
  }
  return JSON.stringify(v ?? null);
}

export function chainHash(prev: string, e: AuditInput, at: string): string {
  return createHash('sha256')
    .update(canonical([prev, at, e.actorId ?? null, e.orgId ?? null, e.action, e.target ?? null, e.detail ?? {}]))
    .digest('hex');
}

/** Append one tamper-evident audit record. A transaction-scoped advisory lock serialises the chain. */
export async function audit(e: AuditInput, existing?: PoolClient): Promise<void> {
  const c = existing ?? (await pool().connect());
  try {
    if (!existing) await c.query('BEGIN');
    await c.query('SELECT pg_advisory_xact_lock(7471001)');
    const last = await c.query<{ hash: string }>('SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1');
    const prev = last.rows[0]?.hash ?? GENESIS;
    const at = new Date().toISOString();
    await c.query(
      `INSERT INTO audit_events(at, actor_id, actor_email, org_id, action, target, detail, ip, prev_hash, hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [at, e.actorId ?? null, e.actorEmail ?? null, e.orgId ?? null, e.action, e.target ?? null,
       JSON.stringify(e.detail ?? {}), e.ip ?? null, prev, chainHash(prev, e, at)],
    );
    if (!existing) await c.query('COMMIT');
  } catch (err) {
    if (!existing) await c.query('ROLLBACK');
    throw err;
  } finally {
    if (!existing) c.release();
  }
}

/** Recompute the chain. Returns the seq of the first broken link, or null if intact. */
export async function verifyAuditChain(): Promise<number | null> {
  const { rows } = await pool().query(
    'SELECT seq, at, actor_id, org_id, action, target, detail, prev_hash, hash FROM audit_events ORDER BY seq',
  );
  let prev = GENESIS;
  for (const r of rows) {
    const h = chainHash(prev, {
      actorId: r.actor_id, orgId: r.org_id, action: r.action, target: r.target, detail: r.detail,
    }, new Date(r.at).toISOString());
    if (r.prev_hash !== prev || r.hash !== h) return Number(r.seq);
    prev = r.hash;
  }
  return null;
}

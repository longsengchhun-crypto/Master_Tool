import type { NextRequest } from 'next/server';
import { q } from './db';
import { hmac, safeEqual } from './crypto';
import { allow } from './ratelimit';
import { HttpError } from './session';

export interface DeviceCtx {
  id: string;
  orgId: string;
  hostname: string;
}

/**
 * Device authentication: `Authorization: Bearer dev_<deviceId>.<secret>`. Only HMAC(token) is stored, so a database
 * leak does not yield usable credentials. Revoked devices are rejected immediately.
 */
export async function authDevice(req: NextRequest): Promise<DeviceCtx> {
  const h = req.headers.get('authorization') ?? '';
  const m = /^Bearer (dev_([0-9a-f-]{36})\.[A-Za-z0-9_-]{32,})$/.exec(h);
  if (!m) throw new HttpError(401, 'Device authentication required', 'unauthenticated');
  const [, token, id] = m;
  if (!(await allow(`dev:${id}`, 120, 60))) throw new HttpError(429, 'Too many requests', 'rate_limited');
  const rows = await q<{ id: string; org_id: string; hostname: string; token_hash: string; status: string }>(
    'SELECT id, org_id, hostname, token_hash, status FROM devices WHERE id = $1',
    [id],
  );
  const d = rows[0];
  // Compare against a dummy when the device does not exist so response time does not reveal valid ids.
  const ok = safeEqual(hmac(token), d?.token_hash ?? '0'.repeat(64));
  if (!d || !ok || d.status !== 'enrolled') throw new HttpError(401, 'Invalid device credentials', 'unauthenticated');
  await q('UPDATE devices SET last_seen_at = now() WHERE id = $1', [d.id]);
  return { id: d.id, orgId: d.org_id, hostname: d.hostname };
}

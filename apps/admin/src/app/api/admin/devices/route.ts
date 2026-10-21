import { q } from '@/lib/db';
import { handle } from '@/lib/http';
import { authorize, scopeIds } from '@/lib/session';

export const runtime = 'nodejs';

export const GET = handle(async (req) => {
  const p = await authorize({ perm: 'device:read' });
  const status = req.nextUrl.searchParams.get('status');
  const rows = await q(
    `SELECT d.id, d.org_id, o.name AS org_name, d.hostname, d.os, d.os_version, d.app_version, d.engine_version,
            d.intel_version, d.intel_updated_at, d.protection, d.status, d.last_seen_at, d.created_at,
            (d.last_seen_at IS NULL OR d.last_seen_at < now() - interval '7 days') AS stale,
            (d.intel_updated_at IS NULL OR d.intel_updated_at < now() - interval '72 hours') AS intel_outdated
       FROM devices d JOIN organizations o ON o.id = d.org_id
      WHERE ($1::uuid[] IS NULL OR d.org_id = ANY($1)) AND ($2::text IS NULL OR d.status::text = $2)
      ORDER BY d.last_seen_at DESC NULLS LAST LIMIT 500`,
    [scopeIds(p), status === 'enrolled' || status === 'revoked' ? status : null],
  );
  return { devices: rows };
});

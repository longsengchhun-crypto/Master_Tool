import { verifyAuditChain } from '@/lib/audit';
import { q } from '@/lib/db';
import { handle } from '@/lib/http';
import { authorize, scopeIds } from '@/lib/session';

export const runtime = 'nodejs';

export const GET = handle(async (req) => {
  const p = await authorize({ perm: 'audit:read' });
  const sp = req.nextUrl.searchParams;
  if (sp.get('verify') === '1') {
    // Chain verification is global; org-scoped admins only learn whether the log is intact, nothing else.
    const broken = await verifyAuditChain();
    return { intact: broken === null, firstBrokenSeq: p.role === 'org_admin' ? undefined : broken };
  }
  const limit = Math.min(Math.max(Number(sp.get('limit')) || 100, 1), 500);
  const before = Number(sp.get('before')) || null;
  const scope = scopeIds(p);
  const rows = await q(
    `SELECT seq, at, actor_email, org_id, action, target, detail, ip::text AS ip
       FROM audit_events
      WHERE ($1::uuid[] IS NULL OR org_id = ANY($1)) AND ($2::bigint IS NULL OR seq < $2)
      ORDER BY seq DESC LIMIT $3`,
    [scope, before, limit],
  );
  return { events: rows };
});

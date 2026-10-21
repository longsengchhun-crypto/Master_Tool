import { z } from 'zod';
import { audit } from '@/lib/audit';
import { q } from '@/lib/db';
import { body, clientIpOf, csrfOf, handle } from '@/lib/http';
import { authorize, scopeIds } from '@/lib/session';

export const runtime = 'nodejs';

export const GET = handle(async () => {
  const p = await authorize({ perm: 'org:read' });
  const rows = await q(
    `SELECT o.id, o.name, o.created_at,
            (SELECT count(*) FROM devices d WHERE d.org_id = o.id AND d.status = 'enrolled') AS devices,
            (SELECT count(*) FROM memberships m WHERE m.org_id = o.id) AS members,
            (SELECT count(*) FROM licenses l WHERE l.org_id = o.id AND l.status = 'active') AS active_licenses
       FROM organizations o WHERE ($1::uuid[] IS NULL OR o.id = ANY($1)) ORDER BY o.name LIMIT 500`,
    [scopeIds(p)],
  );
  return { organizations: rows };
});

const Create = z.strictObject({ name: z.string().trim().min(2).max(120) });

export const POST = handle(async (req) => {
  const p = await authorize({ perm: 'org:manage', csrf: csrfOf(req) });
  const { name } = await body(req, Create);
  const [o] = await q<{ id: string }>('INSERT INTO organizations(name) VALUES ($1) RETURNING id', [name]);
  await audit({ actorId: p.userId, actorEmail: p.email, orgId: o.id, action: 'org.create', target: o.id, detail: { name }, ip: clientIpOf(req) });
  return { organization: { id: o.id, name } };
});

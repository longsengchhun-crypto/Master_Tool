import { z } from 'zod';
import { audit } from '@/lib/audit';
import { q, tx } from '@/lib/db';
import { body, clientIpOf, csrfOf, handle, uuidParam } from '@/lib/http';
import { authorize, HttpError } from '@/lib/session';

export const runtime = 'nodejs';

const Req = z.strictObject({
  action: z.enum(['stage', 'publish', 'cancel', 'rollback']),
  rolloutPct: z.number().int().min(1).max(100).optional(),
});

interface Row {
  version: string;
  platform: string;
  status: string;
  artifact_url: string | null;
  sha256: string | null;
  signature: string | null;
}

/**
 * Release state machine: draft -> staged (partial rollout) -> published; cancel from draft/staged; rollback from
 * published/staged. Anything offered to devices MUST carry an artifact URL, a SHA-256 and an update signature:
 * unsigned releases can never be staged or published.
 */
export const POST = handle(async (req, ctx: { params: Promise<{ id: string }> }) => {
  const p = await authorize({ perm: 'release:publish', csrf: csrfOf(req) });
  const id = uuidParam((await ctx.params).id);
  const { action, rolloutPct } = await body(req, Req);
  const [r] = await q<Row>('SELECT version, platform, status, artifact_url, sha256, signature FROM releases WHERE id = $1', [id]);
  if (!r) throw new HttpError(404, 'Not found', 'not_found');

  const needArtifacts = () => {
    if (!r.artifact_url || !r.sha256 || !r.signature) {
      throw new HttpError(409, 'A release needs an artifact URL, SHA-256 and update signature before it can be offered to devices', 'unsigned_release');
    }
  };

  let next: string;
  let pct: number | null = null;
  switch (action) {
    case 'stage':
      if (!['draft', 'staged'].includes(r.status)) throw new HttpError(409, `Cannot stage a ${r.status} release`, 'bad_state');
      needArtifacts();
      next = 'staged';
      pct = rolloutPct ?? 10;
      if (pct >= 100) throw new HttpError(400, 'Use publish for 100% rollout', 'invalid_request');
      break;
    case 'publish':
      if (!['draft', 'staged'].includes(r.status)) throw new HttpError(409, `Cannot publish a ${r.status} release`, 'bad_state');
      needArtifacts();
      next = 'published';
      pct = 100;
      break;
    case 'cancel':
      if (!['draft', 'staged'].includes(r.status)) throw new HttpError(409, `Cannot cancel a ${r.status} release`, 'bad_state');
      next = 'cancelled';
      pct = 0;
      break;
    case 'rollback':
      if (!['staged', 'published'].includes(r.status)) throw new HttpError(409, `Cannot roll back a ${r.status} release`, 'bad_state');
      next = 'rolled_back';
      pct = 0;
      break;
  }

  await tx(async (c) => {
    await c.query(
      `UPDATE releases SET status = $2::release_status, rollout_pct = $3, published_at = CASE WHEN $2 = 'published' THEN now() ELSE published_at END WHERE id = $1`,
      [id, next, pct],
    );
    await audit({ actorId: p.userId, actorEmail: p.email, action: `release.${action}`, target: id, detail: { version: r.version, platform: r.platform, rolloutPct: pct }, ip: clientIpOf(req) }, c);
  });
  return { ok: true, status: next, rolloutPct: pct };
});

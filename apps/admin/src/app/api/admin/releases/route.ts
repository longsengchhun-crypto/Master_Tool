import { ReleaseCreate } from '@sentrix/contracts';
import { audit } from '@/lib/audit';
import { q } from '@/lib/db';
import { body, clientIpOf, csrfOf, handle } from '@/lib/http';
import { authorize, HttpError } from '@/lib/session';

export const runtime = 'nodejs';

export const GET = handle(async () => {
  await authorize({ perm: 'release:read' });
  const rows = await q(
    `SELECT id, version, platform, channel, status, rollout_pct, notes, artifact_url, sha256, (signature IS NOT NULL) AS has_update_signature,
            code_signed, size_bytes, min_supported, published_at, created_at FROM releases ORDER BY created_at DESC LIMIT 200`,
  );
  return { releases: rows };
});

/** Creates a DRAFT only. Nothing is offered to devices until it is staged/published through the action endpoint. */
export const POST = handle(async (req) => {
  const p = await authorize({ perm: 'release:publish', csrf: csrfOf(req) });
  const b = await body(req, ReleaseCreate);
  try {
    const [r] = await q<{ id: string }>(
      `INSERT INTO releases(version, platform, channel, notes, artifact_url, sha256, signature, code_signed, size_bytes, min_supported)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
      [b.version, b.platform, b.channel, b.notes, b.artifactUrl ?? null, b.sha256 ?? null, b.signature ?? null, b.codeSigned, b.sizeBytes ?? null, b.minSupported ?? null],
    );
    await audit({ actorId: p.userId, actorEmail: p.email, action: 'release.create', target: r.id, detail: { version: b.version, platform: b.platform, channel: b.channel }, ip: clientIpOf(req) });
    return { release: { id: r.id } };
  } catch (e) {
    if ((e as { code?: string }).code === '23505') throw new HttpError(409, 'That version already exists for this platform and channel', 'duplicate');
    throw e;
  }
});

import { q } from '@/lib/db';
import { clientIpOf, handle } from '@/lib/http';
import { allow } from '@/lib/ratelimit';
import { HttpError } from '@/lib/session';

export const runtime = 'nodejs';

/** Public download metadata. Exposes only what a download page needs; no internal ids, no draft/staged builds. */
export const GET = handle(
  async (req) => {
    if (!(await allow(`pub:${clientIpOf(req) ?? 'unknown'}`, 120, 60))) throw new HttpError(429, 'Too many requests', 'rate_limited');
    const rows = await q(
      `SELECT DISTINCT ON (platform) version, platform, artifact_url AS url, sha256, size_bytes AS "sizeBytes", code_signed AS "codeSigned", notes, published_at AS "publishedAt"
         FROM releases WHERE status = 'published' AND channel = 'stable' AND artifact_url IS NOT NULL AND sha256 IS NOT NULL
        ORDER BY platform, string_to_array(version, '.')::int[] DESC`,
    );
    return { releases: rows };
  },
  { cookieAuth: false },
);

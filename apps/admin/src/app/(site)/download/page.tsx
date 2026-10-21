import type { Metadata } from 'next';
import { q } from '@/lib/db';
import DownloadClient, { type PublicRelease } from './client';

export const metadata: Metadata = { title: 'Download' };
export const dynamic = 'force-dynamic';

async function load(): Promise<PublicRelease[]> {
  try {
    return await q<PublicRelease>(
      `SELECT DISTINCT ON (platform) version, platform, artifact_url AS url, sha256, size_bytes::float8 AS "sizeBytes", code_signed AS "codeSigned", notes, published_at AS "publishedAt"
         FROM releases WHERE status = 'published' AND channel = 'stable' AND artifact_url IS NOT NULL AND sha256 IS NOT NULL
        ORDER BY platform, string_to_array(version, '.')::int[] DESC`,
    );
  } catch {
    return [];
  }
}

export default async function Page() {
  return (
    <main className="mx-auto max-w-4xl px-6 py-16">
      <h1 className="text-3xl font-semibold text-ink">Download SENTRIX</h1>
      <p className="mt-3 max-w-2xl text-muted">Windows 10 and 11 (64-bit) is the supported platform today. macOS and Linux builds are planned, not available.</p>
      <DownloadClient releases={await load()} />
    </main>
  );
}

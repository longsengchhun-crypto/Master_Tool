import type { Metadata } from 'next';
import { q } from '@/lib/db';

export const metadata: Metadata = { title: 'Release notes' };
export const dynamic = 'force-dynamic';

export default async function Page() {
  let rows: { version: string; platform: string; notes: string; published_at: string | null }[] = [];
  try {
    rows = await q(`SELECT version, platform, notes, published_at FROM releases WHERE status = 'published' AND channel = 'stable' ORDER BY published_at DESC NULLS LAST LIMIT 50`);
  } catch {
    /* page still renders with an empty state */
  }
  return (
    <main className="mx-auto max-w-3xl px-6 py-16">
      <h1 className="text-4xl font-semibold tracking-tight text-ink">Release notes</h1>
      {rows.length === 0 ? (
        <p className="mt-6 text-muted">No releases have been published yet.</p>
      ) : (
        <ul className="mt-10 space-y-8">
          {rows.map((r) => (
            <li key={`${r.version}-${r.platform}`} className="glass rounded-2xl p-6">
              <div className="flex items-baseline justify-between"><h2 className="text-lg font-semibold text-ink">{r.version} <span className="text-sm font-normal text-muted">{r.platform}</span></h2><span className="text-sm text-muted">{r.published_at ? new Date(r.published_at).toLocaleDateString(undefined, { dateStyle: 'long' }) : ''}</span></div>
              <p className="mt-3 whitespace-pre-line text-sm text-muted">{r.notes || 'No notes provided.'}</p>
            </li>
          ))}
        </ul>
      )}
    </main>
  );
}

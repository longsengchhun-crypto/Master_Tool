'use client';

import { useEffect, useState } from 'react';
import { Download, ShieldAlert } from 'lucide-react';

export interface PublicRelease {
  version: string;
  platform: string;
  url: string;
  sha256: string;
  sizeBytes: number | null;
  codeSigned: boolean;
  notes: string;
  publishedAt: string | null;
}

const OPTIONS = [
  { id: 'windows-x64', label: 'Windows (64-bit)', status: 'supported' },
  { id: 'macos-arm64', label: 'macOS (Apple silicon)', status: 'planned' },
  { id: 'macos-x64', label: 'macOS (Intel)', status: 'planned' },
  { id: 'linux-x64', label: 'Linux (64-bit)', status: 'planned' },
] as const;

/** Best-effort guess only. The visitor can always pick a platform manually. */
function guess(): string {
  if (typeof navigator === 'undefined') return 'windows-x64';
  const ua = navigator.userAgent.toLowerCase();
  if (ua.includes('windows')) return 'windows-x64';
  if (ua.includes('mac')) return 'macos-arm64';
  if (ua.includes('linux') && !ua.includes('android')) return 'linux-x64';
  return 'windows-x64';
}

const mb = (n: number | null) => (n ? `${(n / 1048576).toFixed(1)} MB` : 'size not published');

export default function DownloadClient({ releases }: { releases: PublicRelease[] }) {
  const [platform, setPlatform] = useState('windows-x64');
  useEffect(() => setPlatform(guess()), []);
  const opt = OPTIONS.find((o) => o.id === platform)!;
  const rel = releases.find((r) => r.platform === platform);

  return (
    <div className="mt-10">
      <div role="radiogroup" aria-label="Choose your operating system" className="mb-6 flex flex-wrap gap-2">
        {OPTIONS.map((o) => (
          <button key={o.id} role="radio" aria-checked={platform === o.id} onClick={() => setPlatform(o.id)} className={`rounded-full border px-4 py-2 text-sm transition ${platform === o.id ? 'border-accent/60 bg-accent/10 text-ink' : 'border-line text-muted hover:text-ink'}`}>
            {o.label}
          </button>
        ))}
      </div>

      <div className="glass rounded-3xl p-8">
        {!rel ? (
          <div>
            <h2 className="text-xl font-semibold text-ink">{opt.label}</h2>
            <p className="mt-2 text-muted">
              {opt.status === 'planned' ? 'This platform is planned but has no build yet. We will not list an installer until one has been built and tested.' : 'No installer has been published yet. Check back after the first release.'}
            </p>
          </div>
        ) : (
          <div>
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <h2 className="text-xl font-semibold text-ink">SENTRIX {rel.version} for {opt.label}</h2>
                <p className="mt-1 text-sm text-muted">{mb(rel.sizeBytes)} · released {rel.publishedAt ? new Date(rel.publishedAt).toLocaleDateString(undefined, { dateStyle: 'long' }) : 'date not recorded'}</p>
              </div>
              <a href={rel.url} rel="noopener noreferrer" className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-br from-accent to-accent2 px-6 py-3 text-sm font-medium text-accentink shadow-lg shadow-accent/20 hover:brightness-110">
                <Download className="size-4" /> Download installer
              </a>
            </div>

            {rel.codeSigned ? (
              <p className="mt-5 rounded-xl bg-okbg px-4 py-3 text-sm text-ok">This installer is code-signed. Windows shows the publisher name when you run it.</p>
            ) : (
              <p className="mt-5 flex gap-2 rounded-xl bg-warnbg px-4 py-3 text-sm text-warn">
                <ShieldAlert className="mt-0.5 size-4 shrink-0" />
                <span><strong>This build is not code-signed.</strong> Windows SmartScreen will warn that the publisher is unknown. Only continue if you downloaded it from this page, and verify the checksum below.</span>
              </p>
            )}

            <dl className="mt-6 text-sm">
              <dt className="font-medium text-ink">SHA-256 checksum</dt>
              <dd className="mt-1 select-all break-all rounded-lg bg-surface2 px-3 py-2 font-mono text-xs text-ink">{rel.sha256}</dd>
              <p className="mt-2 text-xs text-muted">In PowerShell: <code className="font-mono">Get-FileHash .\SENTRIX_{rel.version}_x64-setup.exe -Algorithm SHA256</code>. The result must match exactly.</p>
            </dl>
            {rel.notes && <div className="mt-6 whitespace-pre-line border-t border-line pt-5 text-sm text-muted"><div className="mb-1 font-medium text-ink">What is new</div>{rel.notes}</div>}
          </div>
        )}
      </div>
    </div>
  );
}

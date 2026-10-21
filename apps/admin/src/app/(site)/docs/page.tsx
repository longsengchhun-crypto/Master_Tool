import type { Metadata } from 'next';

export const metadata: Metadata = { title: 'Documentation' };

const VERDICTS = [
  ['Clean', 'The malware-signature engine finished and every check that applies to this file type completed, and nothing was found. Not a guarantee of safety.'],
  ['Suspicious', 'Heuristic or integrity evidence reached the documented threshold. This is evidence, not proof: legitimate software can show the same traits.'],
  ['Malicious', 'A detection engine (ClamAV, or your computer\'s own security provider) identified the file. Heuristics alone can never produce this verdict.'],
  ['Unable to verify', 'The scan could not finish: no engine available, a format SENTRIX could not fully open, an encrypted or oversized file, or the file could not be read.'],
  ['Pending', 'Analysis is still running.'],
];

export default function Docs() {
  return (
    <main className="mx-auto max-w-3xl px-6 py-16">
      <h1 className="text-4xl font-semibold tracking-tight text-ink">Documentation</h1>

      <section className="mt-10 space-y-3">
        <h2 className="text-2xl font-semibold text-ink">Getting started</h2>
        <ol className="list-decimal space-y-2 pl-6 text-muted">
          <li>Download and run the installer from the <a className="text-accent hover:underline" href="/download">download page</a>. Check the SHA-256 checksum shown there.</li>
          <li>On first launch, SENTRIX explains what it can and cannot do, then downloads malware signatures (about 300 MB once).</li>
          <li>Drop a file onto the window, or use Scan a File. Open the report to see what was checked.</li>
          <li>Optionally turn on real-time protection to scan new files in folders you choose, such as Downloads.</li>
        </ol>
      </section>

      <section className="mt-12 space-y-3">
        <h2 className="text-2xl font-semibold text-ink">What the verdicts mean</h2>
        <dl className="divide-y divide-line rounded-2xl border border-line">
          {VERDICTS.map(([k, v]) => (
            <div key={k} className="grid gap-1 px-5 py-4 sm:grid-cols-[10rem_1fr]">
              <dt className="font-medium text-ink">{k}</dt>
              <dd className="text-sm text-muted">{v}</dd>
            </div>
          ))}
        </dl>
        <p className="text-sm text-muted">SENTRIX does not show a percentage confidence, because no validated statistical model backs one.</p>
      </section>

      <section className="mt-12 space-y-3">
        <h2 className="text-2xl font-semibold text-ink">Scanning, warning and blocking are different</h2>
        <ul className="list-disc space-y-2 pl-6 text-muted">
          <li><strong className="text-ink">Scanning</strong> — SENTRIX reads a file and reports findings. Implemented.</li>
          <li><strong className="text-ink">Warning</strong> — SENTRIX notifies you and offers safe actions (quarantine, open the folder without running the file). Implemented.</li>
          <li><strong className="text-ink">Blocking</strong> — preventing a program from launching requires a signed operating-system driver. <strong className="text-ink">Not implemented.</strong> SENTRIX cannot stop a program you start.</li>
        </ul>
      </section>

      <section className="mt-12 space-y-3">
        <h2 className="text-2xl font-semibold text-ink">Supported platforms</h2>
        <div className="overflow-x-auto rounded-2xl border border-line">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-line text-xs uppercase tracking-wide text-muted"><tr><th className="px-4 py-3">Platform</th><th className="px-4 py-3">Status</th><th className="px-4 py-3">Notes</th></tr></thead>
            <tbody className="divide-y divide-line text-muted">
              <tr><td className="px-4 py-3 text-ink">Windows 10/11 x64</td><td className="px-4 py-3">Supported</td><td className="px-4 py-3">Scanning, folder monitoring, Authenticode checks, quarantine.</td></tr>
              <tr><td className="px-4 py-3 text-ink">macOS</td><td className="px-4 py-3">Not available</td><td className="px-4 py-3">Needs notarization and Apple Endpoint Security entitlements.</td></tr>
              <tr><td className="px-4 py-3 text-ink">Linux</td><td className="px-4 py-3">Not available</td><td className="px-4 py-3">Needs per-distribution packaging and fanotify integration.</td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="mt-12 space-y-3">
        <h2 className="text-2xl font-semibold text-ink">Known limitations</h2>
        <ul className="list-disc space-y-2 pl-6 text-muted">
          <li>No scanner detects everything. Expect false negatives and occasional false positives.</li>
          <li>Real-time protection scans a file after it lands on disk; it does not hook browsers or mail clients.</li>
          <li>Windows system files signed through catalogs appear as &quot;not digitally signed&quot; in the embedded-signature check.</li>
          <li>7-Zip, RAR, ISO and DMG contents are inspected by the signature engine only, not by SENTRIX&apos;s own analysers.</li>
          <li>Files above the size limit are only partly checked and are reported that way.</li>
        </ul>
      </section>
    </main>
  );
}

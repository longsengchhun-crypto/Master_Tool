import Link from 'next/link';

const POINTS = [
  ['Content decides the type', 'The file type is read from the bytes, not the name. A program renamed to .jpg is still a program, and the report says the name does not match.'],
  ['Several independent checks', 'ClamAV signatures, in-house structure and heuristic analysis, Windows digital-signature verification and archive inspection. Heuristics add evidence but can never label a file malicious on their own.'],
  ['Unfinished means unverified', 'If the engine is down, a file is locked, an archive is encrypted or a size limit was hit, the result is “Unable to verify”. A file is only called clean when the signature engine completed and nothing was left unchecked.'],
  ['Files are never run', 'Inspection happens in place. Archives are read in memory with limits against decompression bombs and path tricks, never extracted to disk.'],
  ['Quarantine you can audit', 'Encrypted vault, tamper-evident records and an audit log. Restoring something identified as malware needs a typed confirmation.'],
  ['Local by default', 'Scanning is on your computer and file contents are never uploaded. Reports can go to a Telegram bot you create yourself; that sends file names and verdicts to Telegram, and the app says so.'],
] as const;

const SAMPLE = `File         invoice_update.exe   (3.3 MB, Windows executable)
Verdict      MALICIOUS
Source       Downloads folder, downloaded from files.example-cdn.net

Checks
  [done]   File type identification
  [done]   SHA-256
  [done]   Digital signature         present, but invalid
  [done]   Malware signatures        ClamAV 1.5.4
  [done]   Static analysis

Findings
  high     Win.Trojan.Sample-1       ClamAV signature match
  high     Signature invalid         file altered after signing
  medium   Process-injection APIs    evidence only, not proof

Next step    Do not open. Quarantine, then delete if not needed.`;

export default function Home() {
  return (
    <main>
      <section className="mx-auto grid max-w-5xl gap-10 px-6 py-14 md:grid-cols-[1.1fr_1fr] md:items-center">
        <div>
          <h1 className="text-4xl font-semibold leading-tight text-ink">A file scanner that says so when it could not finish the job.</h1>
          <p className="mt-4 max-w-xl text-base text-muted">SENTRIX scans files on Windows with ClamAV and its own analysis, watches the folders you choose, and can report to a Telegram bot of your own. Every report lists what was checked and what was not.</p>
          <div className="mt-7 flex flex-wrap gap-2">
            <Link href="/download" className="inline-flex h-9 items-center rounded bg-accent px-4 text-sm font-semibold text-accentink hover:bg-accenthover">Download for Windows</Link>
            <Link href="/docs" className="inline-flex h-9 items-center rounded border border-strong px-4 text-sm font-semibold text-ink hover:bg-surface2">How it works</Link>
          </div>
          <p className="mt-3 text-xs text-faint">Windows 10 and 11, 64-bit. Pre-release builds are not code-signed, so SmartScreen will warn.</p>
        </div>
        <figure>
          <pre className="panel overflow-x-auto rounded-lg p-4 font-mono text-[12px] leading-relaxed text-ink">{SAMPLE}</pre>
          <figcaption className="mt-2 text-xs text-faint">Example report with made-up data, shown to illustrate the format.</figcaption>
        </figure>
      </section>

      <section id="features" className="border-t border-line bg-solid">
        <div className="mx-auto max-w-5xl px-6 py-12">
          <h2 className="text-xl font-semibold text-ink">How it behaves</h2>
          <dl className="mt-6 grid gap-x-10 gap-y-6 md:grid-cols-2">
            {POINTS.map(([t, d]) => (
              <div key={t} className="border-t border-line pt-3">
                <dt className="text-sm font-semibold text-ink">{t}</dt>
                <dd className="mt-1 text-sm text-muted">{d}</dd>
              </div>
            ))}
          </dl>
        </div>
      </section>

      <section className="mx-auto max-w-5xl px-6 py-12">
        <h2 className="text-xl font-semibold text-ink">What it does not do</h2>
        <ol className="mt-4 max-w-3xl list-decimal space-y-2 pl-5 text-sm text-muted">
          <li>It does not detect everything. A clean result means the checks that ran found nothing.</li>
          <li>It cannot stop a download or a program from starting, apart from an optional permission it can set on files a malware engine confirmed. Stopping arbitrary programs needs a signed driver, which is a separate project.</li>
          <li>It does not replace Windows Security. Keep Defender and SmartScreen on.</li>
          <li>It watches folders you choose, not every browser or mail client, and it scans after a file arrives.</li>
          <li>If you choose to sign in, it checks files sent to your Telegram account, after Telegram delivers them to your computer. It never reads message text, never asks for your password, and cannot see secret chats or content Telegram protects. You can also use it without signing in: it scans files Telegram Desktop saved to disk. Either way, results come to your own private chat with the SENTRIX bot, never into a group. If you ask it to protect a group, the files posted there are checked on SENTRIX's server and deleted straight away.</li>
        </ol>
      </section>
    </main>
  );
}

import Link from 'next/link';
import { Archive, Eye, FileSearch, Layers, Lock, RefreshCw } from 'lucide-react';

const FEATURES = [
  { icon: Layers, title: 'Layered detection', body: 'File type is read from content, not the name. Malware signatures (ClamAV), structure analysis, digital-signature checks and heuristics each add evidence, and heuristics alone never call a file malicious.' },
  { icon: Eye, title: 'Honest reports', body: 'Every result lists what was checked and what could not be. If a scan was partial, the file is reported as unable to verify, never as clean.' },
  { icon: FileSearch, title: 'Safe by design', body: 'Files are inspected in place and never executed. Archives are examined in memory with strict limits against decompression bombs and path tricks.' },
  { icon: Archive, title: 'Encrypted quarantine', body: 'Suspicious files are locked in encrypted storage with tamper-evident records and an audit log. Restoring malware needs an extra, typed confirmation.' },
  { icon: Lock, title: 'Local and private', body: 'Scanning happens on your computer. File contents are never uploaded, and optional health reporting is off unless you or your organization turn it on.' },
  { icon: RefreshCw, title: 'Verified updates', body: 'App updates are signed and checked before install, and rolled out in stages. Malware signatures update separately.' },
];

export default function Home() {
  return (
    <main>
      <section className="mx-auto max-w-6xl px-6 pb-16 pt-20 text-center">
        <p className="mb-5 inline-block rounded-full border border-line px-4 py-1.5 text-xs font-medium text-muted">For Windows 10 and 11</p>
        <h1 className="mx-auto max-w-3xl text-5xl font-semibold leading-[1.1] tracking-tight text-ink md:text-6xl">
          Know what is in a file <span className="bg-gradient-to-r from-accent to-accent2 bg-clip-text text-transparent">before you open it.</span>
        </h1>
        <p className="mx-auto mt-6 max-w-2xl text-lg text-muted">SENTRIX inspects files with a layered detection engine and explains every result in plain language, including what it could not check.</p>
        <div className="mt-9 flex flex-wrap justify-center gap-3">
          <Link href="/download" className="rounded-xl bg-gradient-to-br from-accent to-accent2 px-7 py-3.5 text-base font-medium text-accentink shadow-lg shadow-accent/20 hover:brightness-110">Download for Windows</Link>
          <Link href="/docs" className="rounded-xl border border-line px-7 py-3.5 text-base font-medium text-ink hover:border-strong hover:bg-surface2">How it works</Link>
        </div>
      </section>

      <section id="features" className="mx-auto max-w-6xl px-6 py-16">
        <h2 className="mb-10 text-center text-3xl font-semibold tracking-tight text-ink">Built to be trusted, not just to look secure</h2>
        <div className="grid gap-5 md:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map(({ icon: Icon, title, body }) => (
            <div key={title} className="glass rounded-2xl p-6">
              <div className="mb-4 grid size-11 place-items-center rounded-xl bg-gradient-to-br from-accent/20 to-accent2/20 text-accent"><Icon className="size-5" strokeWidth={1.8} /></div>
              <h3 className="text-base font-semibold text-ink">{title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-muted">{body}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-6 py-16">
        <div className="glass rounded-3xl p-10">
          <h2 className="text-2xl font-semibold tracking-tight text-ink">What SENTRIX does not do</h2>
          <ul className="mt-5 grid gap-3 text-sm text-muted md:grid-cols-2">
            <li>• It does not claim to detect every threat. No scanner does, and a clean result is not a guarantee.</li>
            <li>• It does not stop programs you launch from running. That needs an operating-system driver, which is a separate project.</li>
            <li>• It does not replace Windows Security. Keep Defender and SmartScreen on; SENTRIX adds checks alongside them.</li>
            <li>• It does not watch every browser or mail client. It watches the folders you choose and scans files after they arrive.</li>
          </ul>
        </div>
      </section>
    </main>
  );
}

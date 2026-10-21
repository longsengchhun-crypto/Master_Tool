import type { Metadata } from 'next';

export const metadata: Metadata = { title: 'Privacy policy' };

export default function Privacy() {
  return (
    <main className="mx-auto max-w-3xl px-6 py-16">
      <div className="mb-8 rounded-xl bg-warnbg px-4 py-3 text-sm text-warn">Draft for legal review. This describes what the software actually does today; it has not been reviewed by counsel and must be before public launch.</div>
      <h1 className="text-4xl font-semibold tracking-tight text-ink">Privacy policy</h1>
      <div className="mt-8 space-y-8 text-muted [&_h2]:mb-2 [&_h2]:text-xl [&_h2]:font-semibold [&_h2]:text-ink [&_li]:mt-1.5 [&_ul]:list-disc [&_ul]:pl-6">
        <section>
          <h2>The short version</h2>
          <p>SENTRIX scans files on your computer. File contents are never uploaded. Nothing leaves your device unless you enroll it with an organization or turn on optional health reporting.</p>
        </section>
        <section>
          <h2>What stays on your device</h2>
          <ul><li>File contents and file names you scan.</li><li>Scan history, reports and the quarantine vault (encrypted).</li><li>Your settings.</li></ul>
        </section>
        <section>
          <h2>What leaves your device</h2>
          <ul>
            <li><strong className="text-ink">Signature downloads.</strong> SENTRIX fetches ClamAV malware signatures from ClamAV&apos;s public servers. These requests contain no information about your files. Your IP address is visible to those servers, as with any download.</li>
            <li><strong className="text-ink">Application updates</strong> (once enabled): a request to our update server containing your app version and platform.</li>
            <li><strong className="text-ink">Organization enrollment (optional).</strong> If an administrator gives you an enrollment code and you enroll, the device reports: host name, operating system and version, app and engine versions, protection state, signature age, and last check-in time. With health reporting on, it also sends scan counts and, per finding, a file hash and verdict. File names are sent only if your organization&apos;s policy explicitly allows it. File contents are never sent.</li>
          </ul>
        </section>
        <section>
          <h2>What we never collect</h2>
          <p>Passwords, keystrokes, browsing contents, documents, or unrelated personal data. Administrators cannot use the console to read your files, and there is no remote shell or hidden remote control. Remote requests are limited to a fixed list (quick scan, signature update, update check) and are visible to you.</p>
        </section>
        <section>
          <h2>Your control</h2>
          <ul><li>You can remove a device from management at any time from the app; this stops all reporting.</li><li>Turning off health reporting never turns off protection.</li><li>You can clear scan history in Settings.</li></ul>
        </section>
        <section>
          <h2>Retention</h2>
          <p>Retention periods for console data (scan findings, events, audit logs) are set by the operator of the console and must be stated here before launch. Not yet configured.</p>
        </section>
      </div>
    </main>
  );
}

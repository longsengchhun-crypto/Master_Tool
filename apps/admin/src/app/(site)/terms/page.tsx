import type { Metadata } from 'next';

export const metadata: Metadata = { title: 'Terms of service' };

export default function Terms() {
  return (
    <main className="mx-auto max-w-3xl px-6 py-16">
      <div className="mb-8 rounded bg-warnbg px-4 py-3 text-sm text-warn">Draft for legal review. Placeholder terms that state the product&apos;s real limits; governing law, liability caps and entity details must be completed by counsel before launch.</div>
      <h1 className="text-3xl font-semibold text-ink">Terms of service</h1>
      <div className="mt-8 space-y-8 text-muted [&_h2]:mb-2 [&_h2]:text-xl [&_h2]:font-semibold [&_h2]:text-ink">
        <section><h2>No guarantee of protection</h2><p>SENTRIX is a file-inspection tool. It does not detect every threat, and a result of &quot;clean&quot; is not a guarantee that a file is safe. You remain responsible for the files you open and for maintaining other security measures, including the operating system&apos;s built-in protection.</p></section>
        <section><h2>Third-party components</h2><p>SENTRIX uses ClamAV, licensed under the GNU GPL v2, as a separate program. Its license and source availability are provided with the installer.</p></section>
        <section><h2>Acceptable use</h2><p>Use SENTRIX only on devices you own or are authorized to manage. Do not use it to scan data you have no right to inspect.</p></section>
        <section><h2>Organizations and administrators</h2><p>If an organization enrolls your device, its administrators can see the reported information described in the privacy policy and push the settings and fixed requests described there. They cannot read your files or run arbitrary commands.</p></section>
        <section><h2>Licenses</h2><p>Paid features require a valid license. A revoked or expired license is reported to the device at its next check-in.</p></section>
        <section><h2>Warranty and liability</h2><p>Terms on warranty, limitation of liability and governing law: to be completed by counsel.</p></section>
      </div>
    </main>
  );
}

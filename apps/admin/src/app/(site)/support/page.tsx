import type { Metadata } from 'next';

export const metadata: Metadata = { title: 'Support' };

export default function Support() {
  const email = process.env.NEXT_PUBLIC_SUPPORT_EMAIL;
  return (
    <main className="mx-auto max-w-3xl px-6 py-16">
      <h1 className="text-3xl font-semibold text-ink">Support</h1>
      <div className="mt-8 space-y-6 text-muted">
        <p>
          {email ? (<>Contact us at <a className="text-accent hover:underline" href={`mailto:${email}`}>{email}</a>.</>) : 'A support contact has not been configured for this deployment yet.'}
        </p>
        <div className="panel rounded-lg p-5">
          <h2 className="text-base font-semibold text-ink">When you write to us, please include</h2>
          <ul className="mt-3 list-disc space-y-1.5 pl-6 text-sm">
            <li>The SENTRIX version (Settings, then About) and your Windows version.</li>
            <li>The report for the file in question: open it under Reports, then Copy report. It contains no file contents.</li>
            <li>What you expected and what happened instead.</li>
          </ul>
          <p className="mt-4 text-sm">Please do not send suspected malware by email. If you believe a detection is a false positive, send the report and the file&apos;s SHA-256 hash.</p>
        </div>
        <div className="panel rounded-lg p-5">
          <h2 className="text-base font-semibold text-ink">Reporting a security problem</h2>
          <p className="mt-2 text-sm">If you found a vulnerability in SENTRIX or this site, contact us privately before disclosing it publicly. See SECURITY.md in the repository for the process.</p>
        </div>
      </div>
    </main>
  );
}

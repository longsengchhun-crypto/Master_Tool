'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Button, Field, Logo, Notice, inputCls } from '@/components/ui';

export default function MfaSetup({ csrf, email }: { csrf: string; email: string }) {
  const router = useRouter();
  const [secret, setSecret] = useState<string | null>(null);
  const [uri, setUri] = useState<string | null>(null);
  const [token, setToken] = useState('');
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    fetch('/api/auth/mfa/setup', { method: 'POST', headers: { 'x-csrf-token': csrf } })
      .then(async (r) => ({ ok: r.ok, j: await r.json() }))
      .then(({ ok, j }) => {
        if (!ok) throw new Error(j?.error?.message ?? 'Could not start setup');
        setSecret(j.secret);
        setUri(j.uri);
      })
      .catch((e) => setError(e.message));
  }, [csrf]);

  async function verify(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await fetch('/api/auth/mfa/enable', { method: 'POST', headers: { 'content-type': 'application/json', 'x-csrf-token': csrf }, body: JSON.stringify({ token }) });
      const j = await r.json();
      if (!r.ok) throw new Error(j?.error?.message ?? 'Invalid code');
      setCodes(j.recoveryCodes);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid code');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="grid min-h-screen place-items-center p-6">
      <div className="panel w-full max-w-lg rounded-lg p-7">
        <div className="mb-6 flex items-center gap-3">
          <Logo size={40} />
          <div>
            <div className="text-lg font-semibold text-ink">Set up two-step verification</div>
            <div className="text-xs text-muted">Required for every administrator account · {email}</div>
          </div>
        </div>

        {!codes ? (
          <form onSubmit={verify} className="space-y-5">
            <ol className="list-decimal space-y-2 pl-5 text-sm text-muted">
              <li>Open an authenticator app (Microsoft Authenticator, Google Authenticator, 1Password…).</li>
              <li>Add an account using this setup key. It is shown once, so enter it now.</li>
            </ol>
            {secret ? (
              <div className="rounded border border-line bg-surface2 p-4">
                <div className="text-xs text-muted">Setup key</div>
                <div className="mt-1 select-all break-all font-mono text-base tracking-wider text-ink">{secret.match(/.{1,4}/g)?.join(' ')}</div>
                {uri && (
                  <a href={uri} className="mt-2 inline-block text-xs text-accent hover:underline">
                    Open in authenticator app
                  </a>
                )}
              </div>
            ) : (
              !error && <p className="text-sm text-muted">Generating key…</p>
            )}
            <Field label="Enter the 6-digit code to confirm">
              <input inputMode="numeric" pattern="\d{6}" maxLength={6} className={inputCls} value={token} onChange={(e) => setToken(e.target.value.replace(/\D/g, ''))} placeholder="123456" autoComplete="one-time-code" />
            </Field>
            {error && <Notice tone="danger">{error}</Notice>}
            <Button type="submit" variant="primary" className="w-full" busy={busy} disabled={!secret || token.length !== 6}>
              Turn on verification
            </Button>
          </form>
        ) : (
          <div className="space-y-5">
            <Notice tone="warn" title="Save your recovery codes now">
              Each code works once if you lose your authenticator. They are shown only this time and are stored only as hashes.
            </Notice>
            <ul className="grid grid-cols-2 gap-2 rounded border border-line bg-surface2 p-4 font-mono text-sm text-ink">
              {codes.map((c) => (
                <li key={c} className="select-all">{c}</li>
              ))}
            </ul>
            <Button variant="primary" className="w-full" onClick={() => { router.replace('/console'); router.refresh(); }}>
              I saved them, continue
            </Button>
          </div>
        )}
      </div>
    </main>
  );
}

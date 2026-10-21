'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Button, Field, Logo, Notice, inputCls } from '@/components/ui';

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [totp, setTotp] = useState('');
  const [needCode, setNeedCode] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email, password, ...(needCode && totp ? { totp: totp.trim() } : {}) }),
      });
      const j = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(j?.error?.message ?? 'Sign-in failed');
      if (j.mfaRequired) {
        setNeedCode(true);
        return;
      }
      router.replace(j.mfaSetupRequired ? '/setup-mfa' : '/console');
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign-in failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="ambient grid min-h-screen place-items-center p-6">
      <div className="glass w-full max-w-md rounded-3xl p-8" style={{ background: 'var(--surface-solid)' }}>
        <div className="mb-8 flex items-center gap-3">
          <Logo size={40} />
          <div>
            <div className="text-lg font-semibold leading-tight text-ink">SENTRIX Console</div>
            <div className="text-xs text-muted">Administrator sign-in</div>
          </div>
        </div>
        <form onSubmit={submit} className="space-y-4">
          <Field label="Email">
            <input type="email" required autoComplete="username" className={inputCls} value={email} onChange={(e) => setEmail(e.target.value)} disabled={needCode} />
          </Field>
          <Field label="Password">
            <input type="password" required autoComplete="current-password" className={inputCls} value={password} onChange={(e) => setPassword(e.target.value)} disabled={needCode} />
          </Field>
          {needCode && (
            <Field label="Verification code" hint="From your authenticator app, or a one-time recovery code.">
              <input autoFocus inputMode="text" autoComplete="one-time-code" className={inputCls} value={totp} onChange={(e) => setTotp(e.target.value)} placeholder="123456" />
            </Field>
          )}
          {error && <Notice tone="danger">{error}</Notice>}
          <Button type="submit" variant="primary" className="w-full" busy={busy}>
            {needCode ? 'Verify and sign in' : 'Sign in'}
          </Button>
        </form>
        <p className="mt-6 text-xs text-muted">Access is limited to authorized administrators. Sign-ins and actions are logged.</p>
      </div>
    </main>
  );
}

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
    <main className="grid min-h-screen md:grid-cols-[minmax(0,5fr)_minmax(0,6fr)]">
      <aside className="hidden flex-col justify-between bg-[#10233C] p-10 text-[#F5F3EE] md:flex">
        <div className="flex items-center gap-2.5">
          <Logo size={28} />
          <span className="text-[13px] font-semibold tracking-[0.12em]">SENTRIX</span>
        </div>
        <div>
          <h1 className="max-w-xs text-2xl font-semibold leading-snug">Fleet console</h1>
          <p className="mt-2 max-w-xs text-sm text-[#F5F3EE]/70">Devices, licenses, policies and releases. Every administrator account requires two-step verification, and every action is written to a tamper-evident audit log.</p>
        </div>
        <p className="text-xs text-[#F5F3EE]/50">Authorized administrators only.</p>
      </aside>

      <section className="grid place-items-center p-6">
        <div className="w-full max-w-sm">
          <div className="mb-6 flex items-center gap-2.5 md:hidden">
            <Logo size={26} />
            <span className="text-[13px] font-semibold tracking-[0.12em] text-ink">SENTRIX</span>
          </div>
          <h2 className="text-xl font-semibold text-ink">{needCode ? 'Two-step verification' : 'Sign in'}</h2>
          <form onSubmit={submit} className="mt-5 space-y-4">
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
        </div>
      </section>
    </main>
  );
}

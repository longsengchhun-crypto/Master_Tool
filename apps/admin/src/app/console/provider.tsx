'use client';

import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react';
import { Button, Field, Modal, inputCls } from '@/components/ui';

export interface Me {
  email: string;
  name: string;
  role: 'super_admin' | 'security_admin' | 'org_admin' | 'support' | 'auditor';
  csrf: string;
}

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

interface Ctx {
  me: Me;
  /** JSON call with CSRF header; transparently asks for the password again when the server requires re-authentication. */
  call: <T = unknown>(path: string, init?: { method?: string; body?: unknown }) => Promise<T>;
}

const C = createContext<Ctx | null>(null);
export const useConsole = () => {
  const c = useContext(C);
  if (!c) throw new Error('useConsole outside provider');
  return c;
};

export function ConsoleProvider({ me, children }: { me: Me; children: ReactNode }) {
  const [reauth, setReauth] = useState(false);
  const [pw, setPw] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const waiter = useRef<{ resolve: () => void; reject: (e: Error) => void } | null>(null);

  const raw = useCallback(
    async (path: string, init?: { method?: string; body?: unknown }) => {
      const method = init?.method ?? 'GET';
      const res = await fetch(path, {
        method,
        headers: { 'content-type': 'application/json', ...(method !== 'GET' ? { 'x-csrf-token': me.csrf } : {}) },
        body: init?.body === undefined ? undefined : JSON.stringify(init.body),
        credentials: 'same-origin',
      });
      const json = await res.json().catch(() => ({}));
      if (!res.ok) throw new ApiError(res.status, json?.error?.code ?? 'error', json?.error?.message ?? `Request failed (${res.status})`);
      return json;
    },
    [me.csrf],
  );

  const call = useCallback(
    async <T,>(path: string, init?: { method?: string; body?: unknown }): Promise<T> => {
      try {
        return (await raw(path, init)) as T;
      } catch (e) {
        if (e instanceof ApiError && e.code === 'reauth_required') {
          await new Promise<void>((resolve, reject) => {
            waiter.current = { resolve, reject };
            setReauth(true);
          });
          return (await raw(path, init)) as T;
        }
        throw e;
      }
    },
    [raw],
  );

  const submit = async () => {
    setBusy(true);
    setErr(null);
    try {
      await raw('/api/auth/reauth', { method: 'POST', body: { password: pw } });
      setPw('');
      setReauth(false);
      waiter.current?.resolve();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Could not verify your password');
    } finally {
      setBusy(false);
    }
  };

  const cancel = () => {
    setReauth(false);
    setPw('');
    waiter.current?.reject(new Error('Action cancelled'));
  };

  const value = useMemo(() => ({ me, call }), [me, call]);
  return (
    <C.Provider value={value}>
      {children}
      <Modal
        open={reauth}
        onClose={cancel}
        title="Confirm it's you"
        footer={
          <>
            <Button onClick={cancel}>Cancel</Button>
            <Button variant="primary" busy={busy} onClick={submit} disabled={!pw}>
              Continue
            </Button>
          </>
        }
      >
        <p className="mb-4">This action is sensitive. Enter your password to continue. You will not be asked again for 10 minutes.</p>
        <Field label="Password">
          <input type="password" autoFocus autoComplete="current-password" className={inputCls} value={pw} onChange={(e) => setPw(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && pw && submit()} />
        </Field>
        {err && <p role="alert" className="mt-3 text-danger">{err}</p>}
      </Modal>
    </C.Provider>
  );
}

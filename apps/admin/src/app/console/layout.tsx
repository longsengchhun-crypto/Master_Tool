import { redirect } from 'next/navigation';
import { currentPrincipal } from '@/lib/session';
import { ConsoleProvider } from './provider';
import { Nav } from './nav';

export const dynamic = 'force-dynamic';

export default async function ConsoleLayout({ children }: { children: React.ReactNode }) {
  const p = await currentPrincipal();
  if (!p) redirect('/login');
  if (!p.role) redirect('/login');
  if (!p.mfaEnabled || !p.mfaVerified) redirect(p.mfaEnabled ? '/login' : '/setup-mfa');
  const me = { email: p.email, name: p.name, role: p.role, csrf: p.csrf };
  return (
    <ConsoleProvider me={me}>
      <div className="flex min-h-screen">
        <Nav role={p.role} email={p.email} />
        <main className="min-w-0 flex-1 px-8 py-6">
          <div className="mx-auto max-w-[1160px]">{children}</div>
        </main>
      </div>
    </ConsoleProvider>
  );
}

import { redirect } from 'next/navigation';
import { currentPrincipal } from '@/lib/session';
import MfaSetup from './setup';

export const dynamic = 'force-dynamic';

export default async function Page() {
  const p = await currentPrincipal();
  if (!p) redirect('/login');
  if (p.mfaEnabled && p.mfaVerified) redirect('/console');
  return <MfaSetup csrf={p.csrf} email={p.email} />;
}

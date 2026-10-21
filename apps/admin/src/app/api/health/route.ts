import { NextResponse } from 'next/server';
import { q } from '@/lib/db';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** Liveness + database reachability. Deliberately reveals nothing about versions, schema or configuration. */
export async function GET() {
  try {
    await q('SELECT 1');
    return NextResponse.json({ status: 'ok' });
  } catch {
    return NextResponse.json({ status: 'degraded' }, { status: 503 });
  }
}

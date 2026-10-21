import { NextResponse } from 'next/server';

export const runtime = 'nodejs';

// Unknown API paths answer in JSON like every other endpoint, never with the framework's HTML error page.
const notFound = () => NextResponse.json({ error: { code: 'not_found', message: 'Not found' } }, { status: 404 });

export const GET = notFound;
export const POST = notFound;
export const PUT = notFound;
export const PATCH = notFound;
export const DELETE = notFound;

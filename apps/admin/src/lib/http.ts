import { NextResponse, type NextRequest } from 'next/server';
import { ZodError, type ZodType } from 'zod';
import { HttpError } from './session';

const MAX_BODY = 256 * 1024;

type Handler<C> = (req: NextRequest, ctx: C) => Promise<Response | Record<string, unknown> | unknown[]>;

function err(status: number, code: string, message: string, extra?: Record<string, unknown>) {
  return NextResponse.json({ error: { code, message, ...extra } }, { status });
}

/** True when the browser says the request came from another origin. Defense in depth next to SameSite=Strict + CSRF token. */
function crossOrigin(req: NextRequest): boolean {
  const origin = req.headers.get('origin');
  if (!origin) return false; // non-browser clients (device agent) send none; they authenticate with bearer tokens, not cookies
  try {
    return new URL(origin).host !== req.headers.get('host');
  } catch {
    return true;
  }
}

/**
 * Wraps a route handler: maps known errors to JSON, hides internals from clients, and rejects cross-origin
 * state-changing requests. Unexpected errors are logged (message only, no stack/secrets) and returned as a generic 500.
 */
export function handle<C = unknown>(fn: Handler<C>, opts: { cookieAuth?: boolean } = { cookieAuth: true }) {
  return async (req: NextRequest, ctx: C): Promise<Response> => {
    try {
      if (opts.cookieAuth !== false && req.method !== 'GET' && req.method !== 'HEAD' && crossOrigin(req)) {
        throw new HttpError(403, 'Cross-origin request rejected', 'cross_origin');
      }
      const r = await fn(req, ctx);
      return r instanceof Response ? r : NextResponse.json(r);
    } catch (e) {
      if (e instanceof HttpError) return err(e.status, e.code, e.message);
      if (e instanceof ZodError) {
        return err(400, 'invalid_request', 'The request was not valid', { issues: e.issues.map((i) => ({ path: i.path.join('.'), message: i.message })) });
      }
      console.error(JSON.stringify({ level: 'error', msg: e instanceof Error ? e.message : 'unknown', path: req.nextUrl.pathname, method: req.method }));
      return err(500, 'internal', 'Something went wrong');
    }
  };
}

/** Parse and validate a JSON body with a hard size cap. Unknown keys are rejected by strictObject schemas. */
export async function body<T>(req: NextRequest, schema: ZodType<T>): Promise<T> {
  const len = Number(req.headers.get('content-length') ?? '0');
  if (len > MAX_BODY) throw new HttpError(413, 'Request too large', 'too_large');
  const text = await req.text();
  if (text.length > MAX_BODY) throw new HttpError(413, 'Request too large', 'too_large');
  let json: unknown;
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    throw new HttpError(400, 'Body must be valid JSON', 'bad_json');
  }
  return schema.parse(json);
}

export const csrfOf = (req: NextRequest) => req.headers.get('x-csrf-token');

export function uuidParam(v: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) throw new HttpError(404, 'Not found', 'not_found');
  return v.toLowerCase();
}

export function clientIpOf(req: NextRequest): string | null {
  // Behind a trusted proxy (Vercel/Cloud Run/nginx) the first XFF hop is the client; otherwise this is advisory only.
  return req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || req.headers.get('x-real-ip') || null;
}

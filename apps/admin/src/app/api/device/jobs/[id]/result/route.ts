import { z } from 'zod';
import { q } from '@/lib/db';
import { authDevice } from '@/lib/device-auth';
import { body, handle, uuidParam } from '@/lib/http';
import { HttpError } from '@/lib/session';

export const runtime = 'nodejs';

const Req = z.strictObject({ state: z.enum(['succeeded', 'failed']), result: z.string().max(500).optional() });

/** A device can only report on jobs addressed to itself that it has already received. */
export const POST = handle(
  async (req, ctx: { params: Promise<{ id: string }> }) => {
    const dev = await authDevice(req);
    const id = uuidParam((await ctx.params).id);
    const b = await body(req, Req);
    const r = await q("UPDATE update_jobs SET state = $3, result = $4, updated_at = now() WHERE id = $1 AND device_id = $2 AND state = 'delivered' RETURNING id", [id, dev.id, b.state, b.result ?? null]);
    if (!r[0]) throw new HttpError(404, 'Not found', 'not_found');
    return { ok: true };
  },
  { cookieAuth: false },
);

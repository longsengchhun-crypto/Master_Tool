import { z } from 'zod';
import { SecurityEventIn } from '@sentrix/contracts';
import { tx } from '@/lib/db';
import { authDevice } from '@/lib/device-auth';
import { body, handle } from '@/lib/http';

export const runtime = 'nodejs';

const Req = z.strictObject({ events: z.array(SecurityEventIn).min(1).max(50) });

export const POST = handle(
  async (req) => {
    const dev = await authDevice(req);
    const { events } = await body(req, Req);
    await tx(async (c) => {
      for (const e of events) {
        await c.query('INSERT INTO security_events(device_id, kind, severity, detail) VALUES ($1,$2,$3,$4)', [dev.id, e.kind, e.severity, e.detail ?? null]);
      }
    });
    return { ok: true, accepted: events.length };
  },
  { cookieAuth: false },
);

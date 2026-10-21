import { ScanSessionIn } from '@sentrix/contracts';
import { tx } from '@/lib/db';
import { authDevice } from '@/lib/device-auth';
import { policyForOrg } from '@/lib/device-support';
import { body, handle } from '@/lib/http';

export const runtime = 'nodejs';

/**
 * Receive scan metadata: counts and per-finding hash + verdict. Never file contents. File names are stored only if the
 * organization's policy explicitly allows it; otherwise they are dropped on the server even if the device sent them.
 */
export const POST = handle(
  async (req) => {
    const dev = await authDevice(req);
    const b = await body(req, ScanSessionIn);
    const policy = await policyForOrg(dev.orgId);
    const id = await tx(async (c) => {
      const s = await c.query<{ id: string }>(
        `INSERT INTO scan_sessions(device_id, started_at, finished_at, kind, files_total, files_failed, complete) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
        [dev.id, b.startedAt, b.finishedAt, b.kind, b.filesTotal, b.filesFailed, b.complete],
      );
      for (const f of b.findings) {
        await c.query(
          `INSERT INTO scan_findings(session_id, device_id, sha256, file_name, verdict, source, engine_version, detail) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [s.rows[0].id, dev.id, f.sha256, policy.allowFileNameTelemetry ? (f.fileName ?? null) : null, f.verdict, f.source, f.engineVersion ?? null, f.detail ?? null],
        );
      }
      return s.rows[0].id;
    });
    return { ok: true, sessionId: id };
  },
  { cookieAuth: false },
);

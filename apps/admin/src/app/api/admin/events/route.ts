import { q } from '@/lib/db';
import { handle } from '@/lib/http';
import { authorize, scopeIds } from '@/lib/session';

export const runtime = 'nodejs';

export const GET = handle(async () => {
  const p = await authorize({ perm: 'telemetry:read' });
  const scope = scopeIds(p);
  const events = await q(
    `SELECT e.id, e.kind, e.severity, e.detail, e.created_at, d.id AS device_id, d.hostname, o.name AS org_name
       FROM security_events e JOIN devices d ON d.id = e.device_id JOIN organizations o ON o.id = d.org_id
      WHERE ($1::uuid[] IS NULL OR d.org_id = ANY($1)) ORDER BY e.created_at DESC LIMIT 200`,
    [scope],
  );
  // Findings carry hashes and verdicts only; file names appear only if the device policy allowed sending them.
  const findings = await q(
    `SELECT f.id, f.sha256, f.file_name, f.verdict::text AS verdict, f.source, f.engine_version, f.detail, f.found_at, d.hostname, o.name AS org_name
       FROM scan_findings f JOIN devices d ON d.id = f.device_id JOIN organizations o ON o.id = d.org_id
      WHERE f.verdict <> 'CLEAN' AND ($1::uuid[] IS NULL OR d.org_id = ANY($1)) ORDER BY f.found_at DESC LIMIT 200`,
    [scope],
  );
  return { events, findings };
});

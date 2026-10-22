import { q } from '@/lib/db';
import { handle } from '@/lib/http';
import { authorize, scopeIds } from '@/lib/session';

export const runtime = 'nodejs';

/**
 * Operational health and security-detection metrics are returned in separate sections on purpose: a high number of
 * detections is not evidence the product works, and a low number is not evidence of safety.
 */
export const GET = handle(async () => {
  const p = await authorize({ perm: 'telemetry:read' });
  const scope = scopeIds(p);

  const [fleet] = await q<Record<string, string>>(
    `SELECT count(*) FILTER (WHERE status = 'enrolled') AS enrolled,
            count(*) FILTER (WHERE status = 'enrolled' AND last_seen_at > now() - interval '24 hours') AS seen_24h,
            count(*) FILTER (WHERE status = 'enrolled' AND (last_seen_at IS NULL OR last_seen_at < now() - interval '7 days')) AS stale,
            count(*) FILTER (WHERE status = 'enrolled' AND (intel_updated_at IS NULL OR intel_updated_at < now() - interval '72 hours')) AS outdated_intel,
            count(*) FILTER (WHERE status = 'enrolled' AND protection->>'engineState' IS DISTINCT FROM 'running') AS engine_not_running,
            count(*) FILTER (WHERE status = 'enrolled' AND protection->>'realtimeState' = 'error') AS realtime_error,
            count(*) FILTER (WHERE status = 'revoked') AS revoked,
            -- Phase 2 health (aggregates of device-reported counts/booleans; never file names, chat ids or tokens)
            count(*) FILTER (WHERE status = 'enrolled' AND COALESCE((queue->>'failed')::int, 0) > 0) AS devices_with_unchecked_files,
            count(*) FILTER (WHERE status = 'enrolled' AND COALESCE((queue->>'stuck')::int, 0) > 0) AS devices_with_stuck_scans,
            count(*) FILTER (WHERE status = 'enrolled' AND COALESCE((queue->>'queued')::int, 0) > 0) AS devices_with_backlog,
            count(*) FILTER (WHERE status = 'enrolled' AND telegram->>'botConnected' = 'true') AS telegram_bots_connected,
            count(*) FILTER (WHERE status = 'enrolled' AND COALESCE((telegram->>'deliveryFailures24h')::int, 0) > 0) AS telegram_delivery_failures,
            -- Personal Telegram account protection (device-reported state and counts only)
            count(*) FILTER (WHERE status = 'enrolled' AND telegram->>'accountState' = 'connected') AS tg_accounts_connected,
            count(*) FILTER (WHERE status = 'enrolled' AND telegram->>'accountState' = 'expired') AS tg_accounts_expired,
            COALESCE(sum((telegram->'account'->>'scanned')::int) FILTER (WHERE status = 'enrolled'), 0) AS tg_account_checked,
            COALESCE(sum((telegram->'account'->>'threats')::int) FILTER (WHERE status = 'enrolled'), 0) AS tg_account_threats,
            COALESCE(sum((telegram->'account'->>'unverified')::int) FILTER (WHERE status = 'enrolled'), 0) AS tg_account_unverified,
            -- Group Shield (device-reported counts only)
            COALESCE(sum((tg_groups->>'registered')::int) FILTER (WHERE status = 'enrolled'), 0) AS tg_groups_registered,
            COALESCE(sum((tg_groups->>'protected')::int) FILTER (WHERE status = 'enrolled'), 0) AS tg_groups_protected,
            COALESCE(sum((tg_groups->>'autoDelete')::int) FILTER (WHERE status = 'enrolled'), 0) AS tg_groups_auto_delete,
            COALESCE(sum((tg_groups->>'scans24h')::int) FILTER (WHERE status = 'enrolled'), 0) AS tg_group_scans_24h,
            COALESCE(sum((tg_groups->>'threats24h')::int) FILTER (WHERE status = 'enrolled'), 0) AS tg_group_threats_24h,
            COALESCE(sum((tg_groups->>'errors24h')::int) FILTER (WHERE status = 'enrolled'), 0) AS tg_group_errors_24h
       FROM devices WHERE ($1::uuid[] IS NULL OR org_id = ANY($1))`,
    [scope],
  );

  const versions = await q<{ app_version: string | null; n: string }>(
    `SELECT app_version, count(*) AS n FROM devices WHERE status = 'enrolled' AND ($1::uuid[] IS NULL OR org_id = ANY($1)) GROUP BY 1 ORDER BY 2 DESC LIMIT 10`,
    [scope],
  );

  const [scans] = await q<Record<string, string>>(
    `SELECT count(*) AS sessions_30d,
            count(*) FILTER (WHERE NOT complete) AS incomplete_30d,
            COALESCE(sum(files_total), 0) AS files_30d,
            COALESCE(sum(files_failed), 0) AS files_failed_30d
       FROM scan_sessions s JOIN devices d ON d.id = s.device_id
      WHERE s.started_at > now() - interval '30 days' AND ($1::uuid[] IS NULL OR d.org_id = ANY($1))`,
    [scope],
  );

  const verdicts = await q<{ verdict: string; n: string }>(
    `SELECT f.verdict::text AS verdict, count(*) AS n FROM scan_findings f JOIN devices d ON d.id = f.device_id
      WHERE f.found_at > now() - interval '30 days' AND ($1::uuid[] IS NULL OR d.org_id = ANY($1)) GROUP BY 1`,
    [scope],
  );

  const [quar] = await q<Record<string, string>>(
    `SELECT count(*) FILTER (WHERE state = 'quarantined') AS quarantined,
            count(*) FILTER (WHERE state = 'restored') AS restored,
            count(*) FILTER (WHERE state = 'deleted') AS deleted
       FROM quarantine_records r JOIN devices d ON d.id = r.device_id WHERE ($1::uuid[] IS NULL OR d.org_id = ANY($1))`,
    [scope],
  );

  const releases = await q(
    `SELECT version, platform, channel, status, rollout_pct, code_signed, published_at FROM releases ORDER BY created_at DESC LIMIT 5`,
  );
  const intel = await q(`SELECT engine, version, published_at FROM intel_versions ORDER BY published_at DESC LIMIT 3`);

  return {
    operational: { fleet, versions, scans },
    security: { verdicts_30d: verdicts, quarantine: quar },
    releases: p.role === 'org_admin' ? [] : releases,
    intel,
    note: 'Detection counts are activity, not effectiveness. Operational health shows whether protection is actually running.',
  };
});

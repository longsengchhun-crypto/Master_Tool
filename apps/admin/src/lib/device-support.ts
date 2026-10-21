import { createHash } from 'node:crypto';
import { DevicePolicy } from '@sentrix/contracts';
import { q } from './db';

/** The org's default policy, or the conservative built-in defaults if none is set. Always schema-validated. */
export async function policyForOrg(orgId: string): Promise<DevicePolicy> {
  const rows = await q<{ config: unknown }>('SELECT config FROM device_policies WHERE org_id = $1 ORDER BY is_default DESC, updated_at DESC LIMIT 1', [orgId]);
  const parsed = DevicePolicy.safeParse(rows[0]?.config ?? {});
  return parsed.success ? parsed.data : DevicePolicy.parse({});
}

/** Stable 0..99 bucket for staged rollout: the same device always lands in the same cohort for a given version. */
export function rolloutBucket(deviceId: string, version: string): number {
  return parseInt(createHash('sha256').update(`${deviceId}:${version}`).digest('hex').slice(0, 8), 16) % 100;
}

export function semverGt(a: string, b: string): boolean {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) > (pb[i] ?? 0);
  }
  return false;
}

export interface UpdateOffer {
  version: string;
  notes: string;
  url: string;
  sha256: string;
  signature: string;
  pubDate: string | null;
  required: boolean;
}

/**
 * The release a device should be offered, or null. Only published/staged releases that carry an artifact URL, SHA-256
 * and update signature are ever offered. Staged releases reach only the devices whose cohort bucket is under the rollout %.
 */
export async function updateFor(platform: string, channel: string, currentVersion: string, deviceId: string): Promise<UpdateOffer | null> {
  const rows = await q<{ version: string; notes: string; artifact_url: string; sha256: string; signature: string; published_at: string | null; rollout_pct: number; min_supported: string | null }>(
    `SELECT version, notes, artifact_url, sha256, signature, published_at, rollout_pct, min_supported
       FROM releases WHERE platform = $1 AND channel = $2 AND status IN ('published','staged')
        AND artifact_url IS NOT NULL AND sha256 IS NOT NULL AND signature IS NOT NULL`,
    [platform, channel],
  );
  const eligible = rows
    .filter((r) => semverGt(r.version, currentVersion) && rolloutBucket(deviceId, r.version) < r.rollout_pct)
    .sort((a, b) => (semverGt(a.version, b.version) ? -1 : 1));
  const r = eligible[0];
  if (!r) return null;
  return {
    version: r.version,
    notes: r.notes,
    url: r.artifact_url,
    sha256: r.sha256,
    signature: r.signature,
    pubDate: r.published_at,
    required: !!r.min_supported && semverGt(r.min_supported, currentVersion),
  };
}

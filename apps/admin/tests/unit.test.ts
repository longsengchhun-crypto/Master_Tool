import { describe, expect, it } from 'vitest';
import { DevicePolicy, EnrollRequest, FindingIn, HeartbeatRequest, ReleaseCreate } from '@sentrix/contracts';
import { canonical, chainHash } from '@/lib/audit';
import { newCode } from '@/lib/codes';
import { hmac, open, seal, sha256 } from '@/lib/crypto';
import { rolloutBucket, semverGt } from '@/lib/device-support';
import { passwordProblem } from '@/lib/password';
import { can, PLATFORM_ROLES, SENSITIVE, type Permission, type Role } from '@/lib/rbac';
import { hashRecovery, newRecoveryCodes } from '@/lib/totp';

describe('RBAC matrix', () => {
  const ALL: Permission[] = ['org:read', 'org:manage', 'device:read', 'device:manage', 'device:revoke', 'license:read', 'license:manage', 'policy:read', 'policy:write', 'release:read', 'release:publish', 'telemetry:read', 'audit:read', 'user:manage_roles', 'global:settings'];

  it('only the super administrator can manage global settings, roles, licenses, orgs and releases', () => {
    for (const perm of ['global:settings', 'user:manage_roles', 'license:manage', 'org:manage', 'release:publish'] as Permission[]) {
      for (const role of ['security_admin', 'org_admin', 'support', 'auditor'] as Role[]) expect(can(role, perm), `${role} must not have ${perm}`).toBe(false);
      expect(can('super_admin', perm)).toBe(true);
    }
  });

  it('read-only auditor has no write permission at all', () => {
    const writes = ALL.filter((p) => /manage|write|revoke|publish|settings/.test(p));
    for (const p of writes) expect(can('auditor', p), p).toBe(false);
  });

  it('support operator cannot change anything', () => {
    for (const p of ALL.filter((x) => /manage|write|revoke|publish|settings/.test(x))) expect(can('support', p), p).toBe(false);
  });

  it('unknown or missing roles are denied everything (default deny)', () => {
    for (const p of ALL) {
      expect(can(null, p)).toBe(false);
      expect(can(undefined, p)).toBe(false);
      expect(can('root' as Role, p)).toBe(false);
    }
  });

  it('every destructive or privileged permission requires a fresh re-authentication', () => {
    for (const p of ['device:revoke', 'license:manage', 'policy:write', 'release:publish', 'user:manage_roles', 'global:settings'] as Permission[]) expect(SENSITIVE.has(p), p).toBe(true);
  });

  it('org_admin is org-scoped, not a platform role', () => {
    expect(PLATFORM_ROLES.has('org_admin')).toBe(false);
  });
});

describe('crypto', () => {
  it('seal/open round-trips and rejects tampering', () => {
    const e = seal('JBSWY3DPEHPK3PXP');
    expect(open(e)).toBe('JBSWY3DPEHPK3PXP');
    const parts = e.split('.');
    parts[3] = Buffer.from('tampered' + parts[3]).toString('base64url');
    expect(() => open(parts.join('.'))).toThrow();
  });

  it('seal output is non-deterministic and never contains the plaintext', () => {
    const a = seal('secret-value');
    const b = seal('secret-value');
    expect(a).not.toBe(b);
    expect(a).not.toContain('secret-value');
  });

  it('device-token HMAC is keyed (differs from a bare hash)', () => {
    expect(hmac('x')).not.toBe(sha256('x'));
    expect(hmac('x')).toBe(hmac('x'));
  });

  it('recovery codes are stored as hashes and verify case-insensitively', () => {
    const { plain, hashes } = newRecoveryCodes();
    expect(plain).toHaveLength(10);
    expect(new Set(plain).size).toBe(10);
    expect(hashes.includes(hashRecovery(plain[0].toUpperCase()))).toBe(true);
    expect(hashes.join('')).not.toContain(plain[0]);
  });
});

describe('codes', () => {
  it('have the documented shape and use no look-alike characters', () => {
    for (let i = 0; i < 200; i++) {
      const c = newCode('SX', 4, 4);
      expect(c).toMatch(/^SX(-[A-HJ-NP-Z2-9]{4}){4}$/);
    }
  });
  it('do not repeat (80 bits of entropy)', () => {
    const s = new Set(Array.from({ length: 5000 }, () => newCode('SX', 4, 4)));
    expect(s.size).toBe(5000);
  });
});

describe('audit hash chain', () => {
  it('canonical form ignores object key order (jsonb reorders keys)', () => {
    expect(canonical({ b: 1, a: { d: 2, c: 3 } })).toBe(canonical({ a: { c: 3, d: 2 }, b: 1 }));
  });
  it('any field change changes the hash', () => {
    const at = '2026-01-01T00:00:00.000Z';
    const base = chainHash('0'.repeat(64), { action: 'x', detail: { a: 1 } }, at);
    expect(chainHash('0'.repeat(64), { action: 'y', detail: { a: 1 } }, at)).not.toBe(base);
    expect(chainHash('0'.repeat(64), { action: 'x', detail: { a: 2 } }, at)).not.toBe(base);
    expect(chainHash('1'.repeat(64), { action: 'x', detail: { a: 1 } }, at)).not.toBe(base);
    expect(chainHash('0'.repeat(64), { action: 'x', detail: { a: 1 } }, '2026-01-01T00:00:00.001Z')).not.toBe(base);
  });
});

describe('release rollout', () => {
  it('semver comparison', () => {
    expect(semverGt('0.2.0', '0.1.9')).toBe(true);
    expect(semverGt('1.0.0', '0.99.99')).toBe(true);
    expect(semverGt('0.1.0', '0.1.0')).toBe(false);
    expect(semverGt('0.1.0', '0.2.0')).toBe(false);
  });
  it('cohorts are stable and roughly uniform', () => {
    expect(rolloutBucket('dev-1', '0.2.0')).toBe(rolloutBucket('dev-1', '0.2.0'));
    let under = 0;
    for (let i = 0; i < 4000; i++) if (rolloutBucket(`device-${i}`, '0.2.0') < 25) under++;
    expect(under / 4000).toBeGreaterThan(0.21);
    expect(under / 4000).toBeLessThan(0.29);
  });
});

describe('password policy', () => {
  it('requires length, not character classes', () => {
    expect(passwordProblem('short')).toBeTruthy();
    expect(passwordProblem('aaaaaaaaaaaa')).toBeTruthy();
    expect(passwordProblem('correct horse battery staple')).toBeNull();
  });
});

describe('contracts accept what the real clients send', () => {
  it('timestamps with a numeric offset (Rust chrono) and with Z are both valid', () => {
    const base = { appVersion: '0.1.0', engineVersion: null, intelVersion: null, protection: { engineState: 'running', realtimeState: 'active' } };
    for (const t of ['2026-10-21T12:00:00+00:00', '2026-10-21T12:00:00Z', '2026-10-21T12:00:00.123456789+00:00', null]) {
      expect(HeartbeatRequest.safeParse({ ...base, intelUpdatedAt: t }).success, String(t)).toBe(true);
    }
    for (const t of ['yesterday', '2026-10-21', '', 12345]) expect(HeartbeatRequest.safeParse({ ...base, intelUpdatedAt: t }).success, String(t)).toBe(false);
  });
});

describe('contracts are strict', () => {
  it('device policy rejects unknown keys, so no command or script field can ever be smuggled in', () => {
    expect(DevicePolicy.safeParse({ runCommand: 'calc.exe' }).success).toBe(false);
    expect(DevicePolicy.safeParse({ autoQuarantine: 'everything' }).success).toBe(false);
    expect(DevicePolicy.safeParse({ maxFileSizeMb: -1 }).success).toBe(false);
    expect(DevicePolicy.safeParse({}).success).toBe(true);
  });
  it('auto-quarantine can never target suspicious files', () => {
    expect(DevicePolicy.safeParse({ autoQuarantine: 'off' }).success).toBe(true);
    expect(DevicePolicy.safeParse({ autoQuarantine: 'malicious_only' }).success).toBe(true);
    for (const v of ['suspicious', 'suspicious_and_malicious', 'all', 'heuristic']) {
      expect(DevicePolicy.safeParse({ autoQuarantine: v }).success, v).toBe(false);
    }
  });
  it('requests reject unknown fields and malformed hashes', () => {
    expect(EnrollRequest.safeParse({ code: 'x'.repeat(20), hostname: 'h', os: 'windows', appVersion: '1', extra: 1 }).success).toBe(false);
    expect(FindingIn.safeParse({ sha256: 'ABC', verdict: 'CLEAN', source: 's' }).success).toBe(false);
    expect(ReleaseCreate.safeParse({ version: '1.0', platform: 'windows-x64' }).success).toBe(false);
    expect(ReleaseCreate.safeParse({ version: '1.0.0', platform: 'windows-x64', artifactUrl: 'http://insecure.example/a.exe' }).success).toBe(false);
  });
});

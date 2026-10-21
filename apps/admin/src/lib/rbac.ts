// Least-privilege permission matrix. Default for an unknown role/permission is DENY.
export type Permission =
  | 'org:read' | 'org:manage'
  | 'device:read' | 'device:manage' | 'device:revoke'
  | 'license:read' | 'license:manage'
  | 'policy:read' | 'policy:write'
  | 'release:read' | 'release:publish'
  | 'telemetry:read'
  | 'audit:read'
  | 'user:manage_roles'
  | 'global:settings';

export type Role = 'super_admin' | 'security_admin' | 'org_admin' | 'support' | 'auditor';

const MATRIX: Record<Role, readonly Permission[]> = {
  super_admin: [
    'org:read', 'org:manage', 'device:read', 'device:manage', 'device:revoke', 'license:read', 'license:manage',
    'policy:read', 'policy:write', 'release:read', 'release:publish', 'telemetry:read', 'audit:read',
    'user:manage_roles', 'global:settings',
  ],
  security_admin: ['org:read', 'device:read', 'device:manage', 'policy:read', 'policy:write', 'release:read', 'telemetry:read', 'audit:read'],
  org_admin: ['org:read', 'device:read', 'device:manage', 'device:revoke', 'license:read', 'policy:read', 'policy:write', 'telemetry:read', 'audit:read'],
  support: ['org:read', 'device:read', 'license:read', 'policy:read', 'telemetry:read'],
  auditor: ['org:read', 'device:read', 'license:read', 'policy:read', 'release:read', 'telemetry:read', 'audit:read'],
};

/** Permissions that require a recent password re-entry in addition to a verified MFA session. */
export const SENSITIVE: ReadonlySet<Permission> = new Set([
  'device:revoke', 'license:manage', 'policy:write', 'release:publish', 'user:manage_roles', 'global:settings',
]);

/** Platform roles act across organizations; org_admin is scoped to the org they belong to. */
export const PLATFORM_ROLES: ReadonlySet<Role> = new Set(['super_admin', 'security_admin', 'support', 'auditor']);

export function can(role: Role | null | undefined, perm: Permission): boolean {
  return !!role && (MATRIX[role] ?? []).includes(perm);
}

/** Roles that must have MFA enabled before any admin API will serve them. */
export function requiresMfa(role: Role | null | undefined): boolean {
  return !!role; // every administrative role, including org_admin and auditor
}

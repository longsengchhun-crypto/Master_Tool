import { z } from 'zod';

// ---- Verdicts -----------------------------------------------------------------------------
// CLEAN is never a safety guarantee; UNABLE_TO_VERIFY is the default whenever a scan is incomplete.
export const Verdict = z.enum(['CLEAN', 'SUSPICIOUS', 'MALICIOUS', 'UNABLE_TO_VERIFY', 'PENDING']);
export type Verdict = z.infer<typeof Verdict>;

export const sha256Hex = z.string().regex(/^[0-9a-f]{64}$/, 'must be lowercase hex SHA-256');

/** ISO 8601 timestamp. Offsets are allowed ("+00:00" as emitted by Rust's chrono, as well as "Z"). */
export const isoTime = z.string().datetime({ offset: true });

// ---- Device policy ------------------------------------------------------------------------
// Everything a policy can change is enumerated here. There is deliberately no field that
// carries a command, script, or path to execute.
export const DevicePolicy = z.strictObject({
  realtimeMonitoring: z.boolean().default(true),
  monitoredFolders: z.array(z.enum(['downloads', 'desktop', 'documents', 'removable'])).default(['downloads']),
  autoQuarantine: z.enum(['off', 'malicious_only']).default('malicious_only'), // never on SUSPICIOUS
  maxFileSizeMb: z.number().int().min(1).max(4096).default(512),
  archiveMaxDepth: z.number().int().min(0).max(8).default(3),
  allowHashReputationLookup: z.boolean().default(false),
  allowFileNameTelemetry: z.boolean().default(false),
  allowUserRestoreSuspicious: z.boolean().default(true),
  minAppVersion: z.string().regex(/^\d+\.\d+\.\d+$/).optional(),
  maxIntelAgeHours: z.number().int().min(1).max(720).default(48),
  // Organization switches for the Telegram integrations. Turning the bot off also removes its token from the device.
  telegramBotAllowed: z.boolean().default(true),
  telegramAccountAllowed: z.boolean().default(true),
  // Group Shield (the owner's bot scanning files in Telegram groups). Off here also forces the owner's switch off.
  telegramGroupsAllowed: z.boolean().default(true),
});
export type DevicePolicy = z.infer<typeof DevicePolicy>;

// ---- Device-facing API --------------------------------------------------------------------
export const EnrollRequest = z.strictObject({
  code: z.string().min(16).max(64),
  hostname: z.string().min(1).max(255),
  os: z.enum(['windows', 'macos', 'linux']),
  osVersion: z.string().max(100).optional(),
  appVersion: z.string().max(40),
});

export const HeartbeatRequest = z.strictObject({
  appVersion: z.string().max(40),
  engineVersion: z.string().max(100).nullable(),
  intelVersion: z.string().max(100).nullable(),
  intelUpdatedAt: isoTime.nullable(),
  protection: z.strictObject({
    engineState: z.enum(['running', 'stopped', 'degraded', 'unavailable']),
    realtimeState: z.enum(['active', 'paused', 'unsupported', 'error']),
    detail: z.string().max(500).optional(),
  }),
  // Operational counts only (optional: older clients omit them). NEVER file names, hashes, chat ids, tokens or message text:
  // the schema is strict, so any such field is rejected.
  queue: z
    .strictObject({ queued: z.number().int().min(0), failed: z.number().int().min(0), stuck: z.number().int().min(0) })
    .optional(),
  groups: z
    .strictObject({
      registered: z.number().int().min(0),
      protected: z.number().int().min(0),
      autoDelete: z.number().int().min(0),
      scans24h: z.number().int().min(0),
      threats24h: z.number().int().min(0),
      errors24h: z.number().int().min(0),
    })
    .optional(),
  telegram: z
    .strictObject({
      botConnected: z.boolean(),
      deliveryFailures24h: z.number().int().min(0),
      accountState: z.enum(['not_available', 'disconnected', 'connected', 'expired']),
      // Personal-account protection, counts since it was set up. Never account names, phone numbers, chat names or files.
      account: z
        .strictObject({ scanned: z.number().int().min(0), threats: z.number().int().min(0), unverified: z.number().int().min(0) })
        .optional(),
    })
    .optional(),
});

export const SecurityEventIn = z.strictObject({
  kind: z.string().min(1).max(60),
  severity: z.enum(['info', 'warning', 'critical']),
  detail: z.string().max(500).optional(),
});

export const FindingIn = z.strictObject({
  sha256: sha256Hex,
  fileName: z.string().max(260).optional(), // honoured only if policy.allowFileNameTelemetry
  verdict: Verdict,
  source: z.string().max(100),
  engineVersion: z.string().max(100).optional(),
  detail: z.string().max(500).optional(),
});

export const ScanSessionIn = z.strictObject({
  kind: z.enum(['file', 'folder', 'full', 'realtime']),
  startedAt: isoTime,
  finishedAt: isoTime.nullable(),
  filesTotal: z.number().int().min(0),
  filesFailed: z.number().int().min(0),
  complete: z.boolean(),
  findings: z.array(FindingIn).max(500),
});

// ---- Admin-facing API ---------------------------------------------------------------------
export const LoginRequest = z.strictObject({
  email: z.string().email().max(254),
  password: z.string().min(1).max(256),
  // A 6-digit authenticator code, or a one-time recovery code (xxxx-xxxx-xxxx-xxxx).
  totp: z.string().regex(/^(\d{6}|[0-9a-fA-F]{4}(-[0-9a-fA-F]{4}){3})$/).optional(),
});

export const ReleaseCreate = z.strictObject({
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
  platform: z.enum(['windows-x64', 'macos-arm64', 'macos-x64', 'linux-x64']),
  channel: z.enum(['stable', 'beta']).default('stable'),
  notes: z.string().max(10_000).default(''),
  artifactUrl: z.string().url().startsWith('https://').optional(),
  sha256: sha256Hex.optional(),
  signature: z.string().max(4096).optional(),
  codeSigned: z.boolean().default(false),
  sizeBytes: z.number().int().positive().optional(),
  minSupported: z.string().regex(/^\d+\.\d+\.\d+$/).optional(),
});

export const RoleName = z.enum(['super_admin', 'security_admin', 'org_admin', 'support', 'auditor']);
export type RoleName = z.infer<typeof RoleName>;

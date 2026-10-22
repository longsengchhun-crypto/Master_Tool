// Mirrors the serde output of sentrix-core (snake_case) and the app layer (camelCase).

export type Verdict = 'PENDING' | 'UNABLE_TO_VERIFY' | 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS';
export type CheckStatus = 'completed' | 'not_applicable' | 'unavailable' | 'failed' | 'incomplete';
export type Severity = 'info' | 'low' | 'medium' | 'high';

export interface Check {
  id: string;
  name: string;
  status: CheckStatus;
  engine_version: string | null;
  note: string | null;
  retryable?: boolean;
}

export interface Finding {
  source: string;
  engine_version: string | null;
  name: string;
  kind: 'signature' | 'heuristic' | 'integrity' | 'coverage';
  severity: Severity;
  evidence: string;
  location: string | null;
  detected_at: string;
  /** Threat family the behaviour belongs to, when the rule knows one. */
  family?: string | null;
  /** MITRE ATT&CK technique ids: reference labels, not proof it happened. */
  attack?: string[];
}

/** What kind of threat a flagged file is. "identified": the engine named it. "suggested": behaviour resembles it. */
export interface ThreatInfo {
  family: string;
  title: string;
  goal: string;
  arrives_via: string[];
  attack: string[];
  advice: string;
  basis: 'identified' | 'suggested';
  also: string[];
}

export interface FileInfo {
  path: string;
  name: string;
  size: number;
  sha256: string;
  detected_type: string;
  declared_extension: string | null;
  type_mismatch: boolean;
  signature: { state: string; detail: string | null } | null;
  modified: string | null;
  /** Origin recorded by Windows (host and zone only), when known. */
  source?: string | null;
}

export interface ScanReport {
  id: string;
  file: FileInfo;
  verdict: Verdict;
  complete: boolean;
  checks: Check[];
  findings: Finding[];
  summary: string;
  recommended_action: string;
  started_at: string;
  finished_at: string;
  quarantined: boolean;
  blocked: boolean;
  cached: boolean;
  /** What triggered the scan: Telegram Desktop, Downloads folder, Browser download, Custom folder, … */
  origin?: string | null;
  /** Only present for flagged files. */
  threat?: ThreatInfo | null;
}

export interface EngineStatus {
  core_version: string;
  clamav_installed: boolean;
  clamav_database_present: boolean;
  clamav_running: boolean;
  clamav_version: string | null;
  database_age_hours: number | null;
  state: 'running' | 'degraded' | 'stopped' | 'unavailable';
  detail: string;
}

export interface RealtimeStatus {
  state: 'active' | 'off' | 'error';
  watching: string[];
  failed: [string, string][];
  detail: string;
}

export interface Settings {
  realtimeMonitoring: boolean;
  monitoredFolders: string[];
  customFolders: string[];
  autoQuarantine: 'off' | 'malicious_only';
  allowRestoreSuspicious: boolean;
  notifications: boolean;
  maxFileSizeMb: number;
  archiveMaxDepth: number;
  telemetryEnabled: boolean;
  autoUpdate: boolean;
  theme: 'system' | 'light' | 'dark';
  onboardingDone: boolean;
  executionGuard: boolean;
  telegram: {
    chatId: number | null;
    botUsername: string | null;
    notify: NotifyPrefs;
    acceptSubmissions: boolean;
    desktopFolder: string | null;
    botAllowed: boolean;
    accountAllowed: boolean;
    groupShield: boolean;
    groupsAllowed: boolean;
    relayLinked: boolean;
  };
}

export interface NotifyPrefs {
  malicious: boolean;
  suspicious: boolean;
  unableToVerify: boolean;
  cleanScans: boolean;
  quarantined: boolean;
  engineProblems: boolean;
  protectionStopped: boolean;
  accountEvents: boolean;
  includeHash: boolean;
}

export interface AppStatus {
  version: string;
  engine: EngineStatus;
  realtime: RealtimeStatus;
  stats: {
    maliciousFiles: number;
    suspiciousFiles: number;
    quarantined: number;
    scansTotal: number;
    lastScanAt: string | null;
  };
  protection: { level: 'protected' | 'attention' | 'at_risk'; headline: string; reasons: string[] };
  lastSignatureUpdate: string | null;
  lastFullScan: string | null;
  settings: Settings;
  capabilities: {
    fileScanning: boolean;
    folderMonitoring: boolean;
    /** Kernel-level pre-execution filtering. Not available (needs a signed driver). */
    executionBlocking: boolean;
    /** User-mode deny-execute guard for confirmed-malicious files. */
    executionGuard: boolean;
    signatureVerification: boolean;
    platform: string;
  };
  dataDir: string;
  scanRunning: boolean;
  /** Organization whose policy controls protection settings, if this device is enrolled. */
  managedBy: string | null;
  publisher: { state: string; detail: string | null };
  dismissedHashes: string[];
}

export interface UpdateInfo {
  configured: boolean;
  available: boolean;
  current: string;
  version: string | null;
  notes: string | null;
  message: string;
}

export interface AccountStatus {
  enrolled: boolean;
  portalUrl: string | null;
  orgName: string | null;
  deviceId: string | null;
  enrolledAt: string | null;
  lastSyncAt: string | null;
  lastError: string | null;
  license: { state: string; plan: string | null; expiresAt: string | null } | null;
  policy: Record<string, unknown> | null;
  update: { version: string; notes: string } | null;
}

export interface BatchCounts {
  total: number;
  clean: number;
  suspicious: number;
  malicious: number;
  unable_to_verify: number;
  incomplete: number;
}

export interface BatchOut {
  /** Everything for small scans; only files that are not "clean and complete" for large ones. */
  reports: ScanReport[];
  reportsTruncated: boolean;
  counts: BatchCounts;
  skipped: [string, string][];
  skippedTotal: number;
  complete: boolean;
  cancelled: boolean;
  autoQuarantined: number;
}

export interface Progress {
  done: number;
  /** Files found so far; keeps growing while `discovering` is true. */
  discovered: number;
  discovering: boolean;
  current: string;
}

export interface QuarantineRecord {
  id: string;
  original_path: string;
  original_name: string;
  sha256: string;
  size: number;
  verdict: Verdict;
  reason: string;
  detected_type: string;
  quarantined_at: string;
  state: 'quarantined' | 'restored' | 'deleted';
  tampered: boolean;
}

export interface UpdateOutcome {
  ok: boolean;
  message: string;
  engine: EngineStatus;
}

// ---- Phase 2 -----------------------------------------------------------------------------------------------

export interface QueueStats {
  queued: number;
  scanning: number;
  failed: number;
  stuck: number;
  oldestQueuedSeconds: number | null;
  filesScanned: number;
  staleResults: number;
  lastScanAt: number | null;
}

export interface RootHealth {
  path: string;
  label: string;
  exists: boolean;
  watching: boolean;
  error: string | null;
}

export interface EventRow {
  id: number;
  ts: number;
  kind: string;
  severity: 'info' | 'warning' | 'critical';
  message: string;
}

export interface FailedJob {
  id: string;
  path: string;
  source: string;
  attempts: number;
  lastError: string | null;
  updatedAt: number;
}

export interface OutboxRow {
  id: string;
  kind: string;
  text: string;
  state: 'pending' | 'sent' | 'dead';
  attempts: number;
  lastError: string | null;
  createdAt: number;
  sentAt: number | null;
}

export interface OutboxStats {
  pending: number;
  failed24h: number;
  dead: number;
  lastSentAt: number | null;
  lastError: string | null;
}

export interface ProtectionHealth {
  realtimeEnabled: boolean;
  monitorRunning: boolean;
  roots: RootHealth[];
  queue: QueueStats;
  outbox: OutboxStats;
  recentEvents: EventRow[];
  couldNotCheck: FailedJob[];
  rejectedSubmissions: number;
  lastReconcileAt: number | null;
  lastFileEventAt: number | null;
  resumesAfterRestart: boolean;
  engine: EngineStatus;
}

export interface Detection {
  installed: boolean;
  evidence: string[];
  candidates: { path: string; exists: boolean; fileCount: number }[];
}

/** The shared SENTRIX bot: this app is linked to the person's own chat with it. */
export interface RelayStatus {
  /** This build knows where the shared bot is. */
  available: boolean;
  linked: boolean;
  botUsername: string | null;
  botLink: string | null;
  userName: string | null;
  linkedAt: number | null;
  /** The bot can write to the person now. null = not checked yet. */
  reachable: boolean | null;
  checkedAt: number | null;
  error: string | null;
  /** The person unlinked this computer from the bot's own menu. */
  removedRemotely: boolean;
}

export interface TelegramStatus {
  allowed: boolean;
  bot: {
    configured: boolean;
    connected: boolean;
    username: string | null;
    chatHint: string | null;
    lastTestAt: number | null;
    lastTestOk: boolean | null;
    lastTestError: string | null;
    lastDeliveryAt: number | null;
    lastDeliveryError: string | null;
    pending: number;
    failed24h: number;
    dead: number;
  };
  acceptSubmissions: boolean;
  notify: NotifyPrefs;
  desktop: { detection: Detection; folder: string | null; exists: boolean; watching: boolean; error: string | null; scanned: number; threats: number };
  account: TgAccount;
  relay: RelayStatus;
  groups: GroupsStatus;
  rejectedSubmissions: number;
  recentNotifications: OutboxRow[];
}
export type AccountLink =
  | { state: 'unconfigured'; detail: string }
  | { state: 'disconnected' }
  | { state: 'starting' }
  | { state: 'waiting_for_scan' }
  | { state: 'two_step_unsupported' }
  | { state: 'connected' }
  | { state: 'expired' }
  | { state: 'failed'; detail: string };

export interface AccountOptions {
  enabled: boolean;
  privateChats: boolean;
  groups: boolean;
  channels: boolean;
  media: boolean;
}

export interface AccountRecent {
  at: number;
  name: string;
  kind: 'private' | 'group' | 'channel';
  /** Label as the engine prints it: "CLEAN", "SUSPICIOUS", "MALICIOUS", "UNABLE TO VERIFY". */
  verdict: string;
  note: string;
}

/** Personal Telegram account protection. Never carries a phone number, username, id or any message text. */
export type TgAccount = AccountLink & {
  qrSvg: string | null;
  display: string | null;
  connection: 'ready' | 'connecting' | 'waiting_for_network' | 'updating' | 'unknown';
  lastSyncAt: number | null;
  lastScanAt: number | null;
  pending: number;
  counts: { scanned: number; threats: number; suspicious: number; inaccessible: number; skipped: number };
  recent: AccountRecent[];
  /** Organization policy. */
  allowed: boolean;
  options: AccountOptions;
};

export interface GroupStats {
  scans: number;
  threats: number;
  suspicious: number;
  unverified: number;
  skipped: number;
  errors: number;
  lastScanAt: number | null;
}

export interface GroupView {
  id: number;
  title: string;
  kind: string;
  enabled: boolean;
  autoDelete: boolean;
  reportClean: boolean;
  reportIncomplete: boolean;
  enabledAt: number | null;
  deleteConsentAt: number | null;
  /** member, administrator, left */
  botStatus: string;
  joinedAt: number;
  stats: GroupStats;
}

export interface GroupsStatus {
  shield: boolean;
  allowed: boolean;
  /** Telegram privacy mode hides ordinary group messages from the bot (null = not known yet). */
  privacyBlocks: boolean | null;
  list: GroupView[];
}

/**
 * DEVELOPMENT PREVIEW ONLY. Fakes the Tauri IPC layer so every screen can be viewed in a plain browser.
 * Loaded only when running `vite` (import.meta.env.DEV) with `?mock=<scenario>`; never part of a production build.
 * Everything here is invented sample data, and the UI shows a permanent "MOCK DATA" banner while it is active.
 *
 *   ?mock=healthy | stopped | unavailable | managed | onboarding      &theme=light|dark
 */
import type { AppStatus, ScanReport, Settings, QuarantineRecord, AccountStatus, Check, Finding, ProtectionHealth, TelegramStatus, NotifyPrefs } from '../lib/types';

type Handlers = Record<string, (args: any) => unknown>;
declare global {
  interface Window {
    __SENTRIX_MOCK__?: string;
    __TAURI_INTERNALS__?: unknown;
  }
}

const now = Date.now();
const iso = (minAgo: number) => new Date(now - minAgo * 60_000).toISOString();
const sha = (c: string) => c.repeat(64).slice(0, 64);

const ok = (id: string, name: string, v?: string, note?: string): Check => ({ id, name, status: 'completed', engine_version: v ?? null, note: note ?? null });
const na = (id: string, name: string, note: string): Check => ({ id, name, status: 'not_applicable', engine_version: null, note });
const gap = (id: string, name: string, status: 'unavailable' | 'failed' | 'incomplete', note: string): Check => ({ id, name, status, engine_version: null, note });
const finding = (source: string, name: string, kind: Finding['kind'], severity: Finding['severity'], evidence: string, location: string | null = null): Finding => ({ source, name, kind, severity, evidence, location, engine_version: source === 'clamav' ? 'ClamAV 1.5.4/28159' : null, detected_at: iso(5) });

const CLAM = 'ClamAV 1.5.4/28159/Tue Oct 20 13:24:12 2026';
const base = (name: string, folder: string, type: string, size: number, c: string, extra: Partial<ScanReport['file']> = {}): ScanReport['file'] => ({
  path: `${folder}\\${name}`, name, size, sha256: sha(c), detected_type: type, declared_extension: name.split('.').pop() ?? null, type_mismatch: false, signature: null, modified: iso(60), ...extra,
});

const REPORTS: ScanReport[] = [
  {
    id: '00000000-0000-4000-8000-000000000001', verdict: 'MALICIOUS', complete: true, cached: false, quarantined: false, blocked: false, started_at: iso(6), finished_at: iso(5),
    file: base('invoice_update.exe', 'C:\\Users\\Sample\\Downloads', 'Windows executable (PE)', 3_412_480, 'a', { source: 'Downloaded from files.example-cdn.net (the Internet)', signature: { state: 'signed_invalid', detail: 'A signature is present but the file has been altered since it was signed, or the signature is corrupt.' } }),
    summary: 'A malware detection engine identified this file as Win.Trojan.Sample-1.',
    recommended_action: 'Do not open this file. Quarantine it, then delete it if you do not need it. If you believe this is a mistake, keep it quarantined and check the source.',
    checks: [ok('identify', 'File type identification'), ok('hash', 'SHA-256 hash'), ok('signature', 'Digital signature'), ok('builtin-eicar', 'EICAR test-file detector', 'sentrix-core/0.1.0', 'Test-file detector only; not a malware engine.'), ok('clamav', 'Malware signatures (ClamAV)', CLAM), ok('static', 'Static analysis', 'sentrix-core/0.1.0')],
    findings: [finding('clamav', 'Win.Trojan.Sample-1', 'signature', 'high', 'ClamAV signature match: Win.Trojan.Sample-1'), finding('authenticode', 'Digital signature is invalid or the file was altered', 'integrity', 'high', 'A signature is present but the file has been altered since it was signed, or the signature is corrupt.'), finding('heuristic.pe', 'Process-injection API combination', 'heuristic', 'medium', 'Imports VirtualAllocEx, WriteProcessMemory and CreateRemoteThread together, which allows code to be written into and run inside another process. Debuggers and security tools also do this.')],
  },
  {
    id: '00000000-0000-4000-8000-000000000002', verdict: 'SUSPICIOUS', complete: true, cached: false, quarantined: false, blocked: false, started_at: iso(30), finished_at: iso(29),
    file: base('holiday_photo.jpg', 'C:\\Users\\Sample\\Desktop', 'Windows executable (PE)', 884_736, 'b', { type_mismatch: true, declared_extension: 'jpg', signature: { state: 'unsigned', detail: 'No embedded digital signature (system files may be catalog-signed instead).' } }),
    summary: 'This file contains indicators that deserve a closer look. They are not proof of malware; legitimate software can show the same traits.',
    recommended_action: 'Do not open this file until you have confirmed where it came from and that it is authentic. Quarantine it if you are unsure.',
    checks: [ok('identify', 'File type identification'), ok('hash', 'SHA-256 hash'), ok('signature', 'Digital signature'), ok('clamav', 'Malware signatures (ClamAV)', CLAM), ok('static', 'Static analysis', 'sentrix-core/0.1.0')],
    findings: [finding('heuristic.identify', 'File content does not match its extension', 'heuristic', 'medium', 'The content is Windows executable (PE) but the name ends in .jpg.')],
  },
  {
    id: '00000000-0000-4000-8000-000000000003', verdict: 'UNABLE_TO_VERIFY', complete: false, cached: false, quarantined: false, blocked: false, started_at: iso(90), finished_at: iso(89),
    file: base('project-backup.zip', 'D:\\Archive', 'ZIP archive', 412_000_000, 'c'),
    summary: 'The scan was only partial, so SENTRIX cannot say whether this file is safe.',
    recommended_action: "Treat the file with caution. Fix the issue listed under 'Checks not completed' (for example update protection) and scan again.",
    checks: [ok('identify', 'File type identification'), ok('hash', 'SHA-256 hash'), ok('clamav', 'Malware signatures (ClamAV)', CLAM), gap('archive', 'Archive contents', 'incomplete', 'One or more archive entries are password-protected and could not be inspected.')],
    findings: [finding('heuristic.archive', 'Password-protected entry', 'coverage', 'low', 'This entry is encrypted, so its contents cannot be inspected.', 'finance/2025.xlsx')],
  },
  {
    id: '00000000-0000-4000-8000-000000000004', verdict: 'CLEAN', complete: true, cached: false, quarantined: false, blocked: false, started_at: iso(140), finished_at: iso(139),
    file: base('quarterly-report.pdf', 'C:\\Users\\Sample\\Documents', 'PDF document', 1_204_000, 'd'),
    summary: 'The checks that ran found no threat. This is not a guarantee: no scanner detects everything.',
    recommended_action: 'No action needed from this scan. Keep the file only if you trust its source.',
    checks: [ok('identify', 'File type identification'), ok('hash', 'SHA-256 hash'), na('signature', 'Digital signature', 'Not applicable to this file type'), ok('clamav', 'Malware signatures (ClamAV)', CLAM), ok('static', 'Static analysis', 'sentrix-core/0.1.0')],
    findings: [],
  },
  {
    id: '00000000-0000-4000-8000-000000000005', verdict: 'UNABLE_TO_VERIFY', complete: false, cached: false, quarantined: false, blocked: false, started_at: iso(200), finished_at: iso(199),
    file: base('notes.txt', 'C:\\Users\\Sample\\Downloads', 'Plain text', 2048, 'e'),
    summary: 'No malware-signature engine was available to check this file, so SENTRIX cannot say whether this file is safe.',
    recommended_action: "Treat the file with caution. Fix the issue listed under 'Checks not completed' (for example update protection) and scan again.",
    checks: [ok('identify', 'File type identification'), ok('hash', 'SHA-256 hash'), gap('clamav', 'Malware signatures (ClamAV)', 'unavailable', 'ClamAV is not installed at the configured location'), na('static', 'Static analysis', 'No in-house analyzer for this format; signature engine only.')],
    findings: [],
  },
];

const QUAR: QuarantineRecord[] = [
  { id: 'q1', original_path: 'C:\\Users\\Sample\\Downloads\\crack_setup.exe', original_name: 'crack_setup.exe', sha256: sha('f'), size: 5_200_000, verdict: 'MALICIOUS', reason: 'MALICIOUS A malware detection engine identified this file.', detected_type: 'Windows executable (PE)', quarantined_at: iso(300), state: 'quarantined', tampered: false },
  { id: 'q2', original_path: 'C:\\Users\\Sample\\Desktop\\macro_budget.xlsm', original_name: 'macro_budget.xlsm', sha256: sha('9'), size: 220_000, verdict: 'SUSPICIOUS', reason: 'SUSPICIOUS Contains VBA macros.', detected_type: 'Office document (Open XML)', quarantined_at: iso(2000), state: 'quarantined', tampered: false },
];

const NOTIFY: NotifyPrefs = { malicious: true, suspicious: true, unableToVerify: false, cleanScans: false, quarantined: true, engineProblems: true, protectionStopped: true, accountEvents: true, includeHash: true };
const settings = (over: Partial<Settings> = {}): Settings => ({ realtimeMonitoring: true, monitoredFolders: ['downloads', 'desktop'], customFolders: [], autoQuarantine: 'off', allowRestoreSuspicious: true, notifications: true, maxFileSizeMb: 512, archiveMaxDepth: 3, telemetryEnabled: false, theme: 'system', onboardingDone: true, executionGuard: false,
  telegram: { chatId: null, botUsername: null, notify: NOTIFY, acceptSubmissions: false, desktopFolder: null, botAllowed: true, accountAllowed: false, groupShield: false, groupsAllowed: true }, ...over });

function status(scn: string): AppStatus {
  const healthy = scn === 'healthy' || scn === 'managed' || scn === 'onboarding';
  const engine: AppStatus['engine'] = healthy
    ? { core_version: 'sentrix-core/0.1.0', clamav_installed: true, clamav_database_present: true, clamav_running: true, clamav_version: CLAM, database_age_hours: 6, state: 'running', detail: 'Detection engine is running with current signatures.' }
    : scn === 'stopped'
      ? { core_version: 'sentrix-core/0.1.0', clamav_installed: true, clamav_database_present: true, clamav_running: false, clamav_version: null, database_age_hours: 120, state: 'stopped', detail: 'The detection engine is not running. It will be restarted on the next scan.' }
      : { core_version: 'sentrix-core/0.1.0', clamav_installed: false, clamav_database_present: false, clamav_running: false, clamav_version: null, database_age_hours: null, state: 'unavailable', detail: 'ClamAV is not installed. Install the bundled engine or set its location in Settings.' };
  const rt: AppStatus['realtime'] = healthy || scn === 'stopped' ? { state: 'active', watching: ['C:\\Users\\Sample\\Downloads', 'C:\\Users\\Sample\\Desktop'], failed: [], detail: 'New files in the watched folders are scanned after they finish downloading.' } : { state: 'off', watching: [], failed: [], detail: 'Real-time protection is turned off. Files are only scanned when you scan them.' };
  const reasons: string[] = healthy ? [] : scn === 'stopped' ? [engine.detail] : [engine.detail, 'Real-time protection is off.'];
  return {
    version: '0.1.0', engine, realtime: rt,
    stats: { maliciousFiles: 1, suspiciousFiles: 1, quarantined: 2, scansTotal: 128, lastScanAt: iso(5) },
    protection: { level: healthy ? 'protected' : scn === 'stopped' ? 'attention' : 'at_risk', headline: healthy ? 'Protection is active' : scn === 'stopped' ? 'Protection needs attention' : 'Files cannot be verified right now', reasons },
    lastSignatureUpdate: healthy ? iso(360) : null, lastFullScan: iso(60 * 30), settings: settings({ onboardingDone: scn !== 'onboarding', realtimeMonitoring: rt.state === 'active' }),
    capabilities: { fileScanning: true, folderMonitoring: true, executionBlocking: false, executionGuard: true, signatureVerification: true, platform: 'windows' }, dataDir: 'C:\\Users\\Sample\\AppData\\Roaming\\app.sentrix.desktop', scanRunning: false,
    managedBy: scn === 'managed' ? 'Contoso IT' : null,
    publisher: { state: 'unsigned', detail: 'No embedded digital signature (system files may be catalog-signed instead).' },
    dismissedHashes: [],
  };
}


const min = (m: number) => now - m * 60_000;

function health(scn: string): ProtectionHealth {
  const healthy = scn !== 'stopped' && scn !== 'unavailable';
  const on = scn !== 'unavailable';
  return {
    realtimeEnabled: on, monitorRunning: healthy,
    roots: [
      { path: 'C:\Users\Sample\Downloads', label: 'Downloads', exists: true, watching: healthy, error: healthy ? null : 'Access is denied.' },
      { path: 'C:\Users\Sample\Desktop', label: 'Desktop', exists: true, watching: healthy, error: null },
      { path: 'C:\Users\Sample\Downloads\Telegram Desktop', label: 'Telegram Desktop', exists: true, watching: healthy, error: null },
    ],
    queue: { queued: healthy ? 2 : 14, scanning: healthy ? 1 : 0, failed: healthy ? 0 : 2, stuck: 0, oldestQueuedSeconds: healthy ? 3 : 640, filesScanned: 412, staleResults: healthy ? 0 : 1, lastScanAt: healthy ? min(1) : min(95) },
    outbox: { pending: healthy ? 0 : 3, failed24h: healthy ? 0 : 5, dead: 0, lastSentAt: min(healthy ? 4 : 190), lastError: healthy ? null : 'Telegram could not be reached (network error).' },
    recentEvents: [
      { id: 5, ts: min(1), kind: 'scan', severity: 'info', message: 'Scanned quarterly-report.pdf: clean (Downloads).' },
      { id: 4, ts: min(5), kind: 'threat', severity: 'critical', message: 'invoice_update.exe is malicious (Win.Trojan.Sample-1). Quarantine recommended.' },
      { id: 3, ts: min(40), kind: 'reconcile', severity: 'info', message: 'Startup folder check queued 3 files that arrived while SENTRIX was closed.' },
      ...(healthy ? [] : [{ id: 6, ts: min(90), kind: 'monitor', severity: 'warning' as const, message: 'Downloads could not be watched: Access is denied.' }]),
    ],
    couldNotCheck: healthy ? [] : [{ id: 'j1', path: 'C:\Users\Sample\Downloads\setup-large.iso', source: 'Downloads folder', attempts: 7, lastError: 'The file is locked by another program.', updatedAt: min(100) }],
    rejectedSubmissions: 0, lastReconcileAt: min(40), lastFileEventAt: min(1), resumesAfterRestart: scn === 'managed',
    engine: status(scn).engine,
  };
}

function telegram(scn: string): TelegramStatus {
  const connected = scn === 'healthy' || scn === 'stopped' || scn === 'managed';
  const bad = scn === 'stopped';
  return {
    allowed: true,
    bot: { configured: connected, connected, username: connected ? 'my_sentrix_reports_bot' : null, chatHint: connected ? '•••421' : null, lastTestAt: connected ? min(30) : null, lastTestOk: connected ? !bad : null, lastTestError: bad ? 'Telegram could not be reached (network error).' : null, lastDeliveryAt: connected && !bad ? min(4) : null, lastDeliveryError: bad ? 'Telegram could not be reached (network error).' : null, pending: bad ? 3 : 0, failed24h: bad ? 5 : 0, dead: 0 },
    acceptSubmissions: scn === 'healthy', notify: NOTIFY,
    desktop: { detection: { installed: true, evidence: ['C:\Users\Sample\AppData\Roaming\Telegram Desktop'], candidates: [{ path: 'C:\Users\Sample\Downloads\Telegram Desktop', exists: true, fileCount: 18 }] }, folder: connected ? 'C:\Users\Sample\Downloads\Telegram Desktop' : null, exists: true, watching: connected && !bad, error: null, scanned: connected ? 18 : 0, threats: connected ? 1 : 0 },
    account: { state: 'not_available', detail: 'Account-level monitoring is not implemented in this build: it needs a vetted Telegram client library and your own API credentials, and has not been security-audited or tested against a real account.' },
    accountAllowed: false,
    groups: {
      shield: connected, allowed: true, privacyBlocks: scn === 'stopped',
      list: connected ? [
        { id: -1001111, title: 'Design team', kind: 'supergroup', enabled: true, autoDelete: true, reportClean: false, reportIncomplete: true, enabledAt: min(900), deleteConsentAt: min(880), botStatus: 'administrator', joinedAt: min(2000), stats: { scans: 14, threats: 1, suspicious: 0, unverified: 1, skipped: 0, errors: 0, lastScanAt: min(12) } },
        { id: -1002222, title: 'Family chat', kind: 'group', enabled: false, autoDelete: false, reportClean: false, reportIncomplete: true, enabledAt: null, deleteConsentAt: null, botStatus: 'member', joinedAt: min(300), stats: { scans: 0, threats: 0, suspicious: 0, unverified: 0, skipped: 0, errors: 0, lastScanAt: null } },
      ] : [],
    },
    rejectedSubmissions: 0,
    recentNotifications: connected ? [
      { id: 'n1', kind: 'threat_malicious', text: '', state: 'sent', attempts: 1, lastError: null, createdAt: min(5), sentAt: min(4) },
      ...(bad ? [{ id: 'n2', kind: 'engine_problem', text: '', state: 'pending' as const, attempts: 3, lastError: 'Telegram could not be reached (network error).', createdAt: min(120), sentAt: null }] : []),
    ] : [],
  };
}

function account(scn: string): AccountStatus {
  if (scn !== 'managed') return { enrolled: false, portalUrl: null, orgName: null, deviceId: null, enrolledAt: null, lastSyncAt: null, lastError: null, license: null, policy: null, update: null };
  return { enrolled: true, portalUrl: 'https://console.contoso.example', orgName: 'Contoso IT', deviceId: '6f1c2d3e-0000-4000-8000-000000000000', enrolledAt: iso(60 * 24 * 12), lastSyncAt: iso(3), lastError: null, license: { state: 'valid', plan: 'business', expiresAt: new Date(now + 200 * 86_400_000).toISOString() }, policy: {}, update: { version: '0.2.0', notes: 'Improved archive handling.' } };
}

export function installMock() {
  const scn = new URLSearchParams(location.search).get('mock') || 'healthy';
  window.__SENTRIX_MOCK__ = scn;
  const theme = new URLSearchParams(location.search).get('theme');
  if (theme === 'light' || theme === 'dark') localStorage.setItem('sx-mock-theme', theme);
  const forced = localStorage.getItem('sx-mock-theme') as Settings['theme'] | null;

  const h: Handlers = {
    app_status: () => { const s = status(scn); if (forced) s.settings.theme = forced; return s; },
    account_status: () => account(scn),
    list_history: () => REPORTS,
    get_report: (a) => REPORTS.find((r) => r.id === a.id) ?? REPORTS[0],
    report_text: () => 'SENTRIX FILE SECURITY REPORT (mock)',
    list_quarantine: () => QUAR,
    verify_quarantine_audit: () => null,
    check_update: () => ({ configured: true, available: scn === 'managed', current: '0.1.0', version: scn === 'managed' ? '0.2.0' : null, notes: scn === 'managed' ? 'Improved archive handling.' : null, message: 'You have the latest version.' }),
    cancel_scan: () => true,
    protection_health: () => health(scn),
    retry_failed_jobs: () => 1,
    allow_execution: () => null,
    tg_status: () => telegram(scn),
    tg_detect_chat: () => [1234567421],
    tg_test_connection: () => telegram(scn),
    tg_set_options: () => telegram(scn),
    tg_set_group_shield: () => telegram(scn),
    tg_group_disable: () => telegram(scn),
    tg_group_leave: () => telegram(scn),
    tg_detect_desktop: () => telegram(scn).desktop.detection,
    start_engine: () => status(scn).engine,
    get_settings: () => settings(),
    set_settings: () => ({ state: 'active', watching: [], failed: [], detail: '' }),
    complete_onboarding: () => null,
    update_protection: () => ({ ok: true, message: 'Protection is up to date.', engine: status('healthy').engine }),
    scan_paths: () => ({ reports: REPORTS, reportsTruncated: false, counts: { total: 5, clean: 1, suspicious: 1, malicious: 1, unable_to_verify: 2, incomplete: 2 }, skipped: [['C:\\Users\\Sample\\Downloads\\shortcut-link', 'symbolic link or junction (not followed)']], skippedTotal: 1, complete: false, cancelled: false, autoQuarantined: 0 }),
    'plugin:event|listen': () => Math.floor(Math.random() * 1e6),
    'plugin:event|unlisten': () => null,
    'plugin:autostart|is_enabled': () => false,
    'plugin:autostart|enable': () => null,
    'plugin:autostart|disable': () => null,
  };

  const cbs = new Map<number, unknown>();
  window.__TAURI_INTERNALS__ = {
    metadata: { currentWindow: { label: 'main' }, currentWebview: { label: 'main', windowLabel: 'main' } },
    invoke: async (cmd: string, args: unknown) => {
      const fn = h[cmd];
      if (!fn) {
        console.warn('[mock] unhandled command', cmd);
        return null;
      }
      await new Promise((r) => setTimeout(r, 40));
      return fn(args);
    },
    transformCallback: (cb: unknown) => {
      const id = Math.floor(Math.random() * 1e9);
      cbs.set(id, cb);
      return id;
    },
    unregisterCallback: (id: number) => cbs.delete(id),
    convertFileSrc: (p: string) => p,
  };
  (window as unknown as Record<string, unknown>).__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: () => undefined };
}

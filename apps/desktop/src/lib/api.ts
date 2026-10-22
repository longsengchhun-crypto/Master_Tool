import { invoke } from '@tauri-apps/api/core';
import type { AccountOptions, TgAccount, Detection, NotifyPrefs, ProtectionHealth, TelegramStatus, AccountStatus, AppStatus, BatchOut, EngineStatus, QuarantineRecord, ScanReport, Settings, UpdateInfo, UpdateOutcome, RealtimeStatus } from './types';

/** Typed wrappers over the Tauri commands. Errors arrive as plain user-readable strings. */
export const api = {
  status: () => invoke<AppStatus>('app_status'),
  startEngine: () => invoke<EngineStatus>('start_engine'),
  updateProtection: () => invoke<UpdateOutcome>('update_protection'),
  scanPaths: (paths: string[], force = false) => invoke<BatchOut>('scan_paths', { paths, force }),
  fullScan: () => invoke<BatchOut>('full_system_scan'),
  cancelScan: () => invoke<boolean>('cancel_scan'),
  history: (limit = 500) => invoke<ScanReport[]>('list_history', { limit }),
  report: (id: string) => invoke<ScanReport>('get_report', { id }),
  reportText: (id: string) => invoke<string>('report_text', { id }),
  exportReport: (id: string, format: 'text' | 'json', path: string) => invoke<void>('export_report', { id, format, path }),
  clearHistory: () => invoke<void>('clear_history'),
  deleteFile: (id: string) => invoke<void>('delete_scanned_file', { id }),
  dismissWarning: (id: string) => invoke<void>('dismiss_warning', { id }),
  quarantineReport: (id: string) => invoke<void>('quarantine_report', { id }),
  listQuarantine: () => invoke<QuarantineRecord[]>('list_quarantine'),
  restoreQuarantine: (id: string, confirmMalicious: boolean, dest?: string) =>
    invoke<string>('restore_quarantine', { id, confirmMalicious, dest: dest ?? null }),
  deleteQuarantine: (id: string) => invoke<void>('delete_quarantine', { id }),
  verifyQuarantineAudit: () => invoke<number | null>('verify_quarantine_audit'),
  reveal: (path: string) => invoke<void>('reveal_in_folder', { path }),
  getSettings: () => invoke<Settings>('get_settings'),
  setSettings: (settings: Settings) => invoke<RealtimeStatus>('set_settings', { settings }),
  accountStatus: () => invoke<AccountStatus>('account_status'),
  enroll: (portalUrl: string, code: string) => invoke<AccountStatus>('enroll_device', { portalUrl, code }),
  unenroll: () => invoke<boolean>('unenroll_device'),
  syncNow: () => invoke<AccountStatus>('sync_now'),
  protectionHealth: () => invoke<ProtectionHealth>('protection_health'),
  retryFailedJobs: (id?: string) => invoke<number>('retry_failed_jobs', { id: id ?? null }),
  allowExecution: (id: string) => invoke<void>('allow_execution', { id }),
  tgStatus: () => invoke<TelegramStatus>('tg_status'),
  tgDetectChat: (token: string) => invoke<number[]>('tg_detect_chat', { token }),
  tgConnect: (token: string, chatId: number) => invoke<TelegramStatus>('tg_connect_bot', { token, chatId }),
  tgTest: () => invoke<TelegramStatus>('tg_test_connection'),
  tgDisconnect: () => invoke<TelegramStatus>('tg_disconnect_bot'),
  tgSetOptions: (notify: NotifyPrefs, acceptSubmissions: boolean) => invoke<TelegramStatus>('tg_set_options', { notify, acceptSubmissions }),
  tgDetectDesktop: () => invoke<Detection>('tg_detect_desktop'),
  tgSetDesktopFolder: (path: string | null) => invoke<TelegramStatus>('tg_set_desktop_folder', { path }),
  tgSetGroupShield: (enabled: boolean) => invoke<TelegramStatus>('tg_set_group_shield', { enabled }),
  tgGroupDisable: (id: number) => invoke<TelegramStatus>('tg_group_disable', { id }),
  tgRelayLink: (code: string) => invoke<TelegramStatus>('tg_relay_link', { code }),
  tgRelayUnlink: () => invoke<TelegramStatus>('tg_relay_unlink'),
  tgRelayTest: () => invoke<TelegramStatus>('tg_relay_test'),
  tgAccountStatus: () => invoke<TgAccount>('tg_account_status'),
  tgAccountConnect: () => invoke<TgAccount>('tg_account_connect'),
  tgAccountDisconnect: () => invoke<TgAccount>('tg_account_disconnect'),
  tgAccountSetOptions: (options: AccountOptions) => invoke<TgAccount>('tg_account_set_options', { options }),
  tgGroupLeave: (id: number) => invoke<TelegramStatus>('tg_group_leave', { id }),
  checkUpdate: () => invoke<UpdateInfo>('check_update'),
  installUpdate: () => invoke<void>('install_update'),
  completeOnboarding: (enableRealtime: boolean) => invoke<void>('complete_onboarding', { enableRealtime }),
};

export function errText(e: unknown): string {
  if (typeof e === 'string') return e;
  if (e instanceof Error) return e.message;
  return 'Something went wrong.';
}

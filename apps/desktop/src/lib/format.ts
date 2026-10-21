import type { CheckStatus, Verdict } from './types';

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const u = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${u[i]}`;
}

export function ago(iso: string | null | undefined): string {
  if (!iso) return 'Never';
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return 'Just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export function when(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export const VERDICT_LABEL: Record<Verdict, string> = {
  CLEAN: 'Clean',
  SUSPICIOUS: 'Suspicious',
  MALICIOUS: 'Malicious',
  UNABLE_TO_VERIFY: 'Unable to verify',
  PENDING: 'Pending',
};

export const CHECK_LABEL: Record<CheckStatus, string> = {
  completed: 'Completed',
  not_applicable: 'Not applicable',
  unavailable: 'Not available',
  failed: 'Failed',
  incomplete: 'Partial',
};

/** Splits a path into [folder, name] for compact display, tolerant of both separators. */
export function splitPath(p: string): [string, string] {
  const i = Math.max(p.lastIndexOf('\\'), p.lastIndexOf('/'));
  return i < 0 ? ['', p] : [p.slice(0, i), p.slice(i + 1)];
}

/** A scan that is not both complete and CLEAN needs the user's attention. */
export function needsAttention(v: Verdict, complete: boolean): boolean {
  return v === 'MALICIOUS' || v === 'SUSPICIOUS' || v === 'UNABLE_TO_VERIFY' || !complete;
}

/** Like `ago`, for the epoch-millisecond timestamps the protection service uses. */
export function agoMs(ms: number | null | undefined): string {
  if (!ms) return 'Never';
  const s = Math.max(0, (Date.now() - ms) / 1000);
  if (s < 5) return 'Just now';
  if (s < 60) return `${Math.floor(s)} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export function whenMs(ms: number): string {
  return new Date(ms).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}
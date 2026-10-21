import { hash, verify } from '@node-rs/argon2';

// argon2id, OWASP-recommended minimums (19 MiB, t=2, p=1) raised to 64 MiB.
const OPTS = { memoryCost: 65_536, timeCost: 3, parallelism: 1 } as const;

export const hashPassword = (pw: string) => hash(pw, OPTS);

export async function verifyPassword(stored: string, pw: string): Promise<boolean> {
  try {
    return await verify(stored, pw);
  } catch {
    return false;
  }
}

/** Administrator password policy: length over composition rules (NIST 800-63B). */
export function passwordProblem(pw: string): string | null {
  if (pw.length < 12) return 'Password must be at least 12 characters.';
  if (pw.length > 256) return 'Password is too long.';
  if (/^(.)\1+$/.test(pw)) return 'Password is too repetitive.';
  return null;
}

let dummy: Promise<string> | undefined;

/** Unknown-email logins spend the same argon2 time as wrong-password logins (no enumeration by timing). */
export async function burnVerify(pw: string): Promise<void> {
  dummy ??= hashPassword('sentrix-timing-equalizer');
  await verifyPassword(await dummy, pw);
}

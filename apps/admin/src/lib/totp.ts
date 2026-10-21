import { generate, generateSecret, generateURI, verify } from 'otplib';
import { createHash, randomBytes } from 'node:crypto';

export const newTotpSecret = () => generateSecret();

export const totpUri = (secret: string, email: string) => generateURI({ issuer: 'SENTRIX Console', label: email, secret });

/** Returns true if `token` is valid for `secret` (one 30s step of tolerance either side for clock skew). */
export async function totpValid(secret: string, token: string): Promise<boolean> {
  if (!/^\d{6}$/.test(token)) return false;
  try {
    const r = await verify({ secret, token, epochTolerance: 30 });
    return r.valid === true;
  } catch {
    return false;
  }
}

export const totpNow = (secret: string) => generate({ secret });

/** 10 one-time recovery codes; only their SHA-256 hashes are stored. */
export function newRecoveryCodes(): { plain: string[]; hashes: string[] } {
  const plain = Array.from({ length: 10 }, () => {
    const b = randomBytes(8).toString('hex');
    return `${b.slice(0, 4)}-${b.slice(4, 8)}-${b.slice(8, 12)}-${b.slice(12)}`;
  });
  return { plain, hashes: plain.map(hashRecovery) };
}

export const hashRecovery = (code: string) => createHash('sha256').update(code.trim().toLowerCase()).digest('hex');

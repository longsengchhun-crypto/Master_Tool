import { randomBytes } from 'node:crypto';

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 32 symbols, no look-alikes (0/O, 1/I)

/** Human-typable random code, e.g. SX-ABCD-EFGH-JKLM-NPQR. 32 symbols x groups*size gives groups*size*5 bits of entropy. */
export function newCode(prefix: string, groups: number, size: number): string {
  const bytes = randomBytes(groups * size);
  const chars = Array.from(bytes, (b) => ALPHABET[b & 31]); // 256 % 32 == 0, so no modulo bias
  const parts = Array.from({ length: groups }, (_, i) => chars.slice(i * size, (i + 1) * size).join(''));
  return `${prefix}-${parts.join('-')}`;
}

export const normalizeCode = (s: string) => s.trim().toUpperCase();

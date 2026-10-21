import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

function secret(name: string): Buffer {
  const v = process.env[name];
  if (!v || v.length < 32) throw new Error(`${name} must be set to at least 32 characters`);
  return createHash('sha256').update(v).digest(); // 32-byte key derived from the env secret
}

export const sha256 = (s: string | Buffer) => createHash('sha256').update(s).digest('hex');
export const randomToken = (bytes = 32) => randomBytes(bytes).toString('base64url');

/** HMAC for device tokens / enrollment codes so a DB leak does not yield usable credentials. */
export const hmac = (s: string) => createHmac('sha256', secret('DEVICE_TOKEN_PEPPER')).update(s).digest('hex');

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

/** AES-256-GCM envelope for secrets at rest (TOTP seeds). Format: v1.iv.tag.ciphertext (base64url). */
export function seal(plain: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', secret('SESSION_SECRET'), iv);
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return ['v1', iv.toString('base64url'), c.getAuthTag().toString('base64url'), ct.toString('base64url')].join('.');
}

export function open(envelope: string): string {
  const [v, iv, tag, ct] = envelope.split('.');
  if (v !== 'v1' || !iv || !tag || !ct) throw new Error('bad envelope');
  const d = createDecipheriv('aes-256-gcm', secret('SESSION_SECRET'), Buffer.from(iv, 'base64url'));
  d.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([d.update(Buffer.from(ct, 'base64url')), d.final()]).toString('utf8');
}

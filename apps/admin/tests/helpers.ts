import { randomBytes, randomUUID } from 'node:crypto';
import pg from 'pg';
import { inject } from 'vitest';
import { seal } from '@/lib/crypto';
import { hashPassword } from '@/lib/password';
import { newTotpSecret, totpNow } from '@/lib/totp';

const COOKIE = '__Host-sx_session';

export interface Res<T = any> {
  status: number;
  json: T;
  headers: Headers;
}

/** Minimal browser-like client: cookie jar, CSRF token, per-instance client IP so rate-limit buckets never collide. */
export class Client {
  cookie: string | null = null;
  csrf: string | null = null;
  ip = `10.${rnd()}.${rnd()}.${rnd()}`;
  constructor(public base = inject('baseUrl')) {}

  async req<T = any>(path: string, o: { method?: string; body?: unknown; rawBody?: string; headers?: Record<string, string>; csrf?: boolean | string; bearer?: string } = {}): Promise<Res<T>> {
    const method = o.method ?? (o.body !== undefined || o.rawBody !== undefined ? 'POST' : 'GET');
    const headers: Record<string, string> = { 'x-forwarded-for': this.ip, ...(o.headers ?? {}) };
    if (o.body !== undefined || o.rawBody !== undefined) headers['content-type'] = 'application/json';
    if (this.cookie) headers.cookie = `${COOKIE}=${this.cookie}`;
    if (o.bearer) headers.authorization = `Bearer ${o.bearer}`;
    if (method !== 'GET' && o.csrf !== false) {
      const t = typeof o.csrf === 'string' ? o.csrf : this.csrf;
      if (t) headers['x-csrf-token'] = t;
    }
    const res = await fetch(this.base + path, { method, headers, body: o.rawBody ?? (o.body !== undefined ? JSON.stringify(o.body) : undefined), redirect: 'manual' });
    for (const sc of res.headers.getSetCookie()) {
      const m = sc.match(new RegExp(`^${COOKIE}=([^;]*)`));
      if (m) this.cookie = /max-age=0|expires=thu, 01 jan 1970/i.test(sc) || !m[1] ? null : m[1];
    }
    const text = await res.text();
    let json: any = {};
    try {
      json = text ? JSON.parse(text) : {};
    } catch {
      json = { _text: text };
    }
    return { status: res.status, json, headers: res.headers };
  }

  async login(email: string, password: string, totp?: string) {
    const r = await this.req('/api/auth/login', { body: { email, password, ...(totp ? { totp } : {}) } });
    if (r.status === 200 && r.json.ok) await this.refreshCsrf();
    return r;
  }

  async refreshCsrf() {
    const me = await this.req('/api/auth/me');
    this.csrf = me.json.csrf ?? null;
    return me;
  }
}

function rnd() {
  return 1 + Math.floor(Math.random() * 250);
}

export function db() {
  return new pg.Client({ connectionString: inject('dbUrl') });
}

export async function sql<T extends pg.QueryResultRow = any>(text: string, params: unknown[] = []): Promise<T[]> {
  const c = db();
  await c.connect();
  try {
    return (await c.query<T>(text, params)).rows;
  } finally {
    await c.end();
  }
}

export interface SeedUser {
  id: string;
  email: string;
  password: string;
  totpSecret: string | null;
}

export async function seedUser(o: { name: string; platformRole?: string; orgId?: string; orgRole?: 'org_admin' | 'member'; mfa?: boolean }): Promise<SeedUser> {
  const email = `${o.name.toLowerCase().replace(/\W+/g, '-')}-${randomBytes(3).toString('hex')}@test.example`;
  const password = `Pw-${randomBytes(9).toString('base64url')}-ok`;
  const secret = o.mfa === false ? null : newTotpSecret();
  const [u] = await sql<{ id: string }>(
    `INSERT INTO users(email, name, password_hash, platform_role, mfa_enabled, mfa_secret) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
    [email, o.name, await hashPassword(password), o.platformRole ?? null, !!secret, secret ? seal(secret) : null],
  );
  if (o.orgId) await sql('INSERT INTO memberships(user_id, org_id, role) VALUES ($1,$2,$3)', [u.id, o.orgId, o.orgRole ?? 'member']);
  return { id: u.id, email, password, totpSecret: secret };
}

export async function signIn(u: SeedUser): Promise<Client> {
  const c = new Client();
  let r = await c.login(u.email, u.password);
  if (r.json.mfaRequired) r = await c.login(u.email, u.password, await totpNow(u.totpSecret!));
  if (r.status !== 200) throw new Error(`sign-in failed for ${u.email}: ${r.status} ${JSON.stringify(r.json)}`);
  return c;
}

export async function seedOrg(name: string): Promise<string> {
  const [o] = await sql<{ id: string }>('INSERT INTO organizations(name) VALUES ($1) RETURNING id', [`${name} ${randomUUID().slice(0, 6)}`]);
  return o.id;
}

export async function seedLicense(orgId: string, seats: number, extra: { status?: string; expiresInDays?: number | null } = {}) {
  const hash = randomBytes(32).toString('hex');
  const [l] = await sql<{ id: string }>(
    `INSERT INTO licenses(org_id, key_hash, key_hint, seats, status, expires_at) VALUES ($1,$2,'TEST',$3,$4, $5) RETURNING id`,
    [orgId, hash, seats, extra.status ?? 'active', extra.expiresInDays === undefined ? null : extra.expiresInDays === null ? null : new Date(Date.now() + extra.expiresInDays * 864e5).toISOString()],
  );
  return l.id;
}

/** Enroll a device end to end through the real API and return its credential. */
export async function enrollDevice(admin: Client, orgId: string, hostname = 'TEST-PC') {
  const code = await admin.req('/api/admin/enrollments', { body: { orgId } });
  if (code.status !== 200) throw new Error(`enrollment code failed: ${code.status} ${JSON.stringify(code.json)}`);
  const dev = new Client();
  const r = await dev.req('/api/device/enroll', { body: { code: code.json.code, hostname, os: 'windows', appVersion: '0.1.0' } });
  return { res: r, code: code.json.code as string, token: r.json.token as string, deviceId: r.json.deviceId as string, client: dev };
}

export const HEARTBEAT = {
  appVersion: '0.1.0',
  engineVersion: 'ClamAV 1.5.4',
  intelVersion: '28159',
  intelUpdatedAt: new Date().toISOString(),
  protection: { engineState: 'running', realtimeState: 'active' },
};

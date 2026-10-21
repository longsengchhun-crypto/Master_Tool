import { NextResponse } from 'next/server';
import { createHash } from 'node:crypto';
import { updateFor } from '@/lib/device-support';
import { clientIpOf, handle } from '@/lib/http';
import { allow } from '@/lib/ratelimit';
import { HttpError } from '@/lib/session';

export const runtime = 'nodejs';

const PLATFORMS = new Set(['windows-x64', 'macos-arm64', 'macos-x64', 'linux-x64']);

/**
 * Application update feed in the Tauri updater's dynamic-server format. This channel carries *application* updates only;
 * malware signatures update separately. A release is only ever offered if it has an artifact URL, a SHA-256 and a
 * signature, and the client independently verifies the signature against the public key compiled into the app, so a
 * compromised server or CDN cannot push an unsigned build.
 */
export const GET = handle(
  async (req, ctx: { params: Promise<{ platform: string; version: string }> }) => {
    const { platform, version } = await ctx.params;
    if (!PLATFORMS.has(platform) || !/^\d+\.\d+\.\d+$/.test(version)) throw new HttpError(400, 'Bad request', 'invalid_request');
    const ip = clientIpOf(req) ?? 'unknown';
    if (!(await allow(`upd:${ip}`, 120, 60))) throw new HttpError(429, 'Too many requests', 'rate_limited');

    // A stable anonymous install id (or, failing that, the IP) decides rollout cohort membership.
    const id = req.nextUrl.searchParams.get('id') ?? createHash('sha256').update(ip).digest('hex');
    const channel = req.nextUrl.searchParams.get('channel') === 'beta' ? 'beta' : 'stable';
    const offer = await updateFor(platform, channel, version, id.slice(0, 64));
    if (!offer) return new NextResponse(null, { status: 204 });
    return { version: offer.version, notes: offer.notes, pub_date: offer.pubDate, url: offer.url, signature: offer.signature };
  },
  { cookieAuth: false },
);

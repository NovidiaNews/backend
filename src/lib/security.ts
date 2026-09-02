import crypto from 'crypto';
import type { FastifyInstance } from 'fastify';

// ---------------------------------------------------------------------------
// IP ban (instant, DB-backed, cached in memory)
// ---------------------------------------------------------------------------

/** ip -> expiry timestamp in ms; 0 means permanent */
const ipBanCache = new Map<string, number>();
const BAN_CACHE_TTL_MS = 60_000;

export function hashIp(ip: string): string {
  return crypto.createHash('sha256').update(`novidia:${ip}`).digest('hex');
}

export async function loadIpBan(fastify: FastifyInstance, ip: string): Promise<{ expiresAt: number } | null> {
  const rec = await fastify.prisma.ipBan.findUnique({ where: { ip } });
  if (!rec) return null;
  return { expiresAt: rec.expiresAt ? rec.expiresAt.getTime() : 0 };
}

export async function isIpBanned(fastify: FastifyInstance, ip: string): Promise<boolean> {
  const cached = ipBanCache.get(ip);
  if (cached !== undefined) {
    if (cached === 0) return true;
    if (cached > Date.now()) return true;
    ipBanCache.delete(ip);
    return false;
  }

  const rec = await loadIpBan(fastify, ip);
  const expiresAt = rec ? rec.expiresAt : -1;
  ipBanCache.set(ip, expiresAt === 0 ? 0 : expiresAt > 0 ? expiresAt : -1);
  return rec !== null && (rec.expiresAt === 0 || rec.expiresAt > Date.now());
}

export async function banIp(
  fastify: FastifyInstance,
  ip: string,
  reason: string,
  source: 'manual' | 'rate_limit',
  bannedBy?: string | null,
  expiresAt?: Date | null
): Promise<void> {
  const exp = expiresAt ?? null;
  await fastify.prisma.ipBan.upsert({
    where: { ip },
    create: { ip, reason, source, bannedBy, expiresAt: exp },
    update: { reason, source, bannedBy, expiresAt: exp },
  });
  ipBanCache.set(ip, exp ? exp.getTime() : 0);
}

export async function unbanIp(fastify: FastifyInstance, ip: string): Promise<boolean> {
  ipBanCache.delete(ip);
  try {
    await fastify.prisma.ipBan.delete({ where: { ip } });
    return true;
  } catch {
    return false;
  }
}

export function purgeExpiredBanCache() {
  const now = Date.now();
  for (const [ip, exp] of ipBanCache) {
    if (exp !== 0 && exp <= now) ipBanCache.delete(ip);
  }
}

// ---------------------------------------------------------------------------
// Sensitive-path rate limiting: 3 requests / 10s -> 5-minute IP ban
// ---------------------------------------------------------------------------

export const SENSITIVE_PATH_PATTERN =
  /(^\/api\/|\/admin|(^|\/)env|\.env|\/config|\/debug|\/flag|\.git|\/users\/(login|register|verify-email|resend-code)\/?$|^\/auth\/)/i;

const SENSITIVE_WINDOW_MS = 10_000;
const SENSITIVE_MAX = 3;
export const SENSITIVE_VIOLATION_BAN_MS = 5 * 60_000;

const sensitiveHits = new Map<string, number[]>();

export function isSensitivePath(path: string): boolean {
  return SENSITIVE_PATH_PATTERN.test(path.split('?')[0]);
}

/** Returns true when the request count within the window has been exceeded. */
export function recordSensitiveHit(ip: string): boolean {
  const now = Date.now();
  const recent = (sensitiveHits.get(ip) || []).filter((t) => now - t < SENSITIVE_WINDOW_MS);
  recent.push(now);
  sensitiveHits.set(ip, recent);
  return recent.length > SENSITIVE_MAX;
}
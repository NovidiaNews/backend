import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { hashIp } from '../lib/security.js';
import { lookupIp, parseAcceptLanguage } from '../lib/geo.js';

// GDPR: page visit tracking (IP + geolocation) is only performed when the
// visitor has given explicit consent through the cookie banner. The frontend
// sends `X-Novidia-Consent: analytics` only after consent was granted.
const CONSENT_HEADER = 'x-novidia-consent';
const UA_MAX_LENGTH = 400;

export default async function visitRoutes(fastify: FastifyInstance) {
  fastify.post('/visits', {
    schema: {
      body: z.object({
        path: z.string().max(500),
      }),
    },
  }, async (request, reply) => {
    if (request.headers[CONSENT_HEADER] !== 'analytics') {
      // No consent => nothing is stored (GDPR art. 6(1)(a) / ePrivacy)
      return reply.code(204).send();
    }

    const { path } = request.body as any;

    let userId: string | undefined;
    const auth = request.headers.authorization;
    if (auth?.startsWith('Bearer ')) {
      try {
        userId = (await fastify.jwt.verify(auth.slice(7)) as any).id;
      } catch {
        // token optional — ignore invalid tokens
      }
    } else {
      // Try cookie-based auth
      const cookieToken = request.cookies?.novidia_token;
      if (cookieToken) {
        try {
          userId = (await fastify.jwt.verify(cookieToken) as any).id;
        } catch {}
      }
    }

    const userAgent = (request.headers['user-agent'] || '').slice(0, UA_MAX_LENGTH) || null;
    const acceptLanguage = request.headers['accept-language'] as string | undefined;

    const ip = request.ip;
    // Resolve real client IP: check x-forwarded-for (reverse proxy), then
    // x-real-ip (sent by frontend via ipify), then fall back to request.ip
    const forwarded = (request.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim();
    const realIp = request.headers['x-real-ip'] as string | undefined;
    const resolvedIp = (forwarded || realIp || ip);

    const ipHash = hashIp(resolvedIp);
    const geo = await lookupIp(resolvedIp);
    const lang = parseAcceptLanguage(acceptLanguage);

    await fastify.prisma.visit.create({
      data: {
        path,
        ipHash,
        ipTruncated: resolvedIp,
        userId: userId ?? null,
        country: geo.country ?? lang.region ?? null,
        countryCode: geo.countryCode ?? null,
        region: geo.region ?? null,
        city: geo.city || null,
        timezone: geo.timezone ?? null,
        lat: geo.lat,
        lon: geo.lon,
        userAgent,
      },
    });

    return { ok: true };
  });
}
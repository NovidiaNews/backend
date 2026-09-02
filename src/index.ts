import 'dotenv/config';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import { serializerCompiler, validatorCompiler, ZodTypeProvider } from 'fastify-type-provider-zod';
import cookiePlugin from '@fastify/cookie';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import { z } from 'zod';
import prismaPlugin from './plugins/prisma.js';
import authPlugin from './plugins/auth.js';
import articleRoutes from './routes/articles.js';
import userRoutes from './routes/users.js';
import schoolRoutes from './routes/schools.js';
import adminRoutes from './routes/admin.js';
import oauthPlugin from './routes/auth.js';
import visitRoutes from './routes/visits.js';
import eventRoutes from './routes/events.js';
import { isIpBanned, banIp, isSensitivePath, recordSensitiveHit, purgeExpiredBanCache } from './lib/security.js';
import { startDeletionScheduler } from './jobs/deletion-scheduler.js';
import fs from 'fs/promises';
import path from 'path';

// GDPR retention: visit/geodata is purged automatically after 90 days
const VISIT_RETENTION_DAYS = Number(process.env.VISIT_RETENTION_DAYS) || 90;
const VISIT_RETENTION_MS = VISIT_RETENTION_DAYS * 24 * 60 * 60 * 1000;

// Zod environment validation
const isProduction = process.env.NODE_ENV === 'production';
const envSchema = z.object({
  DATABASE_URL: z.string().url(),
  JWT_SECRET: isProduction ? z.string().min(32) : z.string().min(16).optional(),
  PORT: z.string().optional().default('3001'),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  // Add other required envs
});
try {
  envSchema.parse(process.env);
} catch (error: any) {
  console.error("FATAL: Environment validation failed.");
  console.error(error.errors);
  process.exit(1);
}

const fastify = Fastify({
  logger: true,
  bodyLimit: 1048576, // 1MB payload limit
  // Only trust X-Forwarded-For when explicitly behind a reverse proxy.
  // Keeps dev/test environments spoof-safe (loopback bypass and IP bans).
  trustProxy: process.env.TRUST_PROXY === 'true',
}).withTypeProvider<ZodTypeProvider>();

const ALLOWED_ORIGINS = [
  'https://novidia.eu',
  'https://www.novidia.eu',
  'http://localhost:4001',
  'http://localhost:3000',
];

// ---------------------------------------------------------------------------
// Plugin + route bootstrap: every registration is awaited so route-level
// hooks (e.g. the global rate limiter) are attached to ALL routes —
// including root routes like /health, /admin. Without awaiting, root routes
// register before queued plugins run and silently escape their hooks.
// ---------------------------------------------------------------------------
const start = async () => {
  const port = Number(process.env.PORT) || 3000;

  try {
    // CORS: browser-level protection — reject any origin not in the list
    await fastify.register(cors, {
      origin: (origin, cb) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin)) {
          cb(null, true);
          return;
        }
        cb(new Error('Not allowed by CORS'), false);
      },
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Novidia-Consent'],
      credentials: true,
    });

    await fastify.register(helmet, {
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'", "http://localhost:3001", "http://localhost:4001"],
          fontSrc: ["'self'", "https:", "data:"],
          frameAncestors: ["'none'"],
          objectSrc: ["'none'"],
          baseUri: ["'self'"],
        }
      },
      // COOP/CORP must stay OFF for the OAuth round-trip
      crossOriginOpenerPolicy: false,
      crossOriginResourcePolicy: false,
      hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    });

    // Global rate limit: 5 requests per second (per IP).
    // Loopback traffic (local dev/health checks) and CORS preflights are
    // exempt so the admin dashboard's burst of parallel fetches can't
    // self-throttle in development — production traffic is fully limited.
    await fastify.register(rateLimit, {
      max: 5,
      timeWindow: '1 second',
      allowList: (request) => {
        const ip = request.ip;
        if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') return true;
        if (request.method === 'OPTIONS') return true;
        return false;
      },
      errorResponseBuilder: (request: any, context: any) => ({
        statusCode: 429,
        error: 'Too Many Requests',
        message: `Rate limit exceeded, retry in ${context.after}`
      })
    });

    await fastify.register(cookiePlugin);
    await fastify.register(prismaPlugin);
    await fastify.register(authPlugin);
    await fastify.register(oauthPlugin);
    await fastify.register(articleRoutes, { prefix: '/articles' });
    await fastify.register(userRoutes, { prefix: '/users' });
    await fastify.register(schoolRoutes, { prefix: '/schools' });
    await fastify.register(adminRoutes, { prefix: '/admin' });
    await fastify.register(visitRoutes);
    await fastify.register(eventRoutes);

    fastify.get('/health', async () => {
      return { status: 'ok' };
    });

    fastify.get('/', async (request, reply) => {
      try {
        const rootIndex = path.resolve(process.cwd(), 'index.html');
        const publicIndex = path.resolve(process.cwd(), 'public', 'index.html');
        const fileToServe = (await fs.stat(rootIndex).then(() => rootIndex).catch(() => publicIndex));
        const html = await fs.readFile(fileToServe, 'utf8');
        reply.type('text/html').send(html);
      } catch (err) {
        reply.code(404).send('Not found');
      }
    });

    // Serve admin page directly
    fastify.get('/admin.html', async (request, reply) => {
      try {
        const file = path.resolve(process.cwd(), 'public', 'admin.html');
        const html = await fs.readFile(file, 'utf8');
        reply.type('text/html').send(html);
      } catch (err) {
        reply.code(404).send('Not found');
      }
    });

    // Redirect /admin to admin.html
    fastify.get('/admin', async (request, reply) => {
      reply.redirect('/admin.html');
    });

    await fastify.listen({ port, host: '0.0.0.0' });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};
start();

// Server-side origin enforcement — validates Origin/Referer when present
fastify.addHook('onRequest', async (request, reply) => {
  const path = request.url.split('?')[0];
  if ((path.startsWith('/auth/') || path.startsWith('/api/auth/')) && path.endsWith('/callback')) return;

  const origin = request.headers.origin;
  const referer = request.headers.referer as string | undefined;

  function isAllowed(val: string): boolean {
    try {
      return ALLOWED_ORIGINS.includes(new URL(val).origin);
    } catch { return false; }
  }

  if (origin && !isAllowed(origin)) {
    return reply.status(403).send({ message: 'Forbidden' });
  }
  if (referer && !isAllowed(referer)) {
    return reply.status(403).send({ message: 'Forbidden' });
  }
});

// Capture logs into an in-memory buffer for admin UI
import { addLog } from './lib/logBuffer.js';

// Wrap logger methods to also push into buffer
['info', 'warn', 'error', 'debug', 'fatal'].forEach((method) => {
  const orig = (fastify.log as any)[method];
  (fastify.log as any)[method] = (...args: any[]) => {
    try {
      const msg = typeof args[0] === 'string' ? args[0] : JSON.stringify(args[0]);
      addLog({ level: method, time: Date.now(), msg, pid: process.pid });
    } catch (e) {
      // ignore
    }
    return orig.apply(fastify.log, args);
  };
});

// Capture request/response lifecycle and errors with extensive details
fastify.addHook('onRequest', (request, reply, done) => {
  try {
    const ip = request.ip;
    const userAgent = request.headers['user-agent'] || 'unknown';
    const origin = request.headers['origin'] || request.headers['referer'] || 'direct';
    const query = Object.keys(request.query || {}).length > 0 ? JSON.stringify(request.query) : 'none';
    const msg = `[Request] Incoming: ${request.method} ${request.url} | IP: ${ip} | Origin: ${origin} | User-Agent: ${userAgent} | QueryParams: ${query}`;
    addLog({ level: 'info', time: Date.now(), msg, pid: process.pid, url: request.url });
  } catch (e) {}
  done();
});

fastify.addHook('onResponse', (request, reply, done) => {
  try {
    const duration = reply.elapsedTime ? `${reply.elapsedTime.toFixed(2)}ms` : 'unknown';
    const size = reply.getHeader('content-length') || 'unknown';
    const msg = `[Response] Completed: ${request.method} ${request.url} -> Status: ${reply.statusCode} | Duration: ${duration} | Content-Length: ${size}`;
    addLog({ level: 'info', time: Date.now(), msg, pid: process.pid, url: request.url });
  } catch (e) {}
  done();
});

fastify.addHook('onError', (request, reply, error, done) => {
  try {
    const ip = request.ip;
    const msg = `[Error] Failed: ${request.method} ${request.url} from IP: ${ip} -> Error: ${error.message} | Code: ${error.code || 'N/A'} | Stack: ${error.stack}`;
    addLog({ level: 'error', time: Date.now(), msg, pid: process.pid, url: request.url });
  } catch (e) {}
  done();
});

fastify.setValidatorCompiler(validatorCompiler);
fastify.setSerializerCompiler(serializerCompiler);

// Centralized error handler
fastify.setErrorHandler((error: any, request, reply) => {
  request.log.error(error);
  if (error.validation) {
    return reply.status(400).send({ error: 'Bad Request', message: 'Invalid request data' });
  }
  const statusCode = error.statusCode || 500;
  // Always sanitize error messages in production; only show details in development
  const message = isProduction
    ? 'Internal Server Error'
    : (statusCode === 500 ? 'Internal Server Error' : error.message);
  return reply.status(statusCode).send({ error: error.name || 'Error', message });
});

// ---------------------------------------------------------------------------
// Global IP-ban enforcement + sensitive-path rate limiting.
// Sensitive paths (api, admin, env, config, auth, ...): 3 requests / 10
// seconds; every violation bans the offender's IP for 5 minutes.
// ---------------------------------------------------------------------------
fastify.addHook('onRequest', async (request, reply) => {
  const pathname = request.url.split('?')[0];
  const ip = request.ip;

  // OAuth provider callbacks must always pass through (browser redirects)
  if (pathname.endsWith('/callback')) return;

  // Local/loopback traffic (dev tooling, health checks) is exempt from
  // IP bans and sensitive-path limiting.
  if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') return;

  // 1) Instant IP ban (cache-first)
  if (await isIpBanned(fastify, ip)) {
    return reply.code(403).send({ message: 'IP_BANNED', isBanned: true });
  }

  // 2) Sensitive path limiting (authenticated requests are exempt)
  if (isSensitivePath(pathname)) {
    let authenticated = false;
    const auth = request.headers.authorization;
    if (auth?.startsWith('Bearer ')) {
      try {
        await fastify.jwt.verify(auth.slice(7));
        authenticated = true;
      } catch {
        // invalid token — treat as anonymous
      }
    }

    if (!authenticated) {
      const violated = recordSensitiveHit(ip);
      if (violated) {
        const expires = new Date(Date.now() + 5 * 60 * 1000);
        await banIp(fastify, ip, `Zbyt wiele żądań do ścieżki wrażliwej: ${pathname}`, 'rate_limit', null, expires);
        request.log.warn(`[SECURITY] IP ${ip} rate-limited on sensitive path ${pathname} -> banned for 5 minutes`);
        return reply.code(429).send({
          statusCode: 429,
          error: 'Too Many Requests',
          message: 'Zbyt wiele żądań. Adres IP został zablokowany na 5 minut.',
        });
      }
    }
  }
});

// ---------------------------------------------------------------------------
// GDPR retention worker: purge old visits + expired IP bans
fastify.addHook('onReady', async () => {
  const purge = async () => {
    try {
      await fastify.prisma.visit.deleteMany({
        where: { createdAt: { lt: new Date(Date.now() - VISIT_RETENTION_MS) } },
      });
      await fastify.prisma.ipBan.deleteMany({
        where: { expiresAt: { lt: new Date(), not: null } },
      });
      purgeExpiredBanCache();
    } catch (e) {
      fastify.log.error('[RETENTION] purge failed: ' + (e as Error).message);
    }
  };
  await purge().catch(() => {});
  setInterval(purge, 6 * 60 * 60 * 1000).unref();

  // Start the deletion scheduler (soft-delete reminders + hard-delete)
  startDeletionScheduler(fastify.prisma);
});

// ---------------------------------------------------------------------------
// Plugin + route bootstrap: every registration is awaited so route-level

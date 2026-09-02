import fp from 'fastify-plugin';
import fastifyJwt from '@fastify/jwt';
import { FastifyReply, FastifyRequest, FastifyInstance } from 'fastify';

const authPlugin = fp(async (fastify: FastifyInstance) => {
  const isProd = process.env.NODE_ENV === 'production';
  const secret = process.env.JWT_SECRET || (isProd ? '' : 'dev-only-insecure-secret');

  // Never run production with a missing or placeholder secret
  if (!secret || (isProd && secret.includes('supersecret'))) {
    throw new Error('FATAL: JWT_SECRET must be set to a strong random value in production.');
  }

  fastify.register(fastifyJwt, {
    secret,
    sign: {
      expiresIn: '15m', // Short-lived access tokens
    },
  });

  fastify.decorate('authenticate', async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      // Try Authorization header first, then cookie
      const authHeader = request.headers.authorization;
      if (authHeader?.startsWith('Bearer ')) {
        await request.jwtVerify();
      } else if (request.cookies?.novidia_token) {
        // Verify the token from httpOnly cookie
        try {
          const decoded = fastify.jwt.verify(request.cookies.novidia_token) as any;
          (request as any).user = decoded;
        } catch (jwtErr: any) {
          // If the token is expired (not invalid), silently refresh it
          if (jwtErr.code === 'FAST_JWT_EXPIRED') {
            const decoded = fastify.jwt.decode(request.cookies.novidia_token) as any;
            if (decoded?.id) {
              const newToken = fastify.jwt.sign({ id: decoded.id, role: decoded.role });
              reply.setCookie('novidia_token', newToken, {
                path: '/',
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'lax',
                maxAge: 7 * 24 * 60 * 60,
              });
              (request as any).user = decoded;
            } else {
              throw jwtErr;
            }
          } else {
            throw jwtErr;
          }
        }
      } else {
        throw new Error('No token provided');
      }
    } catch (err) {
      reply.setCookie('novidia_token', '', { path: '/', maxAge: 0 });
      return reply.status(401).send({ message: 'Nieautoryzowany dostęp. Zaloguj się ponownie.' });
    }

    // INSTANT ban enforcement: check the live DB state on every authenticated
    // request so a ban takes effect immediately, not only at login.
    const tokenUser = request.user as { id: string };
    const dbUser = await fastify.prisma.user.findUnique({
      where: { id: tokenUser.id },
      select: { id: true, isBanned: true, unbanDate: true },
    });
    if (!dbUser) {
      return reply.status(401).send({ message: 'Konto nie istnieje.' });
    }
    if (dbUser.isBanned) {
      // Auto-unban: if unbanDate has passed, lift the ban immediately
      if (dbUser.unbanDate && dbUser.unbanDate < new Date()) {
        await fastify.prisma.user.update({
          where: { id: dbUser.id },
          data: { isBanned: false, unbanDate: null },
        });
        return; // user is unbanned, let the request through
      }

      const latestBan = await fastify.prisma.banRecord.findFirst({
        where: { userId: tokenUser.id },
        orderBy: { createdAt: 'desc' },
        select: { reason: true },
      });
      return reply.status(403).send({
        message: 'ACCOUNT_BANNED',
        isBanned: true,
        unbanDate: dbUser.unbanDate ?? null,
        banReason: latestBan?.reason ?? null,
      });
    }
  });

  fastify.decorate('requireRole', (minRole: number) => {
    return async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.user as { role: number };
      if (!user || user.role < minRole) {
        return reply.status(403).send({ message: 'Forbidden: Insufficient permissions' });
      }
    };
  });
});

export default authPlugin;

declare module 'fastify' {
  interface FastifyInstance {
    authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    requireRole: (minRole: number) => (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}

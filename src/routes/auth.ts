import { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import fastifyOauth2 from '@fastify/oauth2';
import * as process from 'process';
import * as argon2 from 'argon2';
import crypto from 'crypto';

interface OAuthProfile {
  provider: string;
  providerId: string;
  email: string;
  username: string;
  firstName?: string;
  lastName?: string;
  picture?: string;
}

// Resolve the public URLs for the API gateway and the frontend.
// Explicit env vars win; otherwise production defaults to the real domain
// instead of silently pointing OAuth callbacks/redirects back at localhost.
const isProd = process.env.NODE_ENV === 'production';
const CALLBACK_URL =
  process.env.OAUTH_CALLBACK_URL ||
  (isProd ? 'https://novidia.eu/api' : 'http://localhost:3001');
const FRONTEND_URL =
  process.env.FRONTEND_URL ||
  (isProd ? 'https://novidia.eu' : 'http://localhost:4001');

const INTENT_COOKIE = 'oauth2-intent';

// Landing page shown after a successful OAuth "link" flow
const linkRedirect = () => `${FRONTEND_URL}/?settings=true&tab=linked`;

async function handleOAuthCallback(fastify: FastifyInstance, provider: string, tokens: any, reply: any) {
  try {
    let profile: OAuthProfile;

    switch (provider) {
      case 'google': {
        const res = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
          headers: { Authorization: `Bearer ${tokens.token.access_token}` },
        });
        const data: any = await res.json();
        profile = {
          provider: 'google',
          providerId: data.id,
          email: data.email,
          username: data.email.split('@')[0],
          firstName: data.given_name,
          lastName: data.family_name,
          picture: data.picture,
        };
        break;
      }
      case 'facebook': {
        const res = await fetch(`https://graph.facebook.com/me?fields=id,email,first_name,last_name&access_token=${tokens.token.access_token}`);
        const data: any = await res.json();
        profile = {
          provider: 'facebook',
          providerId: data.id,
          email: data.email || `${data.id}@facebook.com`,
          username: (data.email || data.id).split('@')[0],
          firstName: data.first_name,
          lastName: data.last_name,
        };
        break;
      }
      case 'discord': {
        const res = await fetch('https://discord.com/api/users/@me', {
          headers: { Authorization: `Bearer ${tokens.token.access_token}` },
        });
        const data: any = await res.json();
        profile = {
          provider: 'discord',
          providerId: data.id,
          email: data.email,
          username: data.username,
          firstName: data.global_name || data.username,
        };
        break;
      }
      case 'apple': {
        const idToken = tokens.token.id_token;
        const parts = idToken.split('.');
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        profile = {
          provider: 'apple',
          providerId: payload.sub,
          email: payload.email || `${payload.sub}@apple.com`,
          username: payload.email ? payload.email.split('@')[0] : `apple_${payload.sub.slice(0, 8)}`,
          firstName: payload.given_name,
          lastName: payload.family_name,
        };
        break;
      }
      default:
        return reply.status(400).send({ message: 'Unknown provider' });
    }

    if (!profile.email) {
      return reply.status(400).send({ message: 'Email not provided by OAuth provider' });
    }

    const intent = ((reply.request as any).cookies || {})[INTENT_COOKIE];

    // "Link" flow: attach the provider to an existing account (matched by email).
    // The user is already signed in and explicitly asked to connect a provider.
    if (intent === 'link') {
      const existing = await fastify.prisma.user.findUnique({ where: { email: profile.email } });
      if (!existing) {
        return reply.redirect(`${FRONTEND_URL}/login?error=${encodeURIComponent('Brak konta dla podanego adresu e-mail — najpierw załóż konto.')}`);
      }
      await fastify.prisma.linkedAccount.upsert({
        where: { userId_provider: { userId: existing.id, provider } },
        update: { providerId: profile.providerId },
        create: { userId: existing.id, provider, providerId: profile.providerId },
      });
      await reply.setCookie(INTENT_COOKIE, '', { path: '/', maxAge: 0 });
      return reply.redirect(`${linkRedirect()}&linked=${provider}`);
    }

    let user = await fastify.prisma.user.findUnique({ where: { email: profile.email } });

    if (!user) {
      const hashedPassword = await argon2.hash(crypto.randomBytes(32).toString('hex'));
      user = await fastify.prisma.user.create({
        data: {
          email: profile.email,
          username: profile.username,
          password: hashedPassword,
          firstName: profile.firstName,
          lastName: profile.lastName,
          profilePicture: profile.picture,
          isVerified: true,
          isOnboarded: true,
        },
      });
    }

    await fastify.prisma.linkedAccount.upsert({
      where: { userId_provider: { userId: user.id, provider } },
      update: { providerId: profile.providerId },
      create: { userId: user.id, provider, providerId: profile.providerId },
    });

    const token = fastify.jwt.sign({ id: user.id, username: user.username, role: user.role });
    // Set JWT as httpOnly cookie for same-origin deployments (production)
    reply.setCookie('novidia_token', token, {
      path: '/',
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: isProd ? 'lax' : 'none',
      maxAge: 7 * 24 * 60 * 60, // 7 days
    });
    // Also pass token as URL param for cross-origin dev environments
    reply.redirect(`${FRONTEND_URL}/login?token=${encodeURIComponent(token)}`);
  } catch (err: any) {
    reply.redirect(`${FRONTEND_URL}/login?error=${encodeURIComponent(err.message || 'OAuth failed')}`);
  }
}

const oauthPlugin = fp(async (fastify: FastifyInstance) => {
  const providerConfigs: Record<string, { tokenHost: string; authorizeHost?: string; authorizePath?: string; tokenPath?: string; revokePath?: string }> = {
    google: {
      authorizeHost: 'https://accounts.google.com',
      authorizePath: '/o/oauth2/v2/auth',
      tokenHost: 'https://www.googleapis.com',
      tokenPath: '/oauth2/v4/token'
    },
    discord: {
      authorizeHost: 'https://discord.com',
      authorizePath: '/api/oauth2/authorize',
      tokenHost: 'https://discord.com',
      tokenPath: '/api/oauth2/token',
      revokePath: '/api/oauth2/token/revoke'
    },
  };

  const providers: { name: string; envPrefix: string; scope: string[] }[] = [
    { name: 'google', envPrefix: 'GOOGLE', scope: ['email', 'profile'] },
    { name: 'discord', envPrefix: 'DISCORD', scope: ['identify', 'email'] },
  ];

  for (const p of providers) {
    const clientId = process.env[`${p.envPrefix}_CLIENT_ID`];
    const clientSecret = process.env[`${p.envPrefix}_CLIENT_SECRET`];

    if (!clientId || !clientSecret) {
      fastify.log.info(`OAuth ${p.name} not configured — registering stub`);
      fastify.get(`/auth/${p.name}/login`, async (_request: any, reply: any) => {
        return reply.redirect(`${FRONTEND_URL}/login?error=${encodeURIComponent(`Logowanie przez ${p.name} nie jest skonfigurowane.`)}`);
      });
      continue;
    }

    const customCallbackUri = process.env[`${p.envPrefix}_CALLBACK_URL`];
    const callbackUri = customCallbackUri || `${CALLBACK_URL}/auth/${p.name}/callback`;

    (fastify as any).register(fastifyOauth2, {
      name: p.name,
      scope: p.scope,
      credentials: {
        client: {
          id: clientId,
          secret: clientSecret,
        },
        auth: providerConfigs[p.name],
      },
      startRedirectPath: `/auth/${p.name}/login`,
      callbackUri,
      cookie: {
        path: '/',
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
      },
      redirectStateCookieName: 'oauth2-state-v2',
      generateStateFunction: function(request: any, callback: any) {
        const state = crypto.randomBytes(16).toString('base64url');
        fastify.log.info(`[OAuth2 ${p.name}] State generated`);
        callback(null, state);
      },
      checkStateFunction: function(request: any, callback: any) {
        const queryState = request.query.state;
        const cookieState = request.cookies['oauth2-state-v2'];
        if (queryState && queryState === cookieState) {
          callback();
        } else {
          fastify.log.error(`[OAuth2 ${p.name} Check] Invalid OAuth state`);
          callback(new Error('Invalid state'));
        }
      }
    });

    fastify.get(`/auth/${p.name}/callback`, async (request: any, reply: any) => {
      try {
        const oauth2: any = (fastify as any)[p.name];
        const tokens = await oauth2.getAccessTokenFromAuthorizationCodeFlow(request);
        await handleOAuthCallback(fastify, p.name, tokens, reply);
      } catch (err: any) {
        fastify.log.error(`[OAuth2 ${p.name} Callback] Authentication failed`);
        reply.status(500).send({ error: 'Internal Server Error', message: 'OAuth authentication failed' });
      }
    });

    // "Link a provider" entry point: marks the next OAuth login as a link
    // request (cookie, 10 min) so the callback attaches the provider to the
    // existing account instead of creating/logging into a fresh session.
    fastify.get(`/auth/${p.name}/link`, async (_request: any, reply: any) => {
      reply.setCookie(INTENT_COOKIE, 'link', {
        path: '/',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 600,
      });
      return reply.redirect(`/auth/${p.name}/login`);
    });
  }

  fastify.get('/auth/providers', async () => {
    const available: string[] = [];
    for (const p of providers) {
      const clientId = process.env[`${p.envPrefix}_CLIENT_ID`];
      const clientSecret = process.env[`${p.envPrefix}_CLIENT_SECRET`];
      if (clientId && clientSecret) available.push(p.name);
    }
    return { providers: available };
  });
});

export default oauthPlugin;

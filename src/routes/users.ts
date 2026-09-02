import { FastifyInstance } from 'fastify';
import crypto from 'crypto';
import { z } from 'zod';
import { hashPassword, verifyPassword } from '../utils/password.js';
import { sendVerificationEmail, sendIpVerificationEmail, sendDeletionRequestedEmail } from '../utils/email.js';
import { isOwnerEmail } from '../lib/owners.js';
import { hashIp } from '../lib/security.js';
import { lookupIp } from '../lib/geo.js';

// Timing-safe comparison for verification codes to prevent timing attacks
function timingSafeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// Helper: resolve the real client IP from request headers
function resolveClientIp(request: any): string {
  const forwarded = (request.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim();
  const realIp = request.headers['x-real-ip'] as string | undefined;
  return process.env.TRUST_PROXY === 'true'
    ? (forwarded || realIp || request.ip)
    : request.ip;
}

// Temporary in-memory store for pending IP verification (email -> { ipHash, expiresAt })
const pendingIpVerifications = new Map<string, { ipHash: string; expiresAt: number; ip: string; geo: { city?: string | null; country?: string | null }; userAgent: string | null }>();

const USERNAME_SCHEMA = z.string().min(3).max(32).regex(/^[a-zA-Z0-9_.]+$/, 'Nazwa użytkownika może zawierać tylko litery, cyfry, _ oraz .');

export default async function userRoutes(fastify: FastifyInstance) {
  // Generate cryptographically-secure random 6-digit verification code
  const generateVerificationCode = () => {
    return crypto.randomInt(100000, 1000000).toString();
  };

  // Helper: set JWT as httpOnly cookie on the reply
  function setAuthCookie(reply: any, token: string) {
    reply.setCookie('novidia_token', token, {
      path: '/',
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60, // 7 days
    });
  }

  // Register (Public)
  fastify.post('/register', {
    config: {
      rateLimit: { max: 5, timeWindow: '15 minutes' },
    },
    schema: {
      body: z.object({
        username: USERNAME_SCHEMA,
        email: z.string().email(),
        password: z.string().min(8).max(128),
        firstName: z.string().max(64).optional(),
        lastName: z.string().max(64).optional(),
        consentToTOS: z.boolean().optional(),
      }),
    },
  }, async (request, reply) => {
    const { username, email, password, firstName, lastName, consentToTOS } = request.body as any;
    // GDPR: consent must be explicit — never default to true
    const consent = consentToTOS === true;
    if (!consent) {
      return reply.status(400).send({ message: 'Wymagana jest zgoda na Regulamin i Politykę prywatności.' });
    }

    try {
      // 1. Check if user already exists in User table
      const existingUser = await fastify.prisma.user.findFirst({
        where: {
          OR: [
            { email },
            { username },
          ]
        }
      });
      if (existingUser) {
        // Uniform message to prevent user enumeration
        return reply.status(409).send({ message: 'Konto o podanych danych już istnieje.' });
      }

      // 2. Delete any existing pending user with this email or username to avoid unique constraint issues
      await fastify.prisma.pendingUser.deleteMany({
        where: {
          OR: [
            { email },
            { username },
          ]
        }
      });

      const hashed = await hashPassword(password);
      const code = generateVerificationCode();
      const expires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

      // 3. Create pending user record
      await fastify.prisma.pendingUser.create({
        data: {
          username,
          email,
          password: hashed,
          firstName,
          lastName,
          consentToTOS: consent,
          verificationCode: code,
          verificationCodeExpires: expires,
        }
      });

      // Send verification email
      await sendVerificationEmail(email, code);

      return {
        status: 'needs_verification',
        message: 'Account created. Verification email sent.',
        user: {
          username,
          email,
          firstName,
          lastName,
          isVerified: false,
          isOnboarded: false,
        },
        token: null,
      };
    } catch (err: any) {
      if (err?.code === 'P2002') {
        return reply.status(409).send({ message: 'Konto o podanych danych już istnieje.' });
      }
      throw err;
    }
  });

  // Verify Email (Public, requires email and code)
  fastify.post('/verify-email', {
    config: {
      rateLimit: { max: 10, timeWindow: '15 minutes' },
    },
    schema: {
      body: z.object({
        email: z.string().email(),
        code: z.string().length(6),
      }),
    },
  }, async (request, reply) => {
    const { email, code } = request.body as any;

    // 1. Check if the user is already verified in User table
    const existingUser = await fastify.prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      const token = fastify.jwt.sign({ id: existingUser.id, username: existingUser.username, role: existingUser.role });
      setAuthCookie(reply, token);
      return {
        status: existingUser.isOnboarded ? 'success' : 'needs_onboarding',
        message: 'Email jest już zweryfikowany.',
        user: {
          id: existingUser.id,
          username: existingUser.username,
          email: existingUser.email,
          role: existingUser.role,
          firstName: existingUser.firstName,
          lastName: existingUser.lastName,
          isVerified: true,
          isOnboarded: existingUser.isOnboarded,
        },
        token,
      };
    }

    // 2. Look up the pending user registration
    const pendingUser = await fastify.prisma.pendingUser.findUnique({
      where: { email },
    });

    if (!pendingUser) {
      return reply.status(400).send({ message: 'Nie znaleziono rejestracji dla podanego adresu e-mail lub kod jest nieprawidłowy.' });
    }

    if (!timingSafeCompare(pendingUser.verificationCode, code)) {
      return reply.status(400).send({ message: 'Niepoprawny kod weryfikacyjny.' });
    }

    if (pendingUser.verificationCodeExpires < new Date()) {
      return reply.status(400).send({ message: 'Kod weryfikacyjny wygasł (jest ważny tylko przez 15 minut).' });
    }

    // 3. Email is verified! Create the user record in the main User table
    const user = await fastify.prisma.user.create({
      data: {
        username: pendingUser.username,
        email: pendingUser.email,
        password: pendingUser.password,
        firstName: pendingUser.firstName,
        lastName: pendingUser.lastName,
        consentToTOS: pendingUser.consentToTOS,
        role: isOwnerEmail(pendingUser.email) ? 100 : undefined,
        isVerified: true, // Mark verified directly
        isOnboarded: false,
      },
      select: {
        id: true,
        username: true,
        email: true,
        role: true,
        firstName: true,
        lastName: true,
        isVerified: true,
        isOnboarded: true,
        createdAt: true,
      },
    });

    // 4. Delete the pending user registration
    await fastify.prisma.pendingUser.delete({
      where: { id: pendingUser.id },
    });

    const token = fastify.jwt.sign({ id: user.id, username: user.username, role: user.role });
    setAuthCookie(reply, token);

    return {
      status: 'needs_onboarding', // New users need onboarding
      message: 'E-mail został pomyślnie zweryfikowany.',
      user,
      token,
    };
  });

  // Resend Code (Public)
  fastify.post('/resend-code', {
    config: {
      rateLimit: { max: 5, timeWindow: '15 minutes' },
    },
    schema: {
      body: z.object({
        email: z.string().email(),
      }),
    },
  }, async (request, reply) => {
    const { email } = request.body as any;

    // Check if the user is already verified and in the User table
    const existingUser = await fastify.prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return reply.status(400).send({ message: 'Ten e-mail jest już zweryfikowany.' });
    }

    // Look up the pending registration
    const pendingUser = await fastify.prisma.pendingUser.findUnique({
      where: { email },
    });

    if (!pendingUser) {
      return reply.status(400).send({ message: 'Nie znaleziono rejestracji dla podanego adresu e-mail lub konto jest już zweryfikowane.' });
    }

    const code = generateVerificationCode();
    const expires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    await fastify.prisma.pendingUser.update({
      where: { id: pendingUser.id },
      data: {
        verificationCode: code,
        verificationCodeExpires: expires,
      },
    });

    await sendVerificationEmail(email, code);

    return {
      status: 'success',
      message: 'Nowy kod weryfikacyjny został wysłany.',
    };
  });

  // Login (Public)
  fastify.post('/login', {
    config: {
      rateLimit: { max: 10, timeWindow: '15 minutes' },
    },
    schema: {
      body: z.object({
        login: z.string(), // can be email or username
        password: z.string(),
      }),
    },
  }, async (request, reply) => {
    const { login, password } = request.body as any;

    // Check User table first
    const user = await fastify.prisma.user.findFirst({
      where: {
        OR: [
          { email: login },
          { username: login },
        ],
      },
    });

    if (!user) {
      // If not in User, check if it exists in PendingUser
      const pendingUser = await fastify.prisma.pendingUser.findFirst({
        where: {
          OR: [
            { email: login },
            { username: login },
          ],
        },
      });

      if (!pendingUser) {
        return reply.status(401).send({ message: 'Nieprawidłowy login lub hasło.' });
      }

      // Verify password from PendingUser
      const match = await verifyPassword(pendingUser.password, password);
      if (!match) {
        return reply.status(401).send({ message: 'Nieprawidłowy login lub hasło.' });
      }

      // User exists but is unverified (not in User table yet). Send new code.
      const code = generateVerificationCode();
      const expires = new Date(Date.now() + 15 * 60 * 1000);

      await fastify.prisma.pendingUser.update({
        where: { id: pendingUser.id },
        data: {
          verificationCode: code,
          verificationCodeExpires: expires,
        },
      });

      await sendVerificationEmail(pendingUser.email, code);

      return {
        status: 'needs_verification',
        message: 'Konto nie jest zweryfikowane. Kod weryfikacyjny został wysłany.',
        user: {
          username: pendingUser.username,
          email: pendingUser.email,
          firstName: pendingUser.firstName,
          lastName: pendingUser.lastName,
          isVerified: false,
          isOnboarded: false,
        },
        token: null,
      };
    }

    const match = await verifyPassword(user.password, password);
    if (!match) {
      return reply.status(401).send({ message: 'Nieprawidłowy login lub hasło.' });
    }

    if (user.isBanned) {
      if (user.unbanDate && user.unbanDate < new Date()) {
        await fastify.prisma.user.update({
          where: { id: user.id },
          data: { isBanned: false, unbanDate: null },
        });
      } else {
        return reply.status(403).send({ message: 'Twoje konto jest zablokowane.' });
      }
    }

    if (user.isDisabled) {
      return reply.status(403).send({ message: 'Twoje konto jest wyłączone. Skontaktuj się z administratorem, aby je przywrócić.' });
    }

    // Auto-restore soft-deleted accounts on login
    let restored = false;
    if (user.deletedAt) {
      await fastify.prisma.user.update({
        where: { id: user.id },
        data: { deletedAt: null, scheduledDeletionAt: null, deletionAskedAt: null, deletionCode: null },
      });
      restored = true;
    }

    // Owner accounts are hard-promoted to role 100 on every login
    if (isOwnerEmail(user.email) && user.role < 100) {
      user.role = 100;
      await fastify.prisma.user.update({ where: { id: user.id }, data: { role: 100 } });
    }

    // ── New-IP detection ──────────────────────────────────────────────────
    const resolvedIp = resolveClientIp(request);
    const ipHash = hashIp(resolvedIp);

    const knownIp = await fastify.prisma.knownIp.findUnique({
      where: { userId_ipHash: { userId: user.id, ipHash } },
    });

    if (!knownIp) {
      // New IP — send verification code, don't issue token yet
      const code = generateVerificationCode();
      const expires = new Date(Date.now() + 15 * 60 * 1000);
      await fastify.prisma.user.update({
        where: { id: user.id },
        data: { verificationCode: code, verificationCodeExpires: expires },
      });
      const geo = await lookupIp(resolvedIp);
      const geoData = { city: geo.city, country: geo.country };
      pendingIpVerifications.set(user.email, { ipHash, expiresAt: expires.getTime(), ip: resolvedIp, geo: geoData, userAgent: request.headers['user-agent'] || null });
      // Cleanup stale entries periodically
      const now = Date.now();
      for (const [key, val] of pendingIpVerifications) {
        if (val.expiresAt < now) pendingIpVerifications.delete(key);
      }
      await sendIpVerificationEmail(user.email, code, resolvedIp, geoData);
      return {
        status: 'needs_ip_verification',
        message: 'Wykryto logowanie z nowego adresu IP. Kod weryfikacyjny został wysłany.',
        user: { email: user.email, username: user.username, firstName: user.firstName, lastName: user.lastName },
        token: null,
        restored,
      };
    }

    const token = fastify.jwt.sign({ id: user.id, username: user.username, role: user.role });
    setAuthCookie(reply, token);
    const userResponse = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      firstName: user.firstName,
      lastName: user.lastName,
      isVerified: user.isVerified,
      isOnboarded: user.isOnboarded,
      profilePicture: user.profilePicture,
      backgroundPicture: user.backgroundPicture,
      bio: user.bio,
      headline: user.headline,
      location: user.location,
      pronouns: user.pronouns,
      website: user.website,
      socials: user.socials,
      theme: user.theme,
      notificationsEnabled: user.notificationsEnabled,
      isDisabled: user.isDisabled,
    };

    if (!user.isOnboarded) {
      return {
        status: 'needs_onboarding',
        message: 'Wymagane jest ukończenie onboardingu.',
        user: userResponse,
        token,
        restored,
      };
    }

    return {
      status: 'success',
      message: 'Zalogowano pomyślnie.',
      user: userResponse,
      token,
      restored,
    };
  });

  // Complete Onboarding (Authenticated)
  fastify.post('/onboarding', {
    preHandler: [fastify.authenticate],
    schema: {
      body: z.object({
        profilePicture: z.string().optional(),
        bio: z.string().max(500).optional(),
        theme: z.string().optional(),
        notificationsEnabled: z.boolean().optional(),
      }),
    },
  }, async (request, reply) => {
    const currentUser = request.user as any;
    const { profilePicture, bio, theme, notificationsEnabled } = request.body as any;

    const data: any = {
      isOnboarded: true,
    };
    if (profilePicture !== undefined) data.profilePicture = profilePicture;
    if (bio !== undefined) data.bio = bio;
    if (theme !== undefined) data.theme = theme;
    if (notificationsEnabled !== undefined) data.notificationsEnabled = notificationsEnabled;

    const updatedUser = await fastify.prisma.user.update({
      where: { id: currentUser.id },
      data,
      select: {
        id: true,
        username: true,
        email: true,
        role: true,
        firstName: true,
        lastName: true,
        isVerified: true,
        isOnboarded: true,
        profilePicture: true,
        bio: true,
        theme: true,
        notificationsEnabled: true,
      },
    });

    return {
      status: 'success',
      message: 'Onboarding ukończony pomyślnie.',
      user: updatedUser,
    };
  });

  // Data export (Self, Authenticated) — GDPR art. 15/20: right of access & portability
  fastify.get('/me/export', {
    preHandler: [fastify.authenticate],
  }, async (request, reply) => {
    const currentUser = request.user as any;

    const user = await fastify.prisma.user.findUnique({
      where: { id: currentUser.id },
      select: {
        id: true,
        username: true,
        email: true,
        firstName: true,
        lastName: true,
        bio: true,
        role: true,
        isVerified: true,
        isOnboarded: true,
        notificationsEnabled: true,
        theme: true,
        consentToTOS: true,
        createdAt: true,
      },
    });
    if (!user) return reply.status(404).send({ message: 'Użytkownik nie został znaleziony.' });

    const articles = await fastify.prisma.article.findMany({
      where: { authorId: currentUser.id },
      orderBy: { createdAt: 'asc' },
      select: {
        id: true,
        title: true,
        content: true,
        status: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    return {
      exportedAt: new Date().toISOString(),
      platform: 'Novidia',
      exportedBy: 'user-request',
      user,
      articles,
    };
  });

  // Get current user profile (Authenticated)
  fastify.get('/me', {
    preHandler: [fastify.authenticate],
  }, async (request, reply) => {
    const currentUser = request.user as any;
    const user = await fastify.prisma.user.findUnique({
      where: { id: currentUser.id },
      select: {
        id: true,
        username: true,
        email: true,
        role: true,
        firstName: true,
        lastName: true,
        isVerified: true,
        isOnboarded: true,
        profilePicture: true,
        backgroundPicture: true,
        bio: true,
        headline: true,
        location: true,
        pronouns: true,
        website: true,
        socials: true,
        theme: true,
        notificationsEnabled: true,
        isDisabled: true,
        disabledAt: true,
        createdAt: true,
        linkedAccounts: {
          select: { id: true, provider: true, providerId: true, createdAt: true },
        },
      },
    });
    if (!user) return reply.status(404).send({ message: 'Użytkownik nie został znaleziony.' });
    return user;
  });

  // Get Profile (Authenticated)
  fastify.get('/:id', {
    preHandler: [fastify.authenticate],
    schema: {
      params: z.object({ id: z.string() }),
    },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const currentUser = request.user as any;
    
    if (currentUser.id !== id && currentUser.role < 100) {
      return reply.status(403).send({ message: 'Brak dostępu.' });
    }
    
    const user = await fastify.prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        username: true,
        email: true,
        role: true,
        firstName: true,
        lastName: true,
        isVerified: true,
        isOnboarded: true,
        profilePicture: true,
        backgroundPicture: true,
        bio: true,
        headline: true,
        location: true,
        pronouns: true,
        website: true,
        socials: true,
        theme: true,
        notificationsEnabled: true,
        isDisabled: true,
        createdAt: true,
        linkedAccounts: {
          select: { id: true, provider: true, providerId: true, createdAt: true },
        },
      },
    });
    if (!user) return reply.status(404).send({ message: 'Użytkownik nie został znaleziony.' });
    return user;
  });

  // Disable my account (Self, Authenticated)
  fastify.post('/me/disable', {
    preHandler: [fastify.authenticate],
    schema: {
      body: z.object({
        confirm: z.boolean().optional(),
      }),
    },
  }, async (request, reply) => {
    const currentUser = request.user as any;
    const { confirm } = request.body as any;
    if (!confirm) {
      return reply.status(400).send({ message: 'Potwierdź, że chcesz wyłączyć konto.' });
    }

    const dbUser = await fastify.prisma.user.findUnique({ where: { id: currentUser.id } });
    if (!dbUser) return reply.status(404).send({ message: 'Użytkownik nie został znaleziony.' });
    if (dbUser.role >= 100) {
      return reply.status(403).send({ message: 'Nie można wyłączyć konta właściciela serwisu.' });
    }

    await fastify.prisma.user.update({
      where: { id: currentUser.id },
      data: { isDisabled: true, disabledAt: new Date() },
    });

    // Revoke all sessions so the change takes effect immediately
    await fastify.prisma.refreshToken.deleteMany({ where: { userId: currentUser.id } });

    return { success: true, message: 'Konto zostało wyłączone.' };
  });

  // Reactivate my account (Self, Authenticated)
  fastify.post('/me/enable', {
    preHandler: [fastify.authenticate],
  }, async (request, reply) => {
    const currentUser = request.user as any;
    await fastify.prisma.user.update({
      where: { id: currentUser.id },
      data: { isDisabled: false, disabledAt: null },
    });
    return { success: true, message: 'Konto zostało ponownie aktywowane.' };
  });

  // Unlink an OAuth provider (Self, Authenticated)
  fastify.delete('/me/links/:provider', {
    preHandler: [fastify.authenticate],
    schema: {
      params: z.object({ provider: z.string() }),
    },
  }, async (request, reply) => {
    const currentUser = request.user as any;
    const { provider } = request.params as any;

    const dbUser = await fastify.prisma.user.findUnique({
      where: { id: currentUser.id },
      include: { linkedAccounts: true },
    });
    if (!dbUser) return reply.status(404).send({ message: 'Użytkownik nie został znaleziony.' });

    const willBeLastAuthMethod = dbUser.linkedAccounts.length <= 1 && !dbUser.password;
    if (provider === 'password' || willBeLastAuthMethod) {
      return reply.status(400).send({ message: 'Nie możesz odłączyć jedynej metody logowania.' });
    }

    await fastify.prisma.linkedAccount.deleteMany({
      where: { userId: currentUser.id, provider },
    });

    return { success: true };
  });

  // Update Profile (Self, Authenticated)
  fastify.patch('/:id', {
    preHandler: [fastify.authenticate],
    schema: {
      params: z.object({ id: z.string() }),
      body: z.object({
        username: USERNAME_SCHEMA.optional(),
        email: z.string().email().optional(),
        password: z.string().min(8).max(128).optional(),
        currentPassword: z.string().optional(),
        firstName: z.string().max(64).optional(),
        lastName: z.string().max(64).optional(),
        consentToTOS: z.boolean().optional(),
        profilePicture: z.string().optional(),
        backgroundPicture: z.string().optional().nullable(),
        bio: z.string().max(500).optional(),
        headline: z.string().max(120).optional(),
        location: z.string().max(120).optional(),
        pronouns: z.string().max(40).optional(),
        website: z.string().max(255).optional(),
        socials: z.record(z.string(), z.string()).nullable().optional(),
        theme: z.enum(['light', 'dark', 'system']).optional(),
        notificationsEnabled: z.boolean().optional(),
      }),
    },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const currentUser = request.user as any;
    const {
      username, email, password, currentPassword,
      firstName, lastName, consentToTOS,
      profilePicture, backgroundPicture, bio, headline, location, pronouns, website, socials,
      theme, notificationsEnabled,
    } = request.body as any;
    
    if (currentUser.id !== id) {
      return reply.status(403).send({ message: 'Brak dostępu.' });
    }

    // Security: changing email or password requires re-authentication
    // with the current password (matches the "re-auth on sensitive change" rule).
    const sensitiveChange = email !== undefined || password !== undefined;
    if (sensitiveChange) {
      if (!currentPassword) {
        return reply.status(400).send({ message: 'Podaj aktualne hasło, aby potwierdzić zmiany.' });
      }
      const dbUser = await fastify.prisma.user.findUnique({ where: { id } });
      if (!dbUser) {
        return reply.status(404).send({ message: 'Użytkownik nie został znaleziony.' });
      }
      const match = await verifyPassword(dbUser.password, currentPassword);
      if (!match) {
        return reply.status(403).send({ message: 'Nieprawidłowe aktualne hasło.' });
      }
    }
    
    const data: any = {};
    if (username) data.username = username;
    if (email) data.email = email;
    if (typeof firstName !== 'undefined') data.firstName = firstName;
    if (typeof lastName !== 'undefined') data.lastName = lastName;
    if (typeof consentToTOS !== 'undefined') data.consentToTOS = consentToTOS;
    if (typeof profilePicture !== 'undefined') data.profilePicture = profilePicture;
    if (backgroundPicture !== undefined) data.backgroundPicture = backgroundPicture;
    if (typeof bio !== 'undefined') data.bio = bio;
    if (headline !== undefined) data.headline = headline;
    if (location !== undefined) data.location = location;
    if (pronouns !== undefined) data.pronouns = pronouns;
    if (website !== undefined) data.website = website;
    if (socials !== undefined) data.socials = socials;
    if (theme !== undefined) data.theme = theme;
    if (typeof notificationsEnabled !== 'undefined') data.notificationsEnabled = notificationsEnabled;
    if (password) {
      data.password = await hashPassword(password);
    }

    try {
      const updated = await fastify.prisma.user.update({
        where: { id },
        data,
        select: {
          id: true,
          username: true,
          email: true,
          role: true,
          firstName: true,
          lastName: true,
          isVerified: true,
          isOnboarded: true,
          profilePicture: true,
          backgroundPicture: true,
          bio: true,
          headline: true,
          location: true,
          pronouns: true,
          website: true,
          socials: true,
          theme: true,
          notificationsEnabled: true,
          isDisabled: true,
          createdAt: true,
          linkedAccounts: {
            select: { id: true, provider: true, providerId: true, createdAt: true },
          },
        },
      });
      return updated;
    } catch (err: any) {
      if (err?.code === 'P2002') {
        return reply.status(409).send({ message: 'Nazwa użytkownika lub adres e-mail jest już zajęty.' });
      }
      throw err;
    }
  });

  // Delete Profile (Self or Admin, Authenticated) — soft-delete with 7-day grace
  fastify.delete('/:id', {
    preHandler: [fastify.authenticate],
    schema: {
      params: z.object({ id: z.string() }),
      body: z.object({
        password: z.string(),
        email: z.string(),
        username: z.string(),
      }),
    },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const { password, email, username } = request.body as any;
    const currentUser = request.user as any;
    
    if (currentUser.id !== id && currentUser.role < 100) {
      return reply.status(403).send({ message: 'Brak dostępu.' });
    }

    const user = await fastify.prisma.user.findUnique({ where: { id } });
    if (!user) {
      return reply.status(404).send({ message: 'Konto nie istnieje.' });
    }

    // Verify password
    const passwordMatch = await verifyPassword(user.password, password);
    if (!passwordMatch) {
      return reply.status(401).send({ message: 'Nieprawidłowe hasło.' });
    }

    // Verify email (case-insensitive)
    if (email.toLowerCase() !== user.email.toLowerCase()) {
      return reply.status(400).send({ message: 'Podany adres e-mail nie jest zgodny z adresem konta.' });
    }

    // Verify username (exact match)
    if (username !== user.username) {
      return reply.status(400).send({ message: 'Podana nazwa użytkownika nie jest zgodna z nazwą konta.' });
    }

    const now = new Date();
    const scheduledDeletion = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    const deletionCode = crypto.randomBytes(32).toString('hex');

    await fastify.prisma.user.update({
      where: { id },
      data: {
        deletedAt: now,
        scheduledDeletionAt: scheduledDeletion,
        deletionAskedAt: now,
        deletionCode,
      },
    });

    // Send deletion notification email
    const restoreLink = `https://www.novidia.eu/restore?code=${deletionCode}`;
    await sendDeletionRequestedEmail(user.email, restoreLink);

    return {
      success: true,
      message: 'Konto zostało oznaczone do usunięcia. Zostanie trwale usunięte za 7 dni.',
      scheduledDeletionAt: scheduledDeletion.toISOString(),
    };
  });

  // Verify IP (Public) — called after new-IP login detection
  fastify.post('/verify-ip', {
    config: {
      rateLimit: { max: 10, timeWindow: '15 minutes' },
    },
    schema: {
      body: z.object({
        email: z.string().email(),
        code: z.string().length(6),
      }),
    },
  }, async (request, reply) => {
    const { email, code } = request.body as any;

    const user = await fastify.prisma.user.findFirst({ where: { email } });
    if (!user) {
      return reply.status(404).send({ message: 'Nie znaleziono konta.' });
    }

    // Check code validity
    if (!user.verificationCode || !timingSafeCompare(user.verificationCode, code)) {
      return reply.status(400).send({ message: 'Nieprawidłowy kod weryfikacyjny.' });
    }
    if (!user.verificationCodeExpires || user.verificationCodeExpires < new Date()) {
      return reply.status(400).send({ message: 'Kod weryfikacyjny wygasł. Spróbuj ponownie.' });
    }

    // Retrieve pending IP
    const pending = pendingIpVerifications.get(email);
    if (!pending || pending.expiresAt < Date.now()) {
      pendingIpVerifications.delete(email);
      return reply.status(400).send({ message: 'Weryfikacja IP wygasła. Zaloguj się ponownie.' });
    }

    // Save known IP
    await fastify.prisma.knownIp.upsert({
      where: { userId_ipHash: { userId: user.id, ipHash: pending.ipHash } },
      create: {
        userId: user.id,
        ipHash: pending.ipHash,
        ip: pending.ip,
        city: pending.geo.city,
        country: pending.geo.country,
        userAgent: pending.userAgent,
      },
      update: { lastUsedAt: new Date() },
    });

    pendingIpVerifications.delete(email);

    // Clear verification code
    await fastify.prisma.user.update({
      where: { id: user.id },
      data: { verificationCode: null, verificationCodeExpires: null },
    });

    const token = fastify.jwt.sign({ id: user.id, username: user.username, role: user.role });
    setAuthCookie(reply, token);
    const userResponse = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      firstName: user.firstName,
      lastName: user.lastName,
      isVerified: user.isVerified,
      isOnboarded: user.isOnboarded,
      profilePicture: user.profilePicture,
      backgroundPicture: user.backgroundPicture,
      bio: user.bio,
      headline: user.headline,
      location: user.location,
      pronouns: user.pronouns,
      website: user.website,
      socials: user.socials,
      theme: user.theme,
      notificationsEnabled: user.notificationsEnabled,
      isDisabled: user.isDisabled,
    };

    return {
      status: 'success',
      message: 'Zweryfikowano urządzenie.',
      user: userResponse,
      token,
    };
  });

  // Restore soft-deleted account (Public, via deletion code)
  fastify.post('/restore', {
    config: {
      rateLimit: { max: 5, timeWindow: '15 minutes' },
    },
    schema: {
      body: z.object({
        code: z.string(),
      }),
    },
  }, async (request, reply) => {
    const { code } = request.body as any;

    const user = await fastify.prisma.user.findFirst({
      where: { deletionCode: code, deletedAt: { not: null } },
    });

    if (!user) {
      return reply.status(404).send({ message: 'Nie znaleziono konta do przywrócenia lub link wygasł.' });
    }

    await fastify.prisma.user.update({
      where: { id: user.id },
      data: {
        deletedAt: null,
        scheduledDeletionAt: null,
        deletionAskedAt: null,
        deletionCode: null,
      },
    });

    return {
      success: true,
      message: 'Konto zostało przywrócone. Możesz się teraz zalogować.',
    };
  });

  // ── Known IPs (logged devices) ──────────────────────────────────────────────
  fastify.get('/me/known-ips', {
    preHandler: [fastify.authenticate],
    schema: { querystring: z.object({}) },
  }, async (request, reply) => {
    const userId = (request.user as any).id;

    const ips = await fastify.prisma.knownIp.findMany({
      where: { userId },
      orderBy: { lastUsedAt: 'desc' },
    });

    return ips.map(ip => ({
      id: ip.id,
      ip: ip.ip,
      city: ip.city,
      country: ip.country,
      userAgent: ip.userAgent,
      lastUsedAt: ip.lastUsedAt,
      createdAt: ip.createdAt,
    }));
  });

  fastify.delete('/me/known-ips/:id', {
    preHandler: [fastify.authenticate],
    schema: { params: z.object({ id: z.string().uuid() }) },
  }, async (request, reply) => {
    const userId = (request.user as any).id;

    const { id } = request.params as any;

    const ip = await fastify.prisma.knownIp.findFirst({
      where: { id, userId },
    });

    if (!ip) {
      return reply.status(404).send({ message: 'Nie znaleziono urządzenia.' });
    }

    await fastify.prisma.knownIp.delete({ where: { id } });

    return { success: true };
  });

  // Sign out all other devices (delete all known IPs except current)
  fastify.post('/me/known-ips/sign-out-others', {
    preHandler: [fastify.authenticate],
    schema: { body: z.object({}) },
  }, async (request, reply) => {
    const userId = (request.user as any).id;

    // Get current IP hash to keep it
    const resolvedIp = resolveClientIp(request);
    const currentIpHash = hashIp(resolvedIp);

    const deleted = await fastify.prisma.knownIp.deleteMany({
      where: {
        userId,
        ipHash: { not: currentIpHash },
      },
    });

    return { success: true, signedOut: deleted.count };
  });
}

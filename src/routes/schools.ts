import { FastifyInstance } from 'fastify';
import crypto from 'crypto';
import { z } from 'zod';
import { hashPassword, verifyPassword } from '../utils/password.js';
import { sendVerificationEmail } from '../utils/email.js';
import { verifySchoolDomain } from '../utils/schoolDomain.js';

// Timing-safe comparison for verification codes
function timingSafeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

export default async function schoolRoutes(fastify: FastifyInstance) {
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

  // Register School (Public)
  fastify.post('/register', {
    config: {
      rateLimit: { max: 5, timeWindow: '15 minutes' },
    },
    schema: {
      body: z.object({
        schoolName: z.string().min(1),
        email: z.string().email(),
        password: z.string().min(8),
        phoneNumber: z.string().optional(),
        city: z.string().optional(),
        address: z.string().optional(),
        postalCode: z.string().optional(),
        rspoNumber: z.string().optional(),
        website: z.string().optional(),
        voivodeship: z.string().optional(),
        consentToTOS: z.boolean().optional(),
      }),
    },
  }, async (request, reply) => {
    const {
      schoolName, email, password, phoneNumber, city, address, postalCode,
      rspoNumber, website, voivodeship, consentToTOS,
    } = request.body as any;
    const consent = consentToTOS === true;

    try {
      const existingUser = await fastify.prisma.user.findUnique({ where: { email } });
      if (existingUser) {
        return reply.status(409).send({ message: 'Konto dla tego adresu e-mail już istnieje.' });
      }

      await fastify.prisma.pendingSchool.deleteMany({ where: { email } });

      // Verify school domain
      const domainResult = await verifySchoolDomain(email);
      if (!domainResult.valid) {
        return reply.status(400).send({ message: domainResult.message, domainVerification: domainResult });
      }

      // Pre-fill RSPO data if available
      const rspoData = domainResult.rspoData;
      const hashed = await hashPassword(password);
      const code = generateVerificationCode();
      const expires = new Date(Date.now() + 15 * 60 * 1000);

      await fastify.prisma.pendingSchool.create({
        data: {
          email,
          password: hashed,
          schoolName,
          phoneNumber,
          city: city || rspoData?.city || null,
          address: address || rspoData?.address || null,
          postalCode: postalCode || rspoData?.postalCode || null,
          rspoNumber: rspoNumber || rspoData?.rspoNumber || null,
          website: website || rspoData?.website || null,
          voivodeship: voivodeship || rspoData?.voivodeship || null,
          consentToTOS: consent,
          verificationCode: code,
          verificationCodeExpires: expires,
          domainData: rspoData as any,
        },
      });

      await sendVerificationEmail(email, code);

      return {
        status: 'needs_verification',
        message: 'Konto szkoły utworzone. Wysłano kod weryfikacyjny na adres e-mail.',
        domainVerified: domainResult.isSchoolDomain,
        rspoData,
        user: {
          email,
          schoolName,
          isVerified: false,
          isOnboarded: false,
        },
        token: null,
      };
    } catch (err: any) {
      if (err?.code === 'P2002') {
        return reply.status(409).send({ message: 'Konto dla tego adresu e-mail już istnieje.' });
      }
      throw err;
    }
  });

  // Verify School Email (Public)
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

    const existingUser = await fastify.prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      const token = fastify.jwt.sign({ id: existingUser.id, username: existingUser.email, role: existingUser.role });
      setAuthCookie(reply, token);
      return {
        status: existingUser.isOnboarded ? 'success' : 'needs_onboarding',
        message: 'Email jest już zweryfikowany.',
        schoolProfile: existingUser.role === 30 ? await fastify.prisma.schoolProfile.findUnique({ where: { userId: existingUser.id } }) : null,
        user: {
          id: existingUser.id,
          username: existingUser.username,
          firstName: existingUser.firstName,
          email: existingUser.email,
          role: existingUser.role,
          isVerified: true,
          isOnboarded: existingUser.isOnboarded,
          profilePicture: existingUser.profilePicture,
        },
        token,
      };
    }

    const pendingSchool = await fastify.prisma.pendingSchool.findUnique({ where: { email } });
    if (!pendingSchool) {
      return reply.status(404).send({ message: 'Nie znaleziono rejestracji dla podanego adresu e-mail.' });
    }

    if (!timingSafeCompare(pendingSchool.verificationCode, code)) {
      return reply.status(400).send({ message: 'Niepoprawny kod weryfikacyjny.' });
    }

    if (pendingSchool.verificationCodeExpires < new Date()) {
      return reply.status(400).send({ message: 'Kod weryfikacyjny wygasł (ważny 15 minut).' });
    }

    // Generate unique username from email prefix
    let schoolUsername = pendingSchool.email.split('@')[0].replace(/[^a-zA-Z0-9_-]/g, '_');
    try {
      const existing = await fastify.prisma.user.findUnique({ where: { username: schoolUsername } });
      if (existing) schoolUsername = `${schoolUsername}_${Date.now().toString(36)}`;
    } catch {}

    const user = await fastify.prisma.user.create({
      data: {
        username: schoolUsername,
        email: pendingSchool.email,
        password: pendingSchool.password,
        firstName: pendingSchool.schoolName,
        role: 30,
        consentToTOS: pendingSchool.consentToTOS,
        isVerified: true,
        isOnboarded: false,
      },
      select: {
        id: true,
        username: true,
        email: true,
        role: true,
        firstName: true,
        isVerified: true,
        isOnboarded: true,
        profilePicture: true,
        createdAt: true,
      },
    });

    // Create SchoolProfile
    const schoolProfile = await fastify.prisma.schoolProfile.create({
      data: {
        schoolName: pendingSchool.schoolName,
        phoneNumber: pendingSchool.phoneNumber,
        city: pendingSchool.city,
        address: pendingSchool.address,
        postalCode: pendingSchool.postalCode,
        rspoNumber: pendingSchool.rspoNumber,
        website: pendingSchool.website,
        voivodeship: pendingSchool.voivodeship,
        userId: user.id,
      },
    });

    await fastify.prisma.pendingSchool.delete({ where: { id: pendingSchool.id } });

    const token = fastify.jwt.sign({ id: user.id, username: user.email, role: user.role });
    setAuthCookie(reply, token);

    return {
      status: 'needs_onboarding',
      message: 'E-mail szkoły został pomyślnie zweryfikowany.',
      schoolProfile,
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

    const existingUser = await fastify.prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return reply.status(400).send({ message: 'Ten e-mail jest już zweryfikowany.' });
    }

    const pendingSchool = await fastify.prisma.pendingSchool.findUnique({ where: { email } });
    if (!pendingSchool) {
      return reply.status(404).send({ message: 'Nie znaleziono rejestracji dla podanego adresu e-mail.' });
    }

    const code = generateVerificationCode();
    const expires = new Date(Date.now() + 15 * 60 * 1000);

    await fastify.prisma.pendingSchool.update({
      where: { id: pendingSchool.id },
      data: { verificationCode: code, verificationCodeExpires: expires },
    });

    await sendVerificationEmail(email, code);

    return {
      status: 'success',
      message: 'Nowy kod weryfikacyjny został wysłany.',
    };
  });

  // Login School (Public)
  fastify.post('/login', {
    config: {
      rateLimit: { max: 10, timeWindow: '15 minutes' },
    },
    schema: {
      body: z.object({
        email: z.string(),
        password: z.string(),
      }),
    },
  }, async (request, reply) => {
    const { email, password } = request.body as any;

    const user = await fastify.prisma.user.findFirst({
      where: {
        OR: [{ email }, { username: email }],
      },
    });

    if (!user) {
    const pendingSchool = await fastify.prisma.pendingSchool.findUnique({ where: { email } });
    if (!pendingSchool) {
      return reply.status(400).send({ message: 'Nie znaleziono rejestracji dla podanego adresu e-mail lub konto jest już zweryfikowane.' });
    }

      const match = await verifyPassword(pendingSchool.password, password);
      if (!match) {
        return reply.status(401).send({ message: 'Nieprawidłowy e-mail lub hasło.' });
      }

      const code = generateVerificationCode();
      const expires = new Date(Date.now() + 15 * 60 * 1000);

      await fastify.prisma.pendingSchool.update({
        where: { id: pendingSchool.id },
        data: { verificationCode: code, verificationCodeExpires: expires },
      });

      await sendVerificationEmail(email, code);

      return {
        status: 'needs_verification',
        message: 'Konto szkoły nie jest zweryfikowane. Wysłano nowy kod.',
        user: {
          email: pendingSchool.email,
          schoolName: pendingSchool.schoolName,
          isVerified: false,
          isOnboarded: false,
        },
        token: null,
      };
    }

    const match = await verifyPassword(user.password, password);
    if (!match) {
      return reply.status(401).send({ message: 'Nieprawidłowy e-mail lub hasło.' });
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

    const token = fastify.jwt.sign({ id: user.id, username: user.email || user.username, role: user.role });
    setAuthCookie(reply, token);
    const schoolProfile = await fastify.prisma.schoolProfile.findUnique({ where: { userId: user.id } });

    const userResponse = {
      id: user.id,
      username: user.username,
      firstName: user.firstName,
      email: user.email,
      role: user.role,
      isVerified: user.isVerified,
      isOnboarded: user.isOnboarded,
      profilePicture: user.profilePicture,
      schoolProfile,
    };

    if (!user.isOnboarded) {
      return {
        status: 'needs_onboarding',
        message: 'Wymagane jest uzupełnienie profilu szkoły.',
        user: userResponse,
        token,
      };
    }

    return {
      status: 'success',
      message: 'Zalogowano pomyślnie.',
      user: userResponse,
      token,
    };
  });

  // Complete School Onboarding (Authenticated)
  fastify.post('/onboarding', {
    preHandler: [fastify.authenticate],
    schema: {
      body: z.object({
        logo: z.string().optional(),
        description: z.string().max(1000).optional(),
        phoneNumber: z.string().optional(),
        city: z.string().optional(),
        address: z.string().optional(),
        postalCode: z.string().optional(),
        website: z.string().optional(),
      }),
    },
  }, async (request, reply) => {
    const currentUser = request.user as any;

    const user = await fastify.prisma.user.findUnique({ where: { id: currentUser.id } });
    if (!user) {
      return reply.status(404).send({ message: 'Użytkownik nie znaleziony.' });
    }

    const { logo, description, phoneNumber, city, address, postalCode, website } = request.body as any;

    const profileData: any = { isOnboarded: true };
    if (logo !== undefined) profileData.profilePicture = logo;

    await fastify.prisma.user.update({
      where: { id: currentUser.id },
      data: profileData,
    });

    const schoolData: any = {};
    if (description !== undefined) schoolData.description = description;
    if (phoneNumber !== undefined) schoolData.phoneNumber = phoneNumber;
    if (city !== undefined) schoolData.city = city;
    if (address !== undefined) schoolData.address = address;
    if (postalCode !== undefined) schoolData.postalCode = postalCode;
    if (website !== undefined) schoolData.website = website;

    const schoolProfile = await fastify.prisma.schoolProfile.upsert({
      where: { userId: currentUser.id },
      create: { ...schoolData, userId: currentUser.id, schoolName: user.firstName || '' },
      update: schoolData,
    });

    return {
      status: 'success',
      message: 'Profil szkoły został uzupełniony.',
      schoolProfile,
      user: {
        id: user.id,
        username: user.username,
        firstName: user.firstName,
        email: user.email,
        role: user.role,
        isVerified: user.isVerified,
        isOnboarded: true,
        profilePicture: profileData.profilePicture || user.profilePicture,
      },
    };
  });

  // Get School Profile (Authenticated)
  fastify.get('/profile', {
    preHandler: [fastify.authenticate],
  }, async (request, reply) => {
    const currentUser = request.user as any;

    const user = await fastify.prisma.user.findUnique({
      where: { id: currentUser.id },
      select: {
        id: true,
        email: true,
        role: true,
        firstName: true,
        isVerified: true,
        isOnboarded: true,
        profilePicture: true,
        createdAt: true,
      },
    });

    if (!user) return reply.status(404).send({ message: 'Użytkownik nie znaleziony.' });

    const schoolProfile = await fastify.prisma.schoolProfile.findUnique({
      where: { userId: currentUser.id },
    });

    return { ...user, schoolProfile };
  });

  // Update School Profile (Authenticated)
  fastify.patch('/profile', {
    preHandler: [fastify.authenticate],
    schema: {
      body: z.object({
        schoolName: z.string().optional(),
        phoneNumber: z.string().optional(),
        city: z.string().optional(),
        address: z.string().optional(),
        postalCode: z.string().optional(),
        website: z.string().optional(),
        voivodeship: z.string().optional(),
        description: z.string().max(1000).optional(),
        logo: z.string().optional(),
      }),
    },
  }, async (request, reply) => {
    const currentUser = request.user as any;
    const body = request.body as any;

    const schoolData: any = {};
    if (body.schoolName !== undefined) schoolData.schoolName = body.schoolName;
    if (body.phoneNumber !== undefined) schoolData.phoneNumber = body.phoneNumber;
    if (body.city !== undefined) schoolData.city = body.city;
    if (body.address !== undefined) schoolData.address = body.address;
    if (body.postalCode !== undefined) schoolData.postalCode = body.postalCode;
    if (body.website !== undefined) schoolData.website = body.website;
    if (body.voivodeship !== undefined) schoolData.voivodeship = body.voivodeship;
    if (body.description !== undefined) schoolData.description = body.description;
    if (body.logo !== undefined) schoolData.logo = body.logo;

    if (body.schoolName) {
      await fastify.prisma.user.update({
        where: { id: currentUser.id },
        data: { firstName: body.schoolName },
      });
    }

    const schoolProfile = await fastify.prisma.schoolProfile.upsert({
      where: { userId: currentUser.id },
      create: { ...schoolData, userId: currentUser.id, schoolName: body.schoolName || '' },
      update: schoolData,
    });

    return schoolProfile;
  });
}

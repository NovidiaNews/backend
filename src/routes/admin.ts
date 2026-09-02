import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import * as process from 'process';
import * as argon2 from 'argon2';
import * as os from 'os';
import { banIp, unbanIp } from '../lib/security.js';
import { pushBanEvent } from './events.js';

export default async function adminRoutes(fastify: FastifyInstance) {
  const authPre = [fastify.authenticate, fastify.requireRole(90)];

  const SYSTEM_STAT_SELECT = {
    id: true,
    username: true,
    email: true,
    role: true,
    isBanned: true,
    isVerified: true,
    isOnboarded: true,
    strikes: true,
    profilePicture: true,
    bio: true,
    theme: true,
    notificationsEnabled: true,
    consentToTOS: true,
    createdAt: true,
    userDevices: {
      orderBy: { lastSeenAt: 'desc' as const },
      take: 1,
      select: { ipAddress: true, lastSeenAt: true, userAgent: true },
    },
  };

  function bytesToMB(bytes: number): number {
    return Math.round((bytes / (1024 * 1024)) * 10) / 10;
  }

  async function getCpuUsage(): Promise<{ percent: number; cores: number; model: string }> {
    const cpus = os.cpus();
    const prev = cpus.map((c) => ({ idle: c.times.idle, total: Object.values(c.times).reduce((a, b) => a + b, 0) }));
    await new Promise((r) => setTimeout(r, 500));
    const now = os.cpus();
    const deltas = now.map((c, i) => {
      const total = Object.values(c.times).reduce((a, b) => a + b, 0);
      return { idle: c.times.idle - prev[i].idle, total: total - prev[i].total };
    });
    const totalIdle = deltas.reduce((a, d) => a + d.idle, 0);
    const totalAll = deltas.reduce((a, d) => a + d.total, 0);
    const percent = Math.round((1 - totalIdle / Math.max(totalAll, 1)) * 100);
    return { percent, cores: cpus.length, model: cpus[0]?.model || 'unknown' };
  }

  // List all users
  fastify.get('/users', { preHandler: authPre }, async (request, reply) => {
    // Auto-unban: lift any expired bans before returning the list
    await fastify.prisma.user.updateMany({
      where: { isBanned: true, unbanDate: { not: null, lt: new Date() } },
      data: { isBanned: false, unbanDate: null },
    });

    const users = await fastify.prisma.user.findMany({
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        username: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true,
        strikes: true,
        isBanned: true,
        unbanDate: true,
        isVerified: true,
        isOnboarded: true,
        isDisabled: true,
        createdAt: true,
        userDevices: { orderBy: { lastSeenAt: 'desc' }, take: 1, select: { ipAddress: true, lastSeenAt: true } },
      },
    });
    return users.map((u) => ({ ...u, lastIp: u.userDevices[0]?.ipAddress || null }));
  });

  // Get single user
  fastify.get('/users/:id', {
    preHandler: authPre,
    schema: { params: z.object({ id: z.string() }) },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const user = await fastify.prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        username: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true,
        strikes: true,
        isBanned: true,
        unbanDate: true,
        isVerified: true,
        isOnboarded: true,
        isDisabled: true,
        createdAt: true,
        userDevices: true,
      },
    });
    if (!user) return reply.status(404).send({ message: 'User not found' });
    return user;
  });

  // Partial update user properties (legacy)
  fastify.patch('/users/:id/properties', {
    preHandler: authPre,
    schema: {
      params: z.object({ id: z.string() }),
      body: z.object({
        role: z.number().optional(),
        isBanned: z.boolean().optional(),
        unbanDate: z.string().datetime().optional().nullable(),
        strikes: z.number().optional(),
      }),
    },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const data = request.body as any;

    const updatedUser = await fastify.prisma.user.update({
      where: { id },
      data: {
        ...data,
        unbanDate: data.unbanDate ? new Date(data.unbanDate) : data.unbanDate === null ? null : undefined,
      },
      select: {
        id: true,
        username: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true,
        strikes: true,
        isBanned: true,
        unbanDate: true,
        isVerified: true,
        isOnboarded: true,
        createdAt: true,
      },
    });
    return updatedUser;
  });

  // Full user update (admin: can change any field including password)
  fastify.put('/users/:id', {
    preHandler: authPre,
    schema: { params: z.object({ id: z.string() }) },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const body = request.body as any;
    const currentUser = request.user as { id: string; role: number };

    const existingUser = await fastify.prisma.user.findUnique({ where: { id } });
    if (!existingUser) return reply.status(404).send({ message: 'User not found' });

    // Prevent role escalation: cannot promote others to role >= your own role
    // Owner (100) bypasses all restrictions
    if (currentUser.role < 100) {
      if (body.role !== undefined && id !== currentUser.id && body.role >= currentUser.role) {
        return reply.status(403).send({ message: 'Nie możesz nadać roli równej lub wyższej od własnej.' });
      }
      // Prevent modifying the owner (role 100)
      if (existingUser.role >= 100) {
        return reply.status(403).send({ message: 'Nie możesz modyfikować właściciela serwisu.' });
      }
    }

    const allowedFields = [
      'username', 'email', 'firstName', 'lastName', 'role',
      'strikes', 'isBanned', 'unbanDate', 'isVerified',
      'isOnboarded', 'profilePicture', 'bio', 'theme',
      'notificationsEnabled', 'consentToTOS',
    ] as const;

    const updateData: Record<string, unknown> = {};
    for (const field of allowedFields) {
      if (body[field] !== undefined) {
        if (field === 'unbanDate' && body[field] !== null) {
          updateData[field] = new Date(body[field]);
        } else {
          updateData[field] = body[field];
        }
      }
    }

    if (body.password && body.password !== existingUser.password) {
      updateData.password = await argon2.hash(body.password);
    }

    const updatedUser = await fastify.prisma.user.update({
      where: { id },
      data: updateData,
      select: {
        id: true,
        username: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true,
        strikes: true,
        isBanned: true,
        isVerified: true,
        isOnboarded: true,
        createdAt: true,
      },
    });
    return updatedUser;
  });

  // Delete user
  fastify.delete('/users/:id', {
    preHandler: authPre,
    schema: { params: z.object({ id: z.string() }) },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const currentUser = request.user as { id: string };
    if (id === currentUser.id) {
      return reply.status(403).send({ message: 'Nie możesz usunąć własnego konta.' });
    }
    const user = await fastify.prisma.user.findUnique({ where: { id } });
    if (!user) return reply.status(404).send({ message: 'User not found' });

    await fastify.prisma.article.deleteMany({ where: { authorId: id } });
    await fastify.prisma.user.delete({ where: { id } });
    return { success: true };
  });

  // Ban routes removed as part of undoing ban logic

  // Unban routes removed as part of undoing ban logic

  // List all articles
  fastify.get('/articles', {
    preHandler: authPre,
  }, async (request, reply) => {
    const articles = await fastify.prisma.article.findMany({
      include: { author: true },
      orderBy: { createdAt: 'desc' },
    });
    return articles;
  });

  // Update any article (admin)
  fastify.put('/articles/:id', {
    preHandler: authPre,
    schema: { params: z.object({ id: z.string() }) },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const body = request.body as any;

    const article = await fastify.prisma.article.findUnique({ where: { id } });
    if (!article) return reply.status(404).send({ message: 'Article not found' });

    const updateData: Record<string, unknown> = {};
    if (body.title !== undefined) updateData.title = body.title;
    if (body.content !== undefined) updateData.content = body.content;
    if (body.status !== undefined) updateData.status = body.status;

    const updated = await fastify.prisma.article.update({
      where: { id },
      data: updateData,
    });
    return updated;
  });

  // Delete any article (admin)
  fastify.delete('/articles/:id', {
    preHandler: authPre,
    schema: { params: z.object({ id: z.string() }) },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const article = await fastify.prisma.article.findUnique({ where: { id } });
    if (!article) return reply.status(404).send({ message: 'Article not found' });

    await fastify.prisma.article.delete({ where: { id } });
    return { success: true };
  });

  // GET logs
  fastify.get('/logs', {
    preHandler: authPre,
  }, async (request, reply) => {
    const { getLogs } = await import('../lib/logBuffer.js');
    const since = Number((request.query as any)?.since) || 0;
    const includeAdmin = (request.query as any)?.includeAdmin === 'true';
    return getLogs(since, { excludeAdmin: !includeAdmin });
  });

  // -------------------------------------------------------------------------
  // Instant ban / unban (takes effect immediately via the authenticate hook)
  // -------------------------------------------------------------------------

  // Ban user (optionally with their last known IP and unban date)
  fastify.post('/users/:id/ban', {
    preHandler: authPre,
    schema: {
      params: z.object({ id: z.string() }),
      body: z.object({
        reason: z.string().max(300).optional(),
        banIp: z.boolean().optional(),
        unbanDate: z.string().datetime().optional().nullable(),
      }),
    },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const { reason, banIp, unbanDate } = request.body as any;
    const currentUser = request.user as { id: string };

    const actor = await fastify.prisma.user.findUnique({
      where: { id: currentUser.id },
      select: { id: true, role: true },
    });
    if (!actor) return reply.status(401).send({ message: 'Konto nie istnieje' });

    const user = await fastify.prisma.user.findUnique({
      where: { id },
      include: {
        userDevices: { orderBy: { lastSeenAt: 'desc' }, take: 1, select: { ipAddress: true } },
      },
    });
    if (!user) return reply.status(404).send({ message: 'User not found' });
    if (user.id === actor.id) {
      return reply.status(403).send({ message: 'Nie możesz zbanować samego siebie.' });
    }
    if (user.role >= 100) {
      return reply.status(403).send({ message: 'Nie możesz zbanować właściciela serwisu.' });
    }
    if (user.role >= 90 && actor.role < 100) {
      return reply.status(403).send({ message: 'Nie możesz zbanować administratora — tylko właściciel.' });
    }

    await fastify.prisma.user.update({
      where: { id },
      data: {
        isBanned: true,
        unbanDate: unbanDate ? new Date(unbanDate) : null,
      },
    });

    pushBanEvent(user.id, reason || null);

    let bannedIp: string | null = null;
    if (banIp && user.userDevices[0]?.ipAddress) {
      bannedIp = user.userDevices[0].ipAddress;
      await banIp(fastify, bannedIp, reason || `Ban powiązany z kontem: ${user.username}`, 'manual', currentUser.id);
    }

    return { success: true, bannedIp };
  });

  // Unban user
  fastify.post('/users/:id/unban', {
    preHandler: authPre,
    schema: { params: z.object({ id: z.string() }) },
  }, async (request, reply) => {
    const { id } = request.params as any;
    await fastify.prisma.user.update({
      where: { id },
      data: { isBanned: false, unbanDate: null },
    });
    return { success: true };
  });

  // Quick toggle verified badge
  fastify.patch('/users/:id/verify', {
    preHandler: authPre,
    schema: { params: z.object({ id: z.string() }) },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const user = await fastify.prisma.user.findUnique({ where: { id }, select: { id: true, isVerified: true } });
    if (!user) return reply.status(404).send({ message: 'User not found' });

    const updated = await fastify.prisma.user.update({
      where: { id },
      data: { isVerified: !user.isVerified },
      select: { id: true, isVerified: true },
    });
    return updated;
  });

  // Quick role change (owner-only: can set any role value)
  fastify.patch('/users/:id/role', {
    preHandler: authPre,
    schema: {
      params: z.object({ id: z.string() }),
      body: z.object({ role: z.number().int().min(0).max(999) }),
    },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const { role } = request.body as any;
    const currentUser = request.user as { id: string; role: number };

    const targetUser = await fastify.prisma.user.findUnique({ where: { id }, select: { id: true, role: true } });
    if (!targetUser) return reply.status(404).send({ message: 'User not found' });

    // Only owner (100) can promote to 100 or change other owners
    if (role >= 100 && currentUser.role < 100) {
      return reply.status(403).send({ message: 'Tylko właściciel może nadawać rolę 100.' });
    }
    if (targetUser.role >= 100 && currentUser.role < 100) {
      return reply.status(403).send({ message: 'Nie możesz zmieniać roli właściciela.' });
    }

    const updated = await fastify.prisma.user.update({
      where: { id },
      data: { role },
      select: { id: true, username: true, role: true },
    });
    return updated;
  });

  // -------------------------------------------------------------------------
  // System overview (RAM, CPU, largest user-generated files)
  // -------------------------------------------------------------------------

  fastify.get('/stats/system', { preHandler: authPre }, async (request, reply) => {
    const cpu = await getCpuUsage();
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;

    const [topArticles, topAvatars, topBios, counts] = await Promise.all([
      fastify.prisma.article.findMany({
        orderBy: { content: 'desc' },
        take: 10,
        select: {
          id: true,
          title: true,
          content: true,
          status: true,
          createdAt: true,
          author: { select: { id: true, username: true } },
        },
      }),
      fastify.prisma.user.findMany({
        where: { NOT: { profilePicture: null } },
        orderBy: { profilePicture: 'desc' },
        take: 10,
        select: { id: true, username: true, profilePicture: true },
      }),
      fastify.prisma.user.findMany({
        where: { NOT: { bio: null } },
        orderBy: { bio: 'desc' },
        take: 10,
        select: { id: true, username: true, bio: true },
      }),
      Promise.all([
        fastify.prisma.user.count(),
        fastify.prisma.article.count(),
        fastify.prisma.visit.count(),
        fastify.prisma.ipBan.count(),
      ]),
    ]);

    return {
      cpu: { percent: cpu.percent, cores: cpu.cores, model: cpu.model },
      memory: {
        totalMB: bytesToMB(totalMem),
        usedMB: bytesToMB(usedMem),
        freeMB: bytesToMB(freeMem),
        percent: Math.round((usedMem / totalMem) * 100),
        processMB: Math.round(process.memoryUsage().rss / 1024 / 1024),
      },
      system: {
        platform: os.platform(),
        arch: os.arch(),
        release: os.release(),
        hostname: os.hostname(),
        uptimeSec: Math.round(os.uptime()),
        nodeVersion: process.version,
        loadAvg: os.loadavg().map((n) => Math.round(n * 100) / 100),
      },
      largestFiles: {
        articles: topArticles.map((a) => ({
          id: a.id,
          title: a.title,
          author: a.author.username,
          status: a.status,
          sizeMB: bytesToMB(Buffer.byteLength(a.content)),
          sizeBytes: Buffer.byteLength(a.content),
          createdAt: a.createdAt,
        })),
        avatars: topAvatars.map((u) => ({
          id: u.id,
          username: u.username,
          sizeMB: bytesToMB(Buffer.byteLength(u.profilePicture || '')),
          sizeBytes: Buffer.byteLength(u.profilePicture || ''),
        })),
        bios: topBios.map((u) => ({
          id: u.id,
          username: u.username,
          sizeMB: bytesToMB(Buffer.byteLength(u.bio || '')),
          sizeBytes: Buffer.byteLength(u.bio || ''),
        })),
      },
      counts: {
        users: counts[0],
        articles: counts[1],
        visits: counts[2],
        ipBans: counts[3],
      },
    };
  });

  // -------------------------------------------------------------------------
  // Visits (geotracking)
  // -------------------------------------------------------------------------

  fastify.get('/stats/visits', { preHandler: authPre }, async (request, reply) => {
    const sinceMs = Number((request.query as any)?.since) || 0;
    const where = sinceMs ? { createdAt: { gte: new Date(sinceMs) } } : {};

    const [total, uniqueIps, countries, recent] = await Promise.all([
      fastify.prisma.visit.count({ where }),
      fastify.prisma.visit.groupBy({ by: ['ipHash'], where, _count: true }),
      fastify.prisma.visit.groupBy({ by: ['countryCode', 'country'], where: { countryCode: { not: null } }, _count: { _all: true } }),
      fastify.prisma.visit.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: 100,
      }),
    ]);

    // Visits per day over the last 14 days
    const days: { date: string; count: number }[] = [];
    for (let i = 13; i >= 0; i--) {
      const day = new Date();
      day.setDate(day.getDate() - i);
      day.setHours(0, 0, 0, 0);
      const next = new Date(day);
      next.setDate(next.getDate() + 1);
      const count = await fastify.prisma.visit.count({
        where: { createdAt: { gte: day, lt: next } },
      });
      days.push({ date: day.toISOString().slice(0, 10), count });
    }

    return {
      total,
      uniqueVisitors: uniqueIps.length,
      perDay: days,
      countries: countries
        .map((c) => ({ code: c.countryCode, country: c.country, count: c._count._all }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 50),
      recent,
    };
  });

  // Delete visits (manual GDPR erasure / maintenance)
  fastify.delete('/visits', { preHandler: authPre }, async (request, reply) => {
    const result = await fastify.prisma.visit.deleteMany({});
    return { success: true, deleted: result.count };
  });

  // Delete visits older than N days (retention enforcement)
  fastify.delete('/visits/older-than', {
    preHandler: authPre,
    schema: {
      body: z.object({ days: z.number().int().min(1).max(3650) }),
    },
  }, async (request, reply) => {
    const { days } = request.body as any;
    const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
    const result = await fastify.prisma.visit.deleteMany({ where: { createdAt: { lt: cutoff } } });
    return { success: true, deleted: result.count };
  });

  // -------------------------------------------------------------------------
  // IP bans
  // -------------------------------------------------------------------------

  fastify.get('/ipbans', { preHandler: authPre }, async (request, reply) => {
    const bans = await fastify.prisma.ipBan.findMany({ orderBy: { createdAt: 'desc' } });
    return bans.map((b) => ({ ...b, active: !b.expiresAt || b.expiresAt > new Date() }));
  });

  fastify.post('/ipbans', {
    preHandler: authPre,
    schema: {
      body: z.object({
        ip: z.string().max(64),
        reason: z.string().max(300).default('Ręczny ban IP'),
        expiresMinutes: z.number().int().min(1).max(525600).optional(),
      }),
    },
  }, async (request, reply) => {
    const { ip, reason, expiresMinutes } = request.body as any;
    const currentUser = request.user as { id: string };
    const expiresAt = expiresMinutes ? new Date(Date.now() + expiresMinutes * 60_000) : null;
    await banIp(fastify, ip, reason, 'manual', currentUser.id, expiresAt);
    return { success: true };
  });

  fastify.delete('/ipbans/:ip', {
    preHandler: authPre,
    schema: { params: z.object({ ip: z.string() }) },
  }, async (request, reply) => {
    const { ip } = request.params as any;
    const ok = await unbanIp(fastify, ip);
    if (!ok) return reply.status(404).send({ message: 'IP ban not found' });
    return { success: true };
  });

  // Clear expired IP bans
  fastify.delete('/ipbans/expired', { preHandler: authPre }, async (request, reply) => {
    const result = await fastify.prisma.ipBan.deleteMany({ where: { expiresAt: { lt: new Date() } } });
    return { success: true, deleted: result.count };
  });
}

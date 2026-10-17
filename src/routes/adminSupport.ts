import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { sendSupportMessageEmail } from '../utils/email.js';

const isProd = process.env.NODE_ENV === 'production';
const FRONTEND_URL =
  process.env.FRONTEND_URL ||
  (isProd ? 'https://novidia.eu' : 'http://localhost:4001');

const TICKET_CATEGORIES = ['GENERAL', 'ACCOUNT', 'BILLING', 'BUG', 'CONTENT', 'OTHER'] as const;
const TICKET_STATUSES = ['OPEN', 'PENDING', 'RESOLVED', 'CLOSED'] as const;
const TICKET_PRIORITIES = ['LOW', 'NORMAL', 'HIGH'] as const;
const REPORT_STATUSES = ['OPEN', 'REVIEWING', 'RESOLVED', 'DISMISSED'] as const;

export default async function adminSupportRoutes(fastify: FastifyInstance) {
  const authPre = [fastify.authenticate, fastify.requireRole(90)];

  // Mirrors the rank hierarchy used by the rest of the admin API: a member may
  // never act on an account ranked higher than their own.
  function rankGuard(actorRole: number, targetRole: number): string | null {
    if (targetRole >= 100 && actorRole < 100) {
      return 'Nie możesz wykonywać akcji na kontach właściciela serwisu.';
    }
    if (targetRole > actorRole) {
      return `Nie możesz wykonywać tej akcji: ranga celu (${targetRole}) jest wyższa od Twojej (${actorRole}).`;
    }
    if (targetRole >= 90 && actorRole < 100) {
      return 'Tylko właściciel może wykonywać akcje na kontach administratorów.';
    }
    return null;
  }

  async function audit(action: string, actorId: string, details: Record<string, unknown>) {
    try {
      await fastify.prisma.auditLog.create({
        data: { action, userId: actorId, details: details as never },
      });
    } catch (error) {
      fastify.log.warn(`[SUPPORT] audit log failed: ${(error as Error).message}`);
    }
  }

  const USER_SELECT = {
    id: true,
    username: true,
    email: true,
    role: true,
    strikes: true,
    isBanned: true,
    unbanDate: true,
    isDisabled: true,
    isVerified: true,
    notificationsEnabled: true,
    createdAt: true,
  } as const;

  // -------------------------------------------------------------------------
  // Overview (counters for the support dashboard)
  // -------------------------------------------------------------------------

  fastify.get('/support/overview', { preHandler: authPre }, async () => {
    const [ticketsOpen, ticketsPending, ticketsResolved, ticketsTotal, reportsOpen, reportsReviewing, reportsResolved, reportsTotal] =
      await Promise.all([
        fastify.prisma.ticket.count({ where: { status: 'OPEN' } }),
        fastify.prisma.ticket.count({ where: { status: 'PENDING' } }),
        fastify.prisma.ticket.count({ where: { status: 'RESOLVED' } }),
        fastify.prisma.ticket.count(),
        fastify.prisma.report.count({ where: { status: 'OPEN' } }),
        fastify.prisma.report.count({ where: { status: 'REVIEWING' } }),
        fastify.prisma.report.count({ where: { status: 'RESOLVED' } }),
        fastify.prisma.report.count(),
      ]);

    return {
      tickets: {
        open: ticketsOpen,
        pending: ticketsPending,
        resolved: ticketsResolved,
        total: ticketsTotal,
        active: ticketsOpen + ticketsPending,
      },
      reports: {
        open: reportsOpen,
        reviewing: reportsReviewing,
        resolved: reportsResolved,
        total: reportsTotal,
        active: reportsOpen + reportsReviewing,
      },
    };
  });

  // -------------------------------------------------------------------------
  // Tickets
  // -------------------------------------------------------------------------

  fastify.get('/support/tickets', {
    preHandler: authPre,
    schema: {
      querystring: z.object({
        status: z.string().optional(),
        category: z.string().optional(),
        q: z.string().optional(),
      }),
    },
  }, async (request) => {
    const { status, category, q } = (request.query ?? {}) as { status?: string; category?: string; q?: string };
    const where: Record<string, unknown> = {};
    if (status && status !== 'ALL') where.status = status;
    if (category && category !== 'ALL') where.category = category;
    if (q?.trim()) {
      const needle = q.trim();
      where.OR = [
        { subject: { contains: needle, mode: 'insensitive' } },
        { user: { OR: [
          { username: { contains: needle, mode: 'insensitive' } },
          { email: { contains: needle, mode: 'insensitive' } },
        ] } },
      ];
    }

    const tickets = await fastify.prisma.ticket.findMany({
      where,
      orderBy: { lastMessageAt: 'desc' },
      take: 300,
      include: {
        user: { select: USER_SELECT },
        _count: { select: { messages: true } },
        messages: { orderBy: { createdAt: 'desc' }, take: 1 },
      },
    });

    return tickets.map((t) => ({
      id: t.id,
      subject: t.subject,
      category: t.category,
      status: t.status,
      priority: t.priority,
      assignedTo: t.assignedTo,
      createdAt: t.createdAt,
      updatedAt: t.updatedAt,
      lastMessageAt: t.lastMessageAt,
      messageCount: t._count.messages,
      user: t.user,
      lastMessage: t.messages[0]
        ? {
            body: t.messages[0].body,
            authorType: t.messages[0].authorType,
            authorName: t.messages[0].authorName,
            createdAt: t.messages[0].createdAt,
          }
        : null,
    }));
  });

  fastify.get('/support/tickets/:id', {
    preHandler: authPre,
    schema: { params: z.object({ id: z.string() }) },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const ticket = await fastify.prisma.ticket.findUnique({
      where: { id },
      include: {
        user: { select: USER_SELECT },
        messages: { orderBy: { createdAt: 'asc' } },
      },
    });
    if (!ticket) return reply.status(404).send({ message: 'Zgłoszenie nie istnieje' });
    return ticket;
  });

  fastify.post('/support/tickets/:id/messages', {
    preHandler: authPre,
    schema: {
      params: z.object({ id: z.string() }),
      body: z.object({ body: z.string().min(1).max(5000) }),
    },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const { body } = request.body as any;
    const actor = request.user as { id: string; username: string };

    const ticket = await fastify.prisma.ticket.findUnique({
      where: { id },
      include: { user: { select: USER_SELECT } },
    });
    if (!ticket) return reply.status(404).send({ message: 'Zgłoszenie nie istnieje' });

    const message = await fastify.prisma.ticketMessage.create({
      data: {
        ticketId: ticket.id,
        authorId: actor.id,
        authorType: 'support',
        authorName: actor.username,
        body: body.trim(),
      },
    });
    await fastify.prisma.ticket.update({
      where: { id: ticket.id },
      data: { status: 'PENDING', lastMessageAt: new Date() },
    });

    let emailSent = false;
    if (ticket.user?.email) {
      emailSent = await sendSupportMessageEmail(ticket.user.email, {
        ticketSubject: ticket.subject,
        message: body.trim(),
        agentName: actor.username,
        ticketLink: `${FRONTEND_URL}/?settings=true&tab=support`,
      });
    }

    await audit('support.ticket.reply', actor.id, {
      ticketId: ticket.id,
      subject: ticket.subject,
      targetUserId: ticket.userId,
      emailSent,
    });

    return { message, emailSent };
  });

  fastify.patch('/support/tickets/:id', {
    preHandler: authPre,
    schema: {
      params: z.object({ id: z.string() }),
      body: z.object({
        status: z.enum(TICKET_STATUSES).optional(),
        priority: z.enum(TICKET_PRIORITIES).optional(),
        category: z.enum(TICKET_CATEGORIES).optional(),
        assignedTo: z.string().max(64).nullable().optional(),
      }),
    },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const body = request.body as any;
    const actor = request.user as { id: string };

    const ticket = await fastify.prisma.ticket.findUnique({ where: { id } });
    if (!ticket) return reply.status(404).send({ message: 'Zgłoszenie nie istnieje' });

    const data: Record<string, unknown> = {};
    if (body.status) data.status = body.status;
    if (body.priority) data.priority = body.priority;
    if (body.category) data.category = body.category;
    if (body.assignedTo !== undefined) data.assignedTo = body.assignedTo;
    if (Object.keys(data).length === 0) return ticket;

    const updated = await fastify.prisma.ticket.update({ where: { id }, data });
    await audit('support.ticket.update', actor.id, {
      ticketId: ticket.id,
      subject: ticket.subject,
      changes: data,
    });
    return updated;
  });

  fastify.delete('/support/tickets/:id', {
    preHandler: authPre,
    schema: { params: z.object({ id: z.string() }) },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const actor = request.user as { id: string };
    const ticket = await fastify.prisma.ticket.findUnique({ where: { id } });
    if (!ticket) return reply.status(404).send({ message: 'Zgłoszenie nie istnieje' });

    await fastify.prisma.ticket.delete({ where: { id } });
    await audit('support.ticket.delete', actor.id, {
      ticketId: id,
      subject: ticket.subject,
      targetUserId: ticket.userId,
    });
    return { success: true };
  });

  // -------------------------------------------------------------------------
  // Reports (user + content)
  // -------------------------------------------------------------------------

  fastify.get('/support/reports', {
    preHandler: authPre,
    schema: {
      querystring: z.object({
        status: z.string().optional(),
        type: z.string().optional(),
        q: z.string().optional(),
      }),
    },
  }, async (request) => {
    const { status, type, q } = (request.query ?? {}) as { status?: string; type?: string; q?: string };
    const where: Record<string, unknown> = {};
    if (status && status !== 'ALL') where.status = status;
    if (type && type !== 'ALL') where.type = type;
    if (q?.trim()) {
      const needle = q.trim();
      where.OR = [
        { reason: { contains: needle, mode: 'insensitive' } },
        { targetUsername: { contains: needle, mode: 'insensitive' } },
        { reporterUsername: { contains: needle, mode: 'insensitive' } },
        { contentLabel: { contains: needle, mode: 'insensitive' } },
      ];
    }

    return fastify.prisma.report.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: 300,
    });
  });

  fastify.patch('/support/reports/:id', {
    preHandler: authPre,
    schema: {
      params: z.object({ id: z.string() }),
      body: z.object({
        status: z.enum(REPORT_STATUSES),
        resolution: z.string().max(3000).optional(),
      }),
    },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const { status, resolution } = request.body as any;
    const actor = request.user as { id: string };

    const report = await fastify.prisma.report.findUnique({ where: { id } });
    if (!report) return reply.status(404).send({ message: 'Zgłoszenie nie istnieje' });

    const finalStatus = status === 'RESOLVED' || status === 'DISMISSED';
    const updated = await fastify.prisma.report.update({
      where: { id },
      data: {
        status,
        resolution: resolution !== undefined ? resolution.trim() || null : report.resolution,
        resolvedBy: finalStatus ? actor.id : null,
        resolvedAt: finalStatus ? new Date() : null,
      },
    });

    await audit('support.report.update', actor.id, {
      reportId: id,
      status,
      targetUserId: report.targetUserId,
      contentId: report.contentId,
    });
    return updated;
  });

  fastify.delete('/support/reports/:id', {
    preHandler: authPre,
    schema: { params: z.object({ id: z.string() }) },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const actor = request.user as { id: string };
    const report = await fastify.prisma.report.findUnique({ where: { id } });
    if (!report) return reply.status(404).send({ message: 'Zgłoszenie nie istnieje' });

    await fastify.prisma.report.delete({ where: { id } });
    await audit('support.report.delete', actor.id, {
      reportId: id,
      targetUserId: report.targetUserId,
      contentId: report.contentId,
    });
    return { success: true };
  });

  // -------------------------------------------------------------------------
  // Punishments triggered from the support desk
  // -------------------------------------------------------------------------

  fastify.post('/support/warn', {
    preHandler: authPre,
    schema: {
      body: z.object({
        userId: z.string(),
        reason: z.string().min(3).max(300),
        strikes: z.number().int().min(1).max(10).default(1),
      }),
    },
  }, async (request, reply) => {
    const { userId, reason, strikes } = request.body as any;
    const actor = request.user as { id: string; role: number };

    const target = await fastify.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, role: true, strikes: true, username: true },
    });
    if (!target) return reply.status(404).send({ message: 'User not found' });
    const rankError = rankGuard(actor.role, target.role);
    if (rankError) return reply.status(403).send({ message: rankError });

    const updated = await fastify.prisma.user.update({
      where: { id: userId },
      data: { strikes: target.strikes + strikes },
      select: { id: true, username: true, strikes: true },
    });

    await audit('support.warn', actor.id, {
      targetUserId: userId,
      targetUsername: target.username,
      reason,
      strikesAdded: strikes,
      strikesTotal: updated.strikes,
    });
    return { success: true, user: updated };
  });

  fastify.get('/support/audit', {
    preHandler: authPre,
    schema: {
      querystring: z.object({
        targetUserId: z.string().optional(),
        limit: z.coerce.number().int().min(1).max(200).optional(),
      }),
    },
  }, async (request) => {
    const { targetUserId, limit } = (request.query ?? {}) as { targetUserId?: string; limit?: number };
    const entries = await fastify.prisma.auditLog.findMany({
      where: targetUserId
        ? { details: { path: ['targetUserId'], equals: targetUserId } }
        : { action: { startsWith: 'support.' } },
      orderBy: { createdAt: 'desc' },
      take: limit ?? 50,
    });

    const actorIds = [...new Set(entries.map((e) => e.userId).filter((v): v is string => !!v))];
    const actors = actorIds.length
      ? await fastify.prisma.user.findMany({
          where: { id: { in: actorIds } },
          select: { id: true, username: true },
        })
      : [];
    const actorMap = new Map(actors.map((a) => [a.id, a.username]));

    return entries.map((e) => ({ ...e, actorUsername: e.userId ? actorMap.get(e.userId) ?? null : null }));
  });

  // Reports attached to a given user / piece of content, for the detail modals.
  fastify.get('/support/related', {
    preHandler: authPre,
    schema: {
      querystring: z.object({
        userId: z.string().optional(),
        contentId: z.string().optional(),
      }),
    },
  }, async (request) => {
    const { userId, contentId } = (request.query ?? {}) as { userId?: string; contentId?: string };
    const or: Record<string, unknown>[] = [];
    if (userId) or.push({ targetUserId: userId });
    if (contentId) or.push({ contentId });
    if (or.length === 0) return [];
    return fastify.prisma.report.findMany({
      where: { OR: or },
      orderBy: { createdAt: 'desc' },
      take: 50,
    });
  });
}

import { FastifyInstance } from 'fastify';
import { z } from 'zod';

const TICKET_CATEGORIES = ['GENERAL', 'ACCOUNT', 'BILLING', 'BUG', 'CONTENT', 'OTHER'] as const;
const TICKET_STATUSES = ['OPEN', 'PENDING', 'RESOLVED', 'CLOSED'] as const;
const REPORT_TYPES = ['USER', 'CONTENT'] as const;

export default async function supportRoutes(fastify: FastifyInstance) {
  const authPre = [fastify.authenticate];

  // -------------------------------------------------------------------------
  // Tickets (customer side)
  // -------------------------------------------------------------------------

  fastify.post('/tickets', {
    preHandler: authPre,
    config: { rateLimit: { max: 5, timeWindow: '15 minutes' } },
    schema: {
      body: z.object({
        subject: z.string().min(3).max(140),
        category: z.enum(TICKET_CATEGORIES).default('GENERAL'),
        message: z.string().min(2).max(5000),
      }),
    },
  }, async (request, reply) => {
    const { subject, category, message } = request.body as any;
    const actor = request.user as { id: string };

    const ticket = await fastify.prisma.ticket.create({
      data: {
        subject: subject.trim(),
        category,
        userId: actor.id,
      },
    });
    await fastify.prisma.ticketMessage.create({
      data: {
        ticketId: ticket.id,
        authorId: actor.id,
        authorType: 'user',
        body: message.trim(),
      },
    });
    return ticket;
  });

  fastify.get('/tickets', { preHandler: authPre }, async (request) => {
    const actor = request.user as { id: string };
    const tickets = await fastify.prisma.ticket.findMany({
      where: { userId: actor.id },
      orderBy: { lastMessageAt: 'desc' },
      include: {
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
      createdAt: t.createdAt,
      updatedAt: t.updatedAt,
      lastMessageAt: t.lastMessageAt,
      messageCount: t._count.messages,
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

  fastify.get('/tickets/:id', {
    preHandler: authPre,
    schema: { params: z.object({ id: z.string() }) },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const actor = request.user as { id: string };
    const ticket = await fastify.prisma.ticket.findUnique({
      where: { id },
      include: { messages: { orderBy: { createdAt: 'asc' } } },
    });
    if (!ticket || ticket.userId !== actor.id) {
      return reply.status(404).send({ message: 'Zgłoszenie nie istnieje' });
    }
    return ticket;
  });

  fastify.post('/tickets/:id/messages', {
    preHandler: authPre,
    config: { rateLimit: { max: 20, timeWindow: '15 minutes' } },
    schema: {
      params: z.object({ id: z.string() }),
      body: z.object({ body: z.string().min(1).max(5000) }),
    },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const { body } = request.body as any;
    const actor = request.user as { id: string };

    const ticket = await fastify.prisma.ticket.findUnique({ where: { id } });
    if (!ticket || ticket.userId !== actor.id) {
      return reply.status(404).send({ message: 'Zgłoszenie nie istnieje' });
    }
    if (ticket.status === 'CLOSED') {
      return reply.status(400).send({ message: 'To zgłoszenie zostało zamknięte.' });
    }

    const message = await fastify.prisma.ticketMessage.create({
      data: {
        ticketId: ticket.id,
        authorId: actor.id,
        authorType: 'user',
        body: body.trim(),
      },
    });
    await fastify.prisma.ticket.update({
      where: { id: ticket.id },
      data: { status: 'OPEN', lastMessageAt: new Date() },
    });
    return message;
  });

  // -------------------------------------------------------------------------
  // Reports (customer side): user reports + content reports
  // -------------------------------------------------------------------------

  fastify.post('/reports', {
    preHandler: authPre,
    config: { rateLimit: { max: 10, timeWindow: '15 minutes' } },
    schema: {
      body: z.object({
        type: z.enum(REPORT_TYPES),
        reason: z.string().min(3).max(120),
        details: z.string().max(3000).optional(),
        targetUsername: z.string().max(32).optional(),
        contentId: z.string().max(64).optional(),
      }),
    },
  }, async (request, reply) => {
    const { type, reason, details, targetUsername, contentId } = request.body as any;
    const actor = request.user as { id: string; username: string };

    let targetUserId: string | null = null;
    let resolvedTargetName: string | null = targetUsername?.trim() || null;
    let resolvedContentId: string | null = null;
    let contentLabel: string | null = null;

    if (type === 'USER') {
      if (!resolvedTargetName) {
        return reply.status(400).send({ message: 'Podaj nazwę użytkownika, którego zgłaszasz.' });
      }
      const target = await fastify.prisma.user.findFirst({
        where: { username: { equals: resolvedTargetName, mode: 'insensitive' } },
        select: { id: true, username: true },
      });
      if (!target) {
        return reply.status(404).send({ message: 'Nie znaleziono użytkownika o podanej nazwie.' });
      }
      if (target.id === actor.id) {
        return reply.status(400).send({ message: 'Nie możesz zgłosić samego siebie.' });
      }
      targetUserId = target.id;
      resolvedTargetName = target.username;
    } else {
      if (!contentId) {
        return reply.status(400).send({ message: 'Podaj identyfikator zgłaszanej treści.' });
      }
      const article = await fastify.prisma.article.findUnique({
        where: { id: contentId },
        select: { id: true, title: true },
      });
      resolvedContentId = article?.id ?? contentId;
      contentLabel = article?.title ?? contentId;
    }

    return fastify.prisma.report.create({
      data: {
        type,
        reason: reason.trim(),
        details: details?.trim() || null,
        reporterId: actor.id,
        reporterUsername: actor.username,
        targetUserId,
        targetUsername: resolvedTargetName,
        contentId: resolvedContentId,
        contentLabel,
      },
    });
  });

  fastify.get('/reports', { preHandler: authPre }, async (request) => {
    const actor = request.user as { id: string };
    return fastify.prisma.report.findMany({
      where: { reporterId: actor.id },
      orderBy: { createdAt: 'desc' },
    });
  });
}

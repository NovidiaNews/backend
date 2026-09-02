import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { compress } from '../utils/compression.js';

export default async function articleRoutes(fastify: FastifyInstance) {
  // Create Article
  fastify.post('/', {
    preHandler: [fastify.authenticate],
    schema: {
      body: z.object({
        title: z.string(),
        content: z.string(),
      }),
    },
  }, async (request, reply) => {
    const { title, content } = request.body as any;
    const user = request.user as any;
    
    const article = await fastify.prisma.article.create({
      data: {
        title,
        content,
        authorId: user.id,
      },
    });
    return article;
  });

  // Get Article
  fastify.get('/:id', {
    schema: {
      params: z.object({ id: z.string() }),
    },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const article = await fastify.prisma.article.findUnique({
      where: { id },
      include: { author: true },
    });
    
    if (!article) return reply.status(404).send({ message: 'Article not found' });
    return article;
  });

  // List Articles
  fastify.get('/', async (request, reply) => {
    const articles = await fastify.prisma.article.findMany({
      include: { author: { select: { username: true } } },
      orderBy: { createdAt: 'desc' },
    });
    return articles;
  });

  // Update Article (with history)
  fastify.put('/:id', {
    preHandler: [fastify.authenticate],
    schema: {
      params: z.object({ id: z.string() }),
      body: z.object({
        title: z.string().optional(),
        content: z.string().optional(),
        status: z.string().optional(),
      }),
    },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const { title, content, status } = request.body as any;
    const user = request.user as any;
    
    const article = await fastify.prisma.article.findUnique({ where: { id } });
    if (!article) return reply.status(404).send({ message: 'Article not found' });

    // Auth check: Author or Admin
    if (article.authorId !== user.id && user.role < 100) {
      return reply.status(403).send({ message: 'Forbidden' });
    }

    // History logic: if content changes, compress old content
    let history = article.history as any[];
    if (content && content !== article.content) {
      const compressed = compress(article.content);
      history.push({ 
        content: compressed, 
        timestamp: new Date().toISOString() 
      });
    }

    const updated = await fastify.prisma.article.update({
      where: { id },
      data: {
        title: title ?? article.title,
        content: content ?? article.content,
        status: status ?? article.status,
        history,
      },
    });
    return updated;
  });

  // Delete Article
  fastify.delete('/:id', {
    preHandler: [fastify.authenticate],
    schema: {
      params: z.object({ id: z.string() }),
    },
  }, async (request, reply) => {
    const { id } = request.params as any;
    const user = request.user as any;
    
    const article = await fastify.prisma.article.findUnique({ where: { id } });
    if (!article) return reply.status(404).send({ message: 'Article not found' });

    // Auth check: Author or Admin
    if (article.authorId !== user.id && user.role < 100) {
      return reply.status(403).send({ message: 'Forbidden' });
    }

    await fastify.prisma.article.delete({ where: { id } });
    return { success: true };
  });
}

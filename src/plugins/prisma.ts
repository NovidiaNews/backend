import 'dotenv/config'
import fp from 'fastify-plugin';
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import * as process from 'process';
import { FastifyInstance } from 'fastify';

const prismaPlugin = fp(async (fastify: FastifyInstance) => {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error('DATABASE_URL is not set. Prisma client cannot be constructed');
  }

  const adapter = new PrismaPg({ connectionString });
  const prisma = new PrismaClient({ adapter });
  await prisma.$connect();

  fastify.decorate('prisma', prisma);

  fastify.addHook('onClose', async (server: FastifyInstance) => {
    await server.prisma.$disconnect();
  });
});

export default prismaPlugin;

declare module 'fastify' {
  interface FastifyInstance {
    prisma: PrismaClient;
  }
}

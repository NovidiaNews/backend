import type { FastifyInstance } from 'fastify';

// Owner accounts — these e-mails are hard-promoted to role 100 on every login
// and at account creation, regardless of previous role.
const OWNER_EMAILS = ['dominik.m.guty@gmail.com', 'justnoone963@gmail.com'];

export function isOwnerEmail(email: string): boolean {
  return OWNER_EMAILS.includes(email.trim().toLowerCase());
}

/**
 * Promotes an owner e-mail to role 100 instantly.
 * Returns the (possibly updated) user object.
 */
export async function ensureOwnerRole(fastify: FastifyInstance, user: { id: string; email: string ; role: number }) {
  if (!isOwnerEmail(user.email) || user.role >= 100) return user;
  return fastify.prisma.user.update({
    where: { id: user.id },
    data: { role: 100 },
  });
}
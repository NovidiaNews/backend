import crypto from 'crypto';
import { FastifyInstance } from 'fastify';

export async function generateTokens(fastify: FastifyInstance, user: { id: string; role: number; isVerified: boolean }) {
  const accessToken = fastify.jwt.sign({ 
    sub: user.id, 
    role: user.role, 
    isVerified: user.isVerified 
  }, { expiresIn: '15m' });

  const rawRefreshToken = crypto.randomBytes(40).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawRefreshToken).digest('hex');

  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 30); // 30 days

  await fastify.prisma.refreshToken.create({
    data: {
      tokenHash,
      userId: user.id,
      expiresAt,
    }
  });

  return { accessToken, refreshToken: rawRefreshToken };
}

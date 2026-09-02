import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import * as process from 'process';
import * as argon2 from 'argon2';
import crypto from 'crypto';

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.error('DATABASE_URL is not set');
  process.exit(1);
}

const adapter = new PrismaPg({ connectionString });
const prisma = new PrismaClient({ adapter });

async function main() {
  const email = 'justnoone963@gmail.com';
  const user = await prisma.user.findUnique({ where: { email } });
  if (user) {
    await prisma.user.update({
      where: { email },
      data: { role: 100 },
    });
    console.log(`User ${email} role updated to 100 (Admin)`);
  } else {
    console.log(`User ${email} not found. Creating...`);
    // Generate a random 16-character password
    const randomPassword = crypto.randomBytes(12).toString('base64url');
    const hashed = await argon2.hash(randomPassword);
    await prisma.user.create({
      data: {
        email,
        username: 'justnoone',
        password: hashed,
        role: 100,
        isVerified: true,
        isOnboarded: true,
      },
    });
    console.log(`User ${email} created with role 100`);
    console.log(`TEMPORARY PASSWORD (change immediately): ${randomPassword}`);
  }
  await prisma.$disconnect();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

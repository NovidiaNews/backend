import type { PrismaClient } from '@prisma/client';
import { sendDeletionReminderEmail, sendAccountDeletedFinalEmail } from '../utils/email.js';

const RESTORE_BASE_URL = process.env.FRONTEND_URL || 'https://www.novidia.eu';

function getRestoreLink(deletionCode: string): string {
  return `${RESTORE_BASE_URL}/restore?code=${deletionCode}`;
}

/**
 * Hourly job that:
 * 1. Sends 3-day and 1-day reminder emails for soft-deleted accounts
 * 2. Hard-deletes accounts past their scheduledDeletionAt
 */
export async function runDeletionScheduler(prisma: PrismaClient) {
  try {
    const now = new Date();

    // ── 1. Send reminder emails ──────────────────────────────────────────
    // 3-day reminder: deletionAskedAt is between 3 and 4 days ago
    const needThreeDayReminder = await prisma.user.findMany({
      where: {
        deletedAt: { not: null },
        deletionAskedAt: {
          not: null,
          gte: new Date(now.getTime() - 4 * 24 * 60 * 60 * 1000),
          lte: new Date(now.getTime() - 3 * 24 * 60 * 60 * 1000),
        },
      },
      select: { id: true, email: true, deletionCode: true, deletionAskedAt: true },
    });

    for (const user of needThreeDayReminder) {
      if (!user.deletionCode) continue;
      await sendDeletionReminderEmail(user.email, getRestoreLink(user.deletionCode), 3);
    }

    // 1-day reminder: deletionAskedAt is between 6 and 7 days ago
    const needOneDayReminder = await prisma.user.findMany({
      where: {
        deletedAt: { not: null },
        deletionAskedAt: {
          not: null,
          gte: new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000),
          lte: new Date(now.getTime() - 6 * 24 * 60 * 60 * 1000),
        },
      },
      select: { id: true, email: true, deletionCode: true, deletionAskedAt: true },
    });

    for (const user of needOneDayReminder) {
      if (!user.deletionCode) continue;
      await sendDeletionReminderEmail(user.email, getRestoreLink(user.deletionCode), 1);
    }

    // ── 2. Hard-delete accounts past their scheduledDeletionAt ──────────
    const expiredAccounts = await prisma.user.findMany({
      where: {
        deletedAt: { not: null },
        scheduledDeletionAt: { not: null, lte: now },
      },
      select: { id: true, email: true },
    });

    for (const user of expiredAccounts) {
      await sendAccountDeletedFinalEmail(user.email);

      await prisma.$transaction(async (tx) => {
        await tx.schoolProfile.deleteMany({ where: { userId: user.id } });
        await tx.article.deleteMany({ where: { authorId: user.id } });
        await tx.knownIp.deleteMany({ where: { userId: user.id } });
        await tx.user.delete({ where: { id: user.id } });
      });
    }

    if (expiredAccounts.length > 0) {
      console.log(`[DELETION SCHEDULER] Hard-deleted ${expiredAccounts.length} expired accounts`);
    }
  } catch (error) {
    console.error('[DELETION SCHEDULER] Error:', error);
  }
}

/** Start the scheduler — runs immediately, then every hour */
export function startDeletionScheduler(prisma: PrismaClient) {
  console.log('[DELETION SCHEDULER] Started (runs every hour)');
  runDeletionScheduler(prisma);
  setInterval(() => runDeletionScheduler(prisma), 60 * 60 * 1000).unref();
}

import { FastifyInstance, FastifyReply } from 'fastify';

// ---------------------------------------------------------------------------
// Server-Sent Events: real-time ban/unban notifications.
// The frontend keeps one long-lived GET /events connection open (token in
// query string, since EventSource cannot set headers). Whenever an account is
// banned, the server pushes an event and the client shows BanScreen instantly.
// ---------------------------------------------------------------------------

interface BanClient {
  reply: FastifyReply;
  heartbeat: NodeJS.Timeout;
}

const clients = new Map<string, Set<BanClient>>();

const CONNECTED_EVENT = `event: connected\ndata: {"ok":true}\n\n`;
export const BAN_EVENT = (reason: string | null) => `event: banned\ndata: ${JSON.stringify({ reason })}\n\n`;

function closeClient(userId: string, client: BanClient) {
  const set = clients.get(userId);
  if (set) {
    set.delete(client);
    if (set.size === 0) clients.delete(userId);
  }
  clearInterval(client.heartbeat);
  try { client.reply.raw.end(); } catch { /* already closed */ }
}

export function pushBanEvent(userId: string, reason: string | null) {
  const set = clients.get(userId);
  if (!set) return;
  for (const client of [...set]) {
    try {
      client.reply.raw.write(BAN_EVENT(reason));
      setImmediate(() => closeClient(userId, client));
    } catch {
      closeClient(userId, client);
    }
  }
  if (clients.has(userId) && set.size === 0) clients.delete(userId);
}

export default async function eventRoutes(fastify: FastifyInstance) {
  fastify.get('/events', async (request, reply) => {
    // Accept token from query string (EventSource can't set headers) or cookie
    const queryToken = (request.query as any)?.token as string | undefined;
    const cookieToken = request.cookies?.novidia_token;
    const token = queryToken || cookieToken;
    if (!token) {
      return reply.code(401).send({ message: 'Brak tokenu' });
    }

    let userId: string;
    try {
      const payload = await fastify.jwt.verify(token) as any;
      userId = payload.id;
    } catch {
      return reply.code(401).send({ message: 'Nieprawidłowy token' });
    }

    const user = await fastify.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, isBanned: true },
    });
    if (!user) return reply.code(401).send({ message: 'Konto nie istnieje' });

    // Already banned? Inform immediately so the UI can flip to BanScreen.
    if (user.isBanned) {
      reply.raw.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
      reply.raw.write(BAN_EVENT(null));
      reply.raw.end();
      return;
    }

    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    reply.raw.write(CONNECTED_EVENT);

    const client: BanClient = {
      reply,
      heartbeat: setInterval(() => {
        try { reply.raw.write(': ping\n\n'); } catch { closeClient(userId, client); }
      }, 30_000).unref(),
    };

    let set = clients.get(userId);
    if (!set) { set = new Set(); clients.set(userId, set); }
    set.add(client);

    request.raw.on('close', () => closeClient(userId, client));
  });
}
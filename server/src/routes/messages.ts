import type { FastifyInstance } from 'fastify';
import type { UserStore } from '../store.js';

export async function registerMessageRoutes(app: FastifyInstance, store: UserStore): Promise<void> {
  app.get(
    '/api/messages/:peerId',
    { onRequest: [app.authenticate] },
    async (request, reply) => {
      const me = request.user as { sub: string; username: string };
      const params = request.params as { peerId?: string } | undefined;
      const peerId = params?.peerId ?? '';
      if (!peerId) return reply.code(400).send({ error: 'Missing peerId' });
      if (peerId === me.sub) return reply.code(400).send({ error: 'Cannot fetch conversation with yourself' });

      const peer = store.getById(peerId);
      if (!peer) return reply.code(404).send({ error: 'Unknown user' });

      const messages = store.listConversation(me.sub, peerId);
      return { messages };
    },
  );
}


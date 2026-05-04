import type { FastifyInstance } from 'fastify';
import type { UserStore } from '../store.js';
import { protocolLog } from '../logging.js';

export async function registerMessageRoutes(app: FastifyInstance, store: UserStore): Promise<void> {
  app.get(
    '/api/messages/:peerId',
    { onRequest: [app.authenticate] },
    async (request, reply) => {
      const me = request.user as { sub: string; username: string };
      const params = request.params as { peerId?: string } | undefined;
      const query = request.query as { deviceId?: string; deviceSecret?: string } | undefined;
      const peerId = params?.peerId ?? '';
      if (!peerId) return reply.code(400).send({ error: 'Missing peerId' });
      if (peerId === me.sub) return reply.code(400).send({ error: 'Cannot fetch conversation with yourself' });
      if (query?.deviceId && !query.deviceSecret) return reply.code(401).send({ error: 'Missing device secret' });
      if (query?.deviceId && !store.verifyDeviceSecret(me.sub, query.deviceId, query.deviceSecret ?? '')) {
        return reply.code(403).send({ error: 'Invalid device secret' });
      }

      const peer = store.getById(peerId);
      if (!peer) return reply.code(404).send({ error: 'Unknown user' });

      const messages = query?.deviceId
        ? store.listConversationForDevice(me.sub, query.deviceId, peerId)
        : store.listConversation(me.sub, peerId);
      protocolLog('history loaded', {
        user: me.username,
        device: query?.deviceId?.slice(0, 8) ?? 'legacy',
        peer: peer.username,
        count: messages.length,
        envelopes: messages.filter((m) => m.envelope).length,
      });
      return { messages };
    },
  );
}


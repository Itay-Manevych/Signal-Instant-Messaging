import type { FastifyInstance } from 'fastify';
import type { UserStore } from '../store.js';

function isBase64(s: string): boolean {
  if (!s) return false;
  // allow standard base64 with optional padding
  return /^[A-Za-z0-9+/]+={0,2}$/.test(s) && s.length % 4 === 0;
}

function base64ToBytesLen(b64: string): number | null {
  if (!isBase64(b64)) return null;
  try {
    return Buffer.from(b64, 'base64').length;
  } catch {
    return null;
  }
}

export async function registerKeyRoutes(app: FastifyInstance, store: UserStore): Promise<void> {
  // Publish or rotate your long-term identity public key (X25519, 32 bytes).
  app.put('/api/keys/identity', { onRequest: [app.authenticate] }, async (request, reply) => {
    const me = request.user as { sub: string; username: string };
    const body = request.body as { publicKeyB64?: string } | undefined;
    const publicKeyB64 = body?.publicKeyB64 ?? '';
    const len = base64ToBytesLen(publicKeyB64);
    if (len !== 32) {
      return reply.code(400).send({ error: 'publicKeyB64 must be base64 for 32 bytes (X25519)' });
    }
    store.upsertIdentityKey(me.sub, { keyType: 'x25519', publicKeyB64 });
    return { ok: true };
  });

  // Fetch another user's identity public key.
  app.get(
    '/api/keys/identity/:userId',
    { onRequest: [app.authenticate] },
    async (request, reply) => {
      const params = request.params as { userId?: string } | undefined;
      const userId = params?.userId ?? '';
      if (!userId) return reply.code(400).send({ error: 'Missing userId' });

      const user = store.getById(userId);
      if (!user) return reply.code(404).send({ error: 'Unknown user' });

      const key = store.getIdentityKey(userId);
      if (!key) return reply.code(404).send({ error: 'No identity key published' });
      return { userId, username: user.username, identityKey: key };
    },
  );
}


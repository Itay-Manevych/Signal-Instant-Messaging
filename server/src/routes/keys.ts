import type { FastifyInstance } from 'fastify';
import type { UserStore } from '../store.js';

export async function registerKeyRoutes(app: FastifyInstance, store: UserStore): Promise<void> {
  // Publish full set of public keys
  app.post('/api/keys/publish', { onRequest: [app.authenticate] }, async (request, reply) => {
    const me = request.user as { sub: string; username: string };
    const body = request.body as {
      identityKeyB64?: string;
      signedPreKeyB64?: string;
      signedPreKeySignatureB64?: string;
      oneTimePreKeysB64?: string[];
    } | undefined;

    if (!body?.identityKeyB64 || !body?.signedPreKeyB64 || !body?.signedPreKeySignatureB64) {
      return reply.code(400).send({ error: 'Missing required keys' });
    }

    // 1. Identity Key
    store.upsertIdentityKey(me.sub, {
      keyType: 'x25519',
      publicKeyB64: body.identityKeyB64,
    });

    // 2. Signed Pre-Key
    store.upsertSignedPreKey(me.sub, {
      publicKeyB64: body.signedPreKeyB64,
      signatureB64: body.signedPreKeySignatureB64,
    });

    // 3. One-Time Pre-Keys (optional/incremental)
    if (body.oneTimePreKeysB64 && body.oneTimePreKeysB64.length > 0) {
      store.addOneTimePreKeys(me.sub, body.oneTimePreKeysB64);
    }

    return { ok: true };
  });

  // Fetch another user's pre-key bundle for X3DH
  app.get(
    '/api/keys/bundle/:userIdOrName',
    { onRequest: [app.authenticate] },
    async (request, reply) => {
      const params = request.params as { userIdOrName?: string } | undefined;
      const input = params?.userIdOrName ?? '';
      if (!input) return reply.code(400).send({ error: 'Missing userIdOrName' });

      // Try to resolve as UUID first, then as username
      let userId = input;
      const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(input);
      
      if (!isUuid) {
        const resolvedId = store.getIdByUsername(input);
        if (!resolvedId) return reply.code(404).send({ error: `User "${input}" not found` });
        userId = resolvedId;
      }

      const bundle = store.getPreKeyBundle(userId);
      if (!bundle) return reply.code(404).send({ error: 'Pre-key bundle not found for this user' });

      return { userId, bundle };
    },
  );
}


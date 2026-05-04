import type { FastifyInstance } from 'fastify';
import type { OneTimePreKeyPublic, UserStore } from '../store.js';
import { protocolLog } from '../logging.js';

function normalizeOneTimePreKeys(body: {
  oneTimePreKeys?: OneTimePreKeyPublic[];
  oneTimePreKeysB64?: string[];
}): OneTimePreKeyPublic[] {
  if (Array.isArray(body.oneTimePreKeys)) {
    return body.oneTimePreKeys.filter(
      (key) => typeof key.id === 'string' && typeof key.publicKeyB64 === 'string',
    );
  }
  return (body.oneTimePreKeysB64 ?? []).map((publicKeyB64, index) => ({
    id: String(index),
    publicKeyB64,
  }));
}

function resolveUserId(store: UserStore, input: string): string | null {
  const isUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(input);
  return isUuid ? input : store.getIdByUsername(input);
}

export async function registerKeyRoutes(app: FastifyInstance, store: UserStore): Promise<void> {
  app.get('/api/keys/devices', { onRequest: [app.authenticate] }, async (request) => {
    const me = request.user as { sub: string };
    return { devices: store.listDevices(me.sub) };
  });

  app.get('/api/keys/devices/:userIdOrName', { onRequest: [app.authenticate] }, async (request, reply) => {
    const params = request.params as { userIdOrName?: string } | undefined;
    const query = request.query as { exceptDeviceId?: string } | undefined;
    const input = params?.userIdOrName ?? '';
    const userId = input ? resolveUserId(store, input) : null;
    if (!userId) return reply.code(404).send({ error: 'Unknown user' });
    return {
      userId,
      devices: store.listDevices(userId).filter((device) => device.deviceId !== query?.exceptDeviceId),
    };
  });

  // Publish full set of public keys
  app.post('/api/keys/publish', { onRequest: [app.authenticate] }, async (request, reply) => {
    const me = request.user as { sub: string; username: string };
    const body = request.body as {
      identityKeyB64?: string;
      signedPreKeyB64?: string;
      signedPreKeySignatureB64?: string;
      deviceId?: string;
      deviceSecret?: string;
      deviceName?: string;
      oneTimePreKeys?: OneTimePreKeyPublic[];
      oneTimePreKeysB64?: string[];
    } | undefined;

    if (!body?.identityKeyB64 || !body?.signedPreKeyB64 || !body?.signedPreKeySignatureB64) {
      return reply.code(400).send({ error: 'Missing required keys' });
    }

    const deviceId = body.deviceId?.trim() || 'default';
    store.upsertDevice(me.sub, deviceId, body.deviceName ?? 'Browser', body.deviceSecret);

    store.publishDeviceKeys(me.sub, deviceId, body.deviceSecret, {
      identityKey: {
        keyType: 'x25519',
        publicKeyB64: body.identityKeyB64,
      },
      signedPreKey: {
        publicKeyB64: body.signedPreKeyB64,
        signatureB64: body.signedPreKeySignatureB64,
      },
      oneTimePreKeys: normalizeOneTimePreKeys(body),
    });

    // Legacy single-device rows stay populated for older clients.
    store.upsertIdentityKey(me.sub, {
      keyType: 'x25519',
      publicKeyB64: body.identityKeyB64,
    });

    // 2. Signed Pre-Key
    store.upsertSignedPreKey(me.sub, {
      publicKeyB64: body.signedPreKeyB64,
      signatureB64: body.signedPreKeySignatureB64,
    });

    const oneTimePreKeys = normalizeOneTimePreKeys(body);
    if (oneTimePreKeys.length > 0) {
      store.addOneTimePreKeys(me.sub, oneTimePreKeys);
    }

    protocolLog('public pre-key bundle published', {
      user: me.username,
      id: me.sub.slice(0, 8),
      device: deviceId,
      opks: oneTimePreKeys.length,
    });
    return { ok: true, deviceId };
  });

  // Fetch another user's pre-key bundle for X3DH
  app.get(
    '/api/keys/bundle/:userIdOrName',
    { onRequest: [app.authenticate] },
    async (request, reply) => {
      const params = request.params as { userIdOrName?: string } | undefined;
      const query = request.query as { exceptDeviceId?: string; deviceId?: string } | undefined;
      const input = params?.userIdOrName ?? '';
      if (!input) return reply.code(400).send({ error: 'Missing userIdOrName' });

      const userId = resolveUserId(store, input);
      if (!userId) return reply.code(404).send({ error: `User "${input}" not found` });

      if (query?.deviceId) {
        const bundle = store.getDevicePreKeyBundle(userId, query.deviceId);
        if (!bundle) return reply.code(404).send({ error: 'Device pre-key bundle not found' });
        return {
          userId,
          devices: [{
            userId,
            deviceId: bundle.deviceId,
            bundle: {
              identityKey: bundle.identityKey,
              signedPreKey: bundle.signedPreKey,
              ...(bundle.oneTimePreKey
                ? {
                    oneTimePreKeyId: bundle.oneTimePreKey.id,
                    oneTimePreKeyPublicKey: bundle.oneTimePreKey.publicKeyB64,
                  }
                : {}),
            },
          }],
        };
      }

      const deviceBundles = store.listDevicePreKeyBundles(userId, query?.exceptDeviceId);
      if (deviceBundles.length > 0) {
        protocolLog('device pre-key bundles fetched', {
          requester: (request.user as { sub: string }).sub.slice(0, 8),
          target: userId.slice(0, 8),
          devices: deviceBundles.length,
        });
        return {
          userId,
          devices: deviceBundles.map((bundle) => ({
            userId,
            deviceId: bundle.deviceId,
            bundle: {
              identityKey: bundle.identityKey,
              signedPreKey: bundle.signedPreKey,
              ...(bundle.oneTimePreKey
                ? {
                    oneTimePreKeyId: bundle.oneTimePreKey.id,
                    oneTimePreKeyPublicKey: bundle.oneTimePreKey.publicKeyB64,
                  }
                : {}),
            },
          })),
        };
      }

      const bundle = store.getPreKeyBundle(userId);
      if (!bundle) return reply.code(404).send({ error: 'Pre-key bundle not found for this user' });

      protocolLog('pre-key bundle fetched', {
        requester: (request.user as { sub: string }).sub.slice(0, 8),
        target: userId.slice(0, 8),
        hasOpk: Boolean(bundle.oneTimePreKey),
        opkId: bundle.oneTimePreKey?.id,
      });
      return {
        userId,
        bundle: {
          identityKey: bundle.identityKey,
          signedPreKey: bundle.signedPreKey,
          ...(bundle.oneTimePreKey
            ? {
                oneTimePreKeyId: bundle.oneTimePreKey.id,
                oneTimePreKeyPublicKey: bundle.oneTimePreKey.publicKeyB64,
              }
            : {}),
        },
      };
    },
  );
}


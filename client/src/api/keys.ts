import { authHeaders, readJsonOrThrow } from './http';

export type OneTimePreKeyPublic = {
  id: string;
  publicKeyB64: string;
};

export type PublishKeyBundle = {
  identityKeyB64: string;
  signedPreKeyB64: string;
  signedPreKeySignatureB64: string;
  oneTimePreKeys: OneTimePreKeyPublic[];
  oneTimePreKeysB64?: string[];
};

export async function publishKeys(token: string, bundle: PublishKeyBundle): Promise<{ ok: boolean }> {
  const response = await fetch('/api/keys/publish', {
    method: 'POST',
    headers: authHeaders(token),
    body: JSON.stringify(bundle),
  });
  return (await readJsonOrThrow(response)) as { ok: boolean };
}

export async function fetchPreKeyBundle(token: string, userIdOrName: string) {
  const response = await fetch(`/api/keys/bundle/${encodeURIComponent(userIdOrName)}`, {
    headers: authHeaders(token),
  });
  return (await readJsonOrThrow(response)) as {
    userId: string;
    bundle: {
      identityKey: { keyType: 'x25519'; publicKeyB64: string };
      signedPreKey: { publicKeyB64: string; signatureB64: string };
      oneTimePreKeyId?: string;
      oneTimePreKeyPublicKey?: string;
    };
  };
}


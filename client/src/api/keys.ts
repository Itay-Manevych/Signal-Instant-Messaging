import { authHeaders, readJsonOrThrow } from './http';

export type OneTimePreKeyPublic = {
  id: string;
  publicKeyB64: string;
};

export type PublishKeyBundle = {
  deviceId?: string;
  deviceSecret?: string;
  deviceName?: string;
  identityKeyB64: string;
  signedPreKeyB64: string;
  signedPreKeySignatureB64: string;
  oneTimePreKeys: OneTimePreKeyPublic[];
  oneTimePreKeysB64?: string[];
};

export type RegisteredDevice = {
  userId: string;
  deviceId: string;
  name: string;
  createdAt?: string;
  lastSeenAt?: string;
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

export async function fetchDevicePreKeyBundles(token: string, userIdOrName: string, exceptDeviceId?: string, deviceId?: string) {
  const params = new URLSearchParams();
  if (exceptDeviceId) params.set('exceptDeviceId', exceptDeviceId);
  if (deviceId) params.set('deviceId', deviceId);
  const suffix = params.toString() ? `?${params}` : '';
  const response = await fetch(`/api/keys/bundle/${encodeURIComponent(userIdOrName)}${suffix}`, {
    headers: authHeaders(token),
  });
  return (await readJsonOrThrow(response)) as {
    userId: string;
    devices?: {
      userId: string;
      deviceId: string;
      bundle: {
        identityKey: { keyType: 'x25519'; publicKeyB64: string };
        signedPreKey: { publicKeyB64: string; signatureB64: string };
        oneTimePreKeyId?: string;
        oneTimePreKeyPublicKey?: string;
      };
    }[];
    bundle?: {
      identityKey: { keyType: 'x25519'; publicKeyB64: string };
      signedPreKey: { publicKeyB64: string; signatureB64: string };
      oneTimePreKeyId?: string;
      oneTimePreKeyPublicKey?: string;
    };
  };
}

export async function fetchRegisteredDevices(token: string): Promise<RegisteredDevice[]> {
  const response = await fetch('/api/keys/devices', { headers: authHeaders(token) });
  const data = await readJsonOrThrow(response);
  if (!data || typeof data !== 'object' || !Array.isArray((data as { devices?: unknown }).devices)) {
    throw new Error('Invalid devices response');
  }
  return (data as { devices: RegisteredDevice[] }).devices;
}

export async function fetchUserDevices(token: string, userIdOrName: string, exceptDeviceId?: string): Promise<RegisteredDevice[]> {
  const suffix = exceptDeviceId ? `?exceptDeviceId=${encodeURIComponent(exceptDeviceId)}` : '';
  const response = await fetch(`/api/keys/devices/${encodeURIComponent(userIdOrName)}${suffix}`, { headers: authHeaders(token) });
  const data = await readJsonOrThrow(response);
  if (!data || typeof data !== 'object' || !Array.isArray((data as { devices?: unknown }).devices)) {
    throw new Error('Invalid devices response');
  }
  return (data as { devices: RegisteredDevice[] }).devices;
}


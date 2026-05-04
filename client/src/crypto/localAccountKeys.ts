import { fromBase64 } from './signalKeys';

type StoredOneTimePreKey = {
  id: string;
  publicKeyB64: string;
  privateKeyB64: string;
};

type StoredAccountKeys = {
  identityKey?: { publicKeyB64: string; privateKeyB64: string };
  signedPreKey?: { publicKeyB64: string; privateKeyB64: string; signatureB64: string };
  oneTimePreKeys?: StoredOneTimePreKey[];
};

function storageKey(userId: string): string {
  return `signal-keys-${userId}`;
}

export function loadStoredAccountKeys(userId: string): StoredAccountKeys | null {
  try {
    const raw = localStorage.getItem(storageKey(userId));
    return raw ? (JSON.parse(raw) as StoredAccountKeys) : null;
  } catch {
    return null;
  }
}

export function loadIdentityKeyPair(userId: string) {
  const keys = loadStoredAccountKeys(userId);
  const identity = keys?.identityKey;
  if (!identity?.publicKeyB64 || !identity.privateKeyB64) return null;
  return {
    publicKeyB64: identity.publicKeyB64,
    privateKey: fromBase64(identity.privateKeyB64),
  };
}

export function loadReceiverHandshakeKeys(userId: string) {
  const keys = loadStoredAccountKeys(userId);
  const identity = keys?.identityKey;
  const signedPreKey = keys?.signedPreKey;
  if (!identity?.privateKeyB64 || !signedPreKey?.privateKeyB64 || !signedPreKey.publicKeyB64) return null;
  return {
    identityPrivateKey: fromBase64(identity.privateKeyB64),
    signedPreKeyPrivateKey: fromBase64(signedPreKey.privateKeyB64),
    signedPreKeyPublicKeyB64: signedPreKey.publicKeyB64,
    signedPreKeyPrivateKeyB64: signedPreKey.privateKeyB64,
  };
}

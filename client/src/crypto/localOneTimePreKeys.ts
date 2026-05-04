type StoredOneTimePreKey = {
  id: string | number;
  publicKeyB64: string;
  privateKeyB64: string;
};

type LocalSignalKeys = {
  identityKey?: { publicKeyB64: string };
  signedPreKey?: { publicKeyB64: string; signatureB64: string };
  oneTimePreKeys?: StoredOneTimePreKey[];
};

export type PublicOneTimePreKey = {
  id: string;
  publicKeyB64: string;
};

const storageKey = (userId: string, deviceId?: string) => deviceId ? `signal-keys-${userId}-${deviceId}` : `signal-keys-${userId}`;

function loadLocalKeys(userId: string, deviceId?: string): LocalSignalKeys | null {
  try {
    const raw = localStorage.getItem(storageKey(userId, deviceId)) ?? localStorage.getItem(storageKey(userId));
    return raw ? (JSON.parse(raw) as LocalSignalKeys) : null;
  } catch {
    return null;
  }
}

function saveLocalKeys(userId: string, keys: LocalSignalKeys, deviceId?: string): void {
  localStorage.setItem(storageKey(userId, deviceId), JSON.stringify(keys));
}

export function findOneTimePreKeyPrivate(userId: string, keyId: string, deviceId?: string): StoredOneTimePreKey | null {
  const keys = loadLocalKeys(userId, deviceId);
  return keys?.oneTimePreKeys?.find((key) => String(key.id) === keyId) ?? null;
}

export function removeOneTimePreKeyPrivate(userId: string, keyId: string, deviceId?: string): boolean {
  const keys = loadLocalKeys(userId, deviceId);
  const opks = keys?.oneTimePreKeys;
  if (!keys || !opks) return false;
  const next = opks.filter((key) => String(key.id) !== keyId);
  if (next.length === opks.length) return false;
  saveLocalKeys(userId, { ...keys, oneTimePreKeys: next }, deviceId);
  return true;
}

export function consumeOneTimePreKeyPrivate(userId: string, keyId: string, deviceId?: string): StoredOneTimePreKey | null {
  const key = findOneTimePreKeyPrivate(userId, keyId, deviceId);
  if (!key) return null;
  removeOneTimePreKeyPrivate(userId, keyId, deviceId);
  // TODO: Use this private OPK during receiver-side X3DH, then discard it.
  return key;
}

export function normalizeLocalOneTimePreKeyIds(userId: string, deviceId?: string): {
  changed: boolean;
  publicKeys: PublicOneTimePreKey[];
} | null {
  const keys = loadLocalKeys(userId, deviceId);
  if (!keys?.oneTimePreKeys) return null;
  const normalized = keys.oneTimePreKeys.map((key) => ({ ...key, id: String(key.id) }));
  const changed = keys.oneTimePreKeys.some((key, index) => key.id !== normalized[index].id);
  if (changed) saveLocalKeys(userId, { ...keys, oneTimePreKeys: normalized }, deviceId);
  return {
    changed,
    publicKeys: normalized.map(({ id, publicKeyB64 }) => ({ id, publicKeyB64 })),
  };
}

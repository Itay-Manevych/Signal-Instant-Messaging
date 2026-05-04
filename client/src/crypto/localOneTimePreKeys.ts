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

const storageKey = (userId: string) => `signal-keys-${userId}`;

function loadLocalKeys(userId: string): LocalSignalKeys | null {
  try {
    const raw = localStorage.getItem(storageKey(userId));
    return raw ? (JSON.parse(raw) as LocalSignalKeys) : null;
  } catch {
    return null;
  }
}

function saveLocalKeys(userId: string, keys: LocalSignalKeys): void {
  localStorage.setItem(storageKey(userId), JSON.stringify(keys));
}

export function findOneTimePreKeyPrivate(userId: string, keyId: string): StoredOneTimePreKey | null {
  const keys = loadLocalKeys(userId);
  return keys?.oneTimePreKeys?.find((key) => String(key.id) === keyId) ?? null;
}

export function removeOneTimePreKeyPrivate(userId: string, keyId: string): boolean {
  const keys = loadLocalKeys(userId);
  const opks = keys?.oneTimePreKeys;
  if (!keys || !opks) return false;
  const next = opks.filter((key) => String(key.id) !== keyId);
  if (next.length === opks.length) return false;
  saveLocalKeys(userId, { ...keys, oneTimePreKeys: next });
  return true;
}

export function consumeOneTimePreKeyPrivate(userId: string, keyId: string): StoredOneTimePreKey | null {
  const key = findOneTimePreKeyPrivate(userId, keyId);
  if (!key) return null;
  removeOneTimePreKeyPrivate(userId, keyId);
  // TODO: Use this private OPK during receiver-side X3DH, then discard it.
  return key;
}

export function normalizeLocalOneTimePreKeyIds(userId: string): {
  changed: boolean;
  publicKeys: PublicOneTimePreKey[];
} | null {
  const keys = loadLocalKeys(userId);
  if (!keys?.oneTimePreKeys) return null;
  const normalized = keys.oneTimePreKeys.map((key) => ({ ...key, id: String(key.id) }));
  const changed = keys.oneTimePreKeys.some((key, index) => key.id !== normalized[index].id);
  if (changed) saveLocalKeys(userId, { ...keys, oneTimePreKeys: normalized });
  return {
    changed,
    publicKeys: normalized.map(({ id, publicKeyB64 }) => ({ id, publicKeyB64 })),
  };
}

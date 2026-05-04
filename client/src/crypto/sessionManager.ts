export type PeerSession = {
  peerUserId: string;
  peerIdentityKeyB64: string;
  sharedSecretB64?: string;
  ratchetState?: unknown;
  isInitialized: boolean;
  createdAt: string;
  updatedAt: string;
};

type SessionStore = {
  userId: string;
  sessions: Record<string, PeerSession>;
};

const storageKey = (userId: string) => `signal-sessions-${userId}`;

function now(): string {
  return new Date().toISOString();
}

function emptyStore(userId: string): SessionStore {
  return { userId, sessions: {} };
}

function loadStore(userId: string): SessionStore {
  try {
    const raw = localStorage.getItem(storageKey(userId));
    if (!raw) return emptyStore(userId);
    const parsed = JSON.parse(raw) as Partial<SessionStore>;
    return {
      userId,
      sessions: parsed.sessions ?? {},
    };
  } catch {
    return emptyStore(userId);
  }
}

function saveStore(store: SessionStore): void {
  localStorage.setItem(storageKey(store.userId), JSON.stringify(store));
}

export function getSession(selfUserId: string, peerUserId: string): PeerSession | null {
  return loadStore(selfUserId).sessions[peerUserId] ?? null;
}

export function hasSession(selfUserId: string, peerUserId: string): boolean {
  return Boolean(getSession(selfUserId, peerUserId));
}

export function listSessions(selfUserId: string): PeerSession[] {
  return Object.values(loadStore(selfUserId).sessions);
}

export function saveSession(selfUserId: string, session: PeerSession): PeerSession {
  const store = loadStore(selfUserId);
  const previous = store.sessions[session.peerUserId];
  if (previous && previous.peerIdentityKeyB64 !== session.peerIdentityKeyB64) {
    throw new Error('Peer identity key changed');
  }
  const saved: PeerSession = {
    ...session,
    createdAt: previous?.createdAt ?? session.createdAt,
    updatedAt: now(),
  };
  store.sessions[session.peerUserId] = saved;
  saveStore(store);
  return saved;
}

export function createSessionFromX3DH(
  selfUserId: string,
  peerUserId: string,
  peerIdentityKeyB64: string,
  sharedSecretB64: string,
): PeerSession {
  const timestamp = now();
  return saveSession(selfUserId, {
    peerUserId,
    peerIdentityKeyB64,
    sharedSecretB64,
    isInitialized: true,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}

export function updateRatchetState(
  selfUserId: string,
  peerUserId: string,
  ratchetState: unknown,
): PeerSession | null {
  const session = getSession(selfUserId, peerUserId);
  if (!session) return null;
  return saveSession(selfUserId, { ...session, ratchetState });
}

export function deleteSession(selfUserId: string, peerUserId: string): void {
  const store = loadStore(selfUserId);
  delete store.sessions[peerUserId];
  saveStore(store);
}

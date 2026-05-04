import type { DeviceAddress, SesameSession, SesameStore } from './sesameTypes';

const key = (userId: string, deviceId: string) => `signal-sesame-${userId}-${deviceId}`;
export const addressKey = (addr: DeviceAddress) => `${addr.userId}:${addr.deviceId}`;

function now() {
  return new Date().toISOString();
}

function empty(userId: string, deviceId: string): SesameStore {
  return { userId, deviceId, sessions: {}, active: {} };
}

export function loadSesameStore(userId: string, deviceId: string): SesameStore {
  try {
    const raw = localStorage.getItem(key(userId, deviceId));
    if (!raw) return empty(userId, deviceId);
    const parsed = JSON.parse(raw) as Partial<SesameStore>;
    return { userId, deviceId, sessions: parsed.sessions ?? {}, active: parsed.active ?? {} };
  } catch {
    return empty(userId, deviceId);
  }
}

export function saveSesameStore(store: SesameStore): void {
  localStorage.setItem(key(store.userId, store.deviceId), JSON.stringify(store));
}

export function getActiveSession(userId: string, deviceId: string, peer: DeviceAddress) {
  const store = loadSesameStore(userId, deviceId);
  const id = store.active[addressKey(peer)];
  return id ? store.sessions[id] ?? null : null;
}

export function getSesameSession(userId: string, deviceId: string, sessionId: string) {
  return loadSesameStore(userId, deviceId).sessions[sessionId] ?? null;
}

export function upsertSesameSession(userId: string, deviceId: string, session: SesameSession) {
  const store = loadSesameStore(userId, deviceId);
  const previous = store.sessions[session.sessionId];
  const saved = { ...session, createdAt: previous?.createdAt ?? session.createdAt, updatedAt: now() };
  store.sessions[session.sessionId] = saved;
  if (saved.active) store.active[addressKey(saved.peer)] = saved.sessionId;
  saveSesameStore(store);
  return saved;
}

export function activateSesameSession(userId: string, deviceId: string, sessionId: string) {
  const store = loadSesameStore(userId, deviceId);
  const session = store.sessions[sessionId];
  if (!session) return null;
  const peerKey = addressKey(session.peer);
  for (const item of Object.values(store.sessions)) {
    if (addressKey(item.peer) === peerKey) item.active = item.sessionId === sessionId;
  }
  session.active = true;
  session.updatedAt = now();
  store.active[peerKey] = sessionId;
  saveSesameStore(store);
  return session;
}

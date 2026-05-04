import type { RatchetState } from './ratchetTypes';
import type { DeviceAddress, SesameSession } from './sesameTypes';
import { activateSesameSession, getActiveSession, getSesameSession, upsertSesameSession } from './sesameStore';

function id(): string {
  return typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `sesame-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function now(): string {
  return new Date().toISOString();
}

export function createSesameSession(
  self: DeviceAddress,
  peer: DeviceAddress,
  peerIdentityKeyB64: string,
  sharedSecretB64?: string,
  sessionId = id(),
): SesameSession {
  const timestamp = now();
  return upsertSesameSession(self.userId, self.deviceId, {
    sessionId,
    peer,
    peerIdentityKeyB64,
    sharedSecretB64,
    active: false,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}

export function activeSession(self: DeviceAddress, peer: DeviceAddress) {
  return getActiveSession(self.userId, self.deviceId, peer);
}

export function sessionById(self: DeviceAddress, sessionId: string) {
  return getSesameSession(self.userId, self.deviceId, sessionId);
}

export function updateSesameRatchet(self: DeviceAddress, sessionId: string, ratchetState: RatchetState) {
  const session = sessionById(self, sessionId);
  if (!session) return null;
  return upsertSesameSession(self.userId, self.deviceId, { ...session, ratchetState });
}

export function activateSession(self: DeviceAddress, sessionId: string) {
  return activateSesameSession(self.userId, self.deviceId, sessionId);
}

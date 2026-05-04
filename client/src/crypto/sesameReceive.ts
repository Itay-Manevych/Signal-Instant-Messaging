import type { ChatEnvelope } from '../protocol';
import { decryptRatchetEnvelope } from './encryptedChat';
import { loadReceiverHandshakeKeys } from './localAccountKeys';
import { findOneTimePreKeyPrivate, removeOneTimePreKeyPrivate } from './localOneTimePreKeys';
import { ratchetInitBob } from './ratchetInit';
import type { RatchetState } from './ratchetTypes';
import type { DeviceAddress } from './sesameTypes';
import { activateSession, createSesameSession, sessionById, updateSesameRatchet } from './sesameSession';
import { fromBase64, toBase64 } from './signalKeys';
import { initializeReceiverSessionDetailed } from './x3dh';

export async function decryptSesameEnvelope(
  self: DeviceAddress,
  peer: DeviceAddress,
  envelope: ChatEnvelope,
): Promise<string> {
  const sessionId = envelope.sesameSessionId;
  if (!sessionId) throw new Error('Missing Sesame session id');
  const existing = sessionById(self, sessionId);
  if (envelope.kind === 'initial' && !existing) return decryptInitial(self, peer, envelope, sessionId);
  if (!existing?.ratchetState) throw new Error('Missing Sesame ratchet state');
  const result = await decryptRatchetEnvelope(existing.ratchetState as RatchetState, envelope, peer.userId, self.userId, {
    fromDeviceId: peer.deviceId,
    toDeviceId: self.deviceId,
    sesameSessionId: sessionId,
  });
  updateSesameRatchet(self, sessionId, result.state);
  activateSession(self, sessionId);
  return result.plaintext;
}

async function decryptInitial(self: DeviceAddress, peer: DeviceAddress, envelope: ChatEnvelope, sessionId: string) {
  const keys = loadReceiverHandshakeKeys(self.userId, self.deviceId);
  if (!keys || !envelope.senderEphemeralKeyB64) throw new Error('Missing receiver handshake keys');
  const opk = envelope.usedOneTimePreKeyId
    ? findOneTimePreKeyPrivate(self.userId, envelope.usedOneTimePreKeyId, self.deviceId)
    : null;
  if (envelope.usedOneTimePreKeyId && !opk) throw new Error(`Missing one-time prekey ${envelope.usedOneTimePreKeyId}`);
  const x3dh = initializeReceiverSessionDetailed(
    keys.identityPrivateKey,
    keys.signedPreKeyPrivateKey,
    opk ? fromBase64(opk.privateKeyB64) : null,
    fromBase64(envelope.senderIdentityKeyB64),
    fromBase64(envelope.senderEphemeralKeyB64),
  );
  createSesameSession(self, peer, envelope.senderIdentityKeyB64, toBase64(x3dh.sharedSecret), sessionId);
  const ratchet = ratchetInitBob(x3dh.sharedSecret, {
    publicKeyB64: keys.signedPreKeyPublicKeyB64,
    privateKeyB64: keys.signedPreKeyPrivateKeyB64,
  });
  const result = await decryptRatchetEnvelope(ratchet, envelope, peer.userId, self.userId, {
    fromDeviceId: peer.deviceId,
    toDeviceId: self.deviceId,
    sesameSessionId: sessionId,
  });
  updateSesameRatchet(self, sessionId, result.state);
  activateSession(self, sessionId);
  if (envelope.usedOneTimePreKeyId) removeOneTimePreKeyPrivate(self.userId, envelope.usedOneTimePreKeyId, self.deviceId);
  return result.plaintext;
}

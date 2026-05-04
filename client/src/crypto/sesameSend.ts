import { fetchDevicePreKeyBundles, fetchUserDevices, type RegisteredDevice } from '../api/keys';
import { associatedData, encryptRatchetEnvelope } from './encryptedChat';
import { loadIdentityKeyPair } from './localAccountKeys';
import { rememberOutgoingPlaintext } from './localMessageCache';
import { ratchetEncrypt } from './doubleRatchet';
import { ratchetInitAlice } from './ratchetInit';
import type { RatchetState } from './ratchetTypes';
import type { DeviceAddress } from './sesameTypes';
import { activeSession, activateSession, createSesameSession, updateSesameRatchet } from './sesameSession';
import { fromBase64, toBase64 } from './signalKeys';
import { initializeSenderSession, type PreKeyBundle } from './x3dh';

type DeviceBundle = NonNullable<Awaited<ReturnType<typeof fetchDevicePreKeyBundles>>['devices']>[number];

function toPreKeyBundle(bundle: DeviceBundle['bundle']): PreKeyBundle {
  return {
    identityPublicKey: fromBase64(bundle.identityKey.publicKeyB64),
    signedPreKeyPublicKey: fromBase64(bundle.signedPreKey.publicKeyB64),
    signedPreKeySignature: fromBase64(bundle.signedPreKey.signatureB64),
    oneTimePreKeyId: bundle.oneTimePreKeyId,
    oneTimePreKeyPublicKey: bundle.oneTimePreKeyPublicKey ? fromBase64(bundle.oneTimePreKeyPublicKey) : undefined,
  };
}

export async function encryptForPeerDevices(token: string, self: DeviceAddress, peerUserId: string, plaintext: string, allowEmpty = false) {
  const devices = await fetchUserDevices(token, peerUserId, self.deviceId);
  if (devices.length === 0) {
    if (allowEmpty) return [];
    throw new Error('Recipient has no registered devices yet. They must sign in once before encrypted messages can be sent.');
  }
  return Promise.all(devices.map((device) => encryptForDevice(token, self, peerUserId, device, plaintext)));
}

async function encryptForDevice(token: string, self: DeviceAddress, peerUserId: string, device: RegisteredDevice, plaintext: string) {
  const peer = { userId: peerUserId, deviceId: device.deviceId };
  const existing = activeSession(self, peer);
  if (existing?.ratchetState) return encryptExisting(self, peer, existing.sessionId, existing.ratchetState as RatchetState, plaintext);
  const response = await fetchDevicePreKeyBundles(token, peerUserId, self.deviceId, device.deviceId);
  const bundle = response.devices?.[0];
  if (!bundle) throw new Error(`Missing pre-key bundle for device ${device.deviceId}`);
  return encryptInitial(self, peer, bundle, plaintext);
}

async function encryptExisting(self: DeviceAddress, peer: DeviceAddress, sessionId: string, state: RatchetState, plaintext: string) {
  const senderIdentityKeyB64 = loadIdentityKeyPair(self.userId, self.deviceId)?.publicKeyB64 ?? '';
  const result = await encryptRatchetEnvelope(self.userId, state, plaintext, senderIdentityKeyB64, self.userId, peer.userId, {
    fromDeviceId: self.deviceId,
    toDeviceId: peer.deviceId,
    sesameSessionId: sessionId,
  });
  updateSesameRatchet(self, sessionId, result.state);
  return { toUserId: peer.userId, toDeviceId: peer.deviceId, sesameSessionId: sessionId, envelope: result.envelope };
}

async function encryptInitial(self: DeviceAddress, peer: DeviceAddress, device: DeviceBundle, plaintext: string) {
  const identity = loadIdentityKeyPair(self.userId, self.deviceId);
  if (!identity) throw new Error('Missing local identity key pair');
  const sessionId = crypto.randomUUID();
  const result = initializeSenderSession(identity.privateKey, toPreKeyBundle(device.bundle));
  const ratchetState = ratchetInitAlice(result.sharedSecret, device.bundle.signedPreKey.publicKeyB64);
  createSesameSession(self, peer, device.bundle.identityKey.publicKeyB64, toBase64(result.sharedSecret), sessionId);
  const first = await ratchetEncrypt(
    ratchetState,
    plaintext,
    associatedData(self.userId, peer.userId, identity.publicKeyB64, {
      fromDeviceId: self.deviceId,
      toDeviceId: peer.deviceId,
      sesameSessionId: sessionId,
    }),
  );
  updateSesameRatchet(self, sessionId, first.state);
  activateSession(self, sessionId);
  const envelope = {
    version: 1 as const,
    kind: 'initial' as const,
    sesameSessionId: sessionId,
    senderIdentityKeyB64: identity.publicKeyB64,
    senderEphemeralKeyB64: toBase64(result.ephemeralPublicKey),
    usedOneTimePreKeyId: result.usedOneTimePreKeyId,
    ratchetHeader: first.header,
    ciphertextB64: first.ciphertextB64,
    nonceB64: first.nonceB64,
  };
  rememberOutgoingPlaintext(self.userId, envelope, plaintext);
  return { toUserId: peer.userId, toDeviceId: peer.deviceId, sesameSessionId: sessionId, envelope };
}

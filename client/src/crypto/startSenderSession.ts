import { fetchPreKeyBundle } from '../api';
import { createDevEnvelope } from './envelope';
import { loadIdentityKeyPair } from './localAccountKeys';
import { protocolLog } from './protocolLog';
import { createSessionFromX3DH } from './sessionManager';
import { fromBase64, toBase64 } from './signalKeys';
import { initializeSenderSession, type PreKeyBundle } from './x3dh';

function shortSecret(bytes: Uint8Array): string {
  return toBase64(bytes).slice(0, 16);
}

export async function startSenderSession(
  token: string,
  selfUserId: string,
  peerUserId: string,
  plaintext: string,
) {
  const identityKeyPair = loadIdentityKeyPair(selfUserId);
  if (!identityKeyPair) throw new Error('Missing local identity key pair');
  protocolLog('[X3DH] No session found, fetching pre-key bundle', { peer: peerUserId.slice(0, 8) });
  const response = await fetchPreKeyBundle(token, peerUserId);
  const bundle = response.bundle;
  protocolLog('[X3DH] Pre-key bundle fetched', {
    receiverIdentityPublicKey: bundle.identityKey.publicKeyB64,
    receiverSignedPreKeyPublicKey: bundle.signedPreKey.publicKeyB64,
    receiverOneTimePreKeyPublicKey: bundle.oneTimePreKeyPublicKey,
    signedPreKeySignature: bundle.signedPreKey.signatureB64,
  });
  const preKeyBundle: PreKeyBundle = {
    identityPublicKey: fromBase64(bundle.identityKey.publicKeyB64),
    signedPreKeyPublicKey: fromBase64(bundle.signedPreKey.publicKeyB64),
    signedPreKeySignature: fromBase64(bundle.signedPreKey.signatureB64),
    oneTimePreKeyId: bundle.oneTimePreKeyId,
    oneTimePreKeyPublicKey: bundle.oneTimePreKeyPublicKey
      ? fromBase64(bundle.oneTimePreKeyPublicKey)
      : undefined,
  };
  const result = initializeSenderSession(identityKeyPair.privateKey, preKeyBundle);
  protocolLog('[X3DH] Generating sender ephemeral key pair', {
    senderEphemeralPublicKey: toBase64(result.ephemeralPublicKey),
    senderEphemeralPrivateKey: result.ephemeralPrivateKey ? toBase64(result.ephemeralPrivateKey) : undefined,
  });
  protocolLog('[X3DH] Performing DH calculations', {
    dh1: result.dh1 ? toBase64(result.dh1) : undefined,
    dh2: result.dh2 ? toBase64(result.dh2) : undefined,
    dh3: result.dh3 ? toBase64(result.dh3) : undefined,
    dh4: result.dh4 ? toBase64(result.dh4) : undefined,
  });
  protocolLog('[X3DH] Combining DH outputs and deriving shared secret using KDF', {
    sharedSecretPrefix: shortSecret(result.sharedSecret),
  });
  createSessionFromX3DH(selfUserId, peerUserId, bundle.identityKey.publicKeyB64, toBase64(result.sharedSecret));
  protocolLog('[X3DH] Sender session initialized', { sharedSecretPrefix: shortSecret(result.sharedSecret) });
  protocolLog('[X3DH] Shared secret saved in sessionManager', { peer: peerUserId.slice(0, 8) });
  const envelope = createDevEnvelope(plaintext, {
    kind: 'initial',
    senderIdentityKeyB64: identityKeyPair.publicKeyB64,
    senderEphemeralKeyB64: toBase64(result.ephemeralPublicKey),
    usedOneTimePreKeyId: result.usedOneTimePreKeyId,
  });
  protocolLog('[X3DH] Sending initial envelope', {
    senderIdentityPublicKey: identityKeyPair.publicKeyB64,
    senderEphemeralPublicKey: toBase64(result.ephemeralPublicKey),
    usedOneTimePreKeyId: result.usedOneTimePreKeyId,
  });
  return envelope;
}


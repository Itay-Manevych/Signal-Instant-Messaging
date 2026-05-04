import { fetchPreKeyBundle } from '../api';
import { associatedData } from './encryptedChat';
import { loadIdentityKeyPair } from './localAccountKeys';
import { rememberOutgoingPlaintext } from './localMessageCache';
import { protocolLog } from './protocolLog';
import { createSessionFromX3DH, updateRatchetState } from './sessionManager';
import { ratchetEncrypt } from './doubleRatchet';
import { ratchetInitAlice } from './ratchetInit';
import { fromBase64, toBase64 } from './signalKeys';
import { initializeSenderSession, type PreKeyBundle } from './x3dh';

function shortSecret(bytes: Uint8Array): string {
  return toBase64(bytes).slice(0, 16);
}
export async function startSenderSession(token: string, selfUserId: string, peerUserId: string, plaintext: string) {
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
  const ratchetState = ratchetInitAlice(result.sharedSecret, bundle.signedPreKey.publicKeyB64);
  protocolLog('[DR] Alice ratchet initialized (DEV ONLY)', {
    rootKey: ratchetState.rootKeyB64,
    sendingChainKey: ratchetState.sendingChainKeyB64,
    selfRatchetPublicKey: ratchetState.selfRatchetPublicKeyB64,
  });
  protocolLog('[X3DH] Shared secret saved in sessionManager', { peer: peerUserId.slice(0, 8) });
  const first = await ratchetEncrypt(
    ratchetState,
    plaintext,
    associatedData(selfUserId, peerUserId, identityKeyPair.publicKeyB64),
  );
  updateRatchetState(selfUserId, peerUserId, first.state);
  const envelope = {
    version: 1 as const,
    kind: 'initial' as const,
    senderIdentityKeyB64: identityKeyPair.publicKeyB64,
    senderEphemeralKeyB64: toBase64(result.ephemeralPublicKey),
    usedOneTimePreKeyId: result.usedOneTimePreKeyId,
    ratchetHeader: first.header,
    ciphertextB64: first.ciphertextB64,
    nonceB64: first.nonceB64,
  };
  rememberOutgoingPlaintext(selfUserId, envelope, plaintext);
  protocolLog('[X3DH] Sending initial envelope', {
    senderIdentityPublicKey: identityKeyPair.publicKeyB64,
    senderEphemeralPublicKey: toBase64(result.ephemeralPublicKey),
    usedOneTimePreKeyId: result.usedOneTimePreKeyId,
  });
  protocolLog('[DR] Initial envelope encrypted (DEV ONLY)', {
    header: JSON.stringify(first.header),
    ciphertext: first.ciphertextB64,
    nonce: first.nonceB64,
  });
  return envelope;
}

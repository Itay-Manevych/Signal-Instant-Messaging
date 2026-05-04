import { calculateX25519 } from './signalCrypto';
import { generateEphemeralKeyPair, toBase64, fromBase64 } from './signalKeys';
import { kdfRootKey } from './ratchetKdf';
import type { RatchetState } from './ratchetTypes';

export function ratchetInitAlice(sharedSecret: Uint8Array, remoteRatchetPublicKeyB64: string): RatchetState {
  const selfRatchet = generateEphemeralKeyPair();
  const dhOut = calculateX25519(selfRatchet.privateKey, fromBase64(remoteRatchetPublicKeyB64));
  const next = kdfRootKey(sharedSecret, dhOut);
  return {
    rootKeyB64: toBase64(next.rootKey),
    sendingChainKeyB64: toBase64(next.chainKey),
    selfRatchetPrivateKeyB64: toBase64(selfRatchet.privateKey),
    selfRatchetPublicKeyB64: toBase64(selfRatchet.publicKey),
    remoteRatchetPublicKeyB64,
    sentMessageCount: 0,
    receivedMessageCount: 0,
    previousSendingChainLength: 0,
    skippedMessageKeys: {},
  };
}

export function ratchetInitBob(sharedSecret: Uint8Array, selfRatchetKeyPair: {
  privateKeyB64: string;
  publicKeyB64: string;
}): RatchetState {
  return {
    rootKeyB64: toBase64(sharedSecret),
    selfRatchetPrivateKeyB64: selfRatchetKeyPair.privateKeyB64,
    selfRatchetPublicKeyB64: selfRatchetKeyPair.publicKeyB64,
    sentMessageCount: 0,
    receivedMessageCount: 0,
    previousSendingChainLength: 0,
    skippedMessageKeys: {},
  };
}

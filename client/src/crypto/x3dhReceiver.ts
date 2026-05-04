import { calculateX25519 } from './signalCrypto';
import { signalKdf } from './x3dhKdf';
import type { ReceiverHandshakeResult } from './x3dhTypes';

export function initializeReceiverSession(
  receiverIdentityPrivateKey: Uint8Array,
  receiverSignedPreKeyPrivateKey: Uint8Array,
  receiverOneTimePreKeyPrivateKey: Uint8Array | null,
  senderIdentityPublicKey: Uint8Array,
  senderEphemeralPublicKey: Uint8Array,
): Uint8Array {
  return initializeReceiverSessionDetailed(
    receiverIdentityPrivateKey,
    receiverSignedPreKeyPrivateKey,
    receiverOneTimePreKeyPrivateKey,
    senderIdentityPublicKey,
    senderEphemeralPublicKey,
  ).sharedSecret;
}

export function initializeReceiverSessionDetailed(
  receiverIdentityPrivateKey: Uint8Array,
  receiverSignedPreKeyPrivateKey: Uint8Array,
  receiverOneTimePreKeyPrivateKey: Uint8Array | null,
  senderIdentityPublicKey: Uint8Array,
  senderEphemeralPublicKey: Uint8Array,
): ReceiverHandshakeResult {
  const dhValues = [
    calculateX25519(receiverSignedPreKeyPrivateKey, senderIdentityPublicKey),
    calculateX25519(receiverIdentityPrivateKey, senderEphemeralPublicKey),
    calculateX25519(receiverSignedPreKeyPrivateKey, senderEphemeralPublicKey),
  ];
  if (receiverOneTimePreKeyPrivateKey) {
    dhValues.push(calculateX25519(receiverOneTimePreKeyPrivateKey, senderEphemeralPublicKey));
  }
  return {
    sharedSecret: signalKdf(dhValues),
    dh1: dhValues[0],
    dh2: dhValues[1],
    dh3: dhValues[2],
    dh4: dhValues[3],
  };
}

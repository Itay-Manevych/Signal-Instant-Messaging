import type { ChatEnvelope } from '../protocol';
import { consumeOutgoingPlaintext, loadMessagePlaintext, rememberOutgoingPlaintext, saveMessagePlaintext } from './localMessageCache';
import { protocolLog } from './protocolLog';
import { ratchetDecrypt, ratchetEncrypt } from './doubleRatchet';
import type { RatchetState } from './ratchetTypes';

export function associatedData(
  fromUserId: string,
  toUserId: string,
  senderIdentityKeyB64: string,
  device?: { fromDeviceId?: string; toDeviceId?: string; sesameSessionId?: string },
) {
  return JSON.stringify({ fromUserId, toUserId, senderIdentityKeyB64, ...device });
}

export async function encryptRatchetEnvelope(
  userId: string,
  state: RatchetState,
  plaintext: string,
  senderIdentityKeyB64: string,
  fromUserId: string,
  toUserId: string,
  device?: { fromDeviceId?: string; toDeviceId?: string; sesameSessionId?: string },
) {
  const first = await ratchetEncrypt(state, plaintext, associatedData(fromUserId, toUserId, senderIdentityKeyB64, device));
  const envelope: ChatEnvelope = {
    version: 1,
    kind: 'ratchet',
    sesameSessionId: device?.sesameSessionId,
    senderIdentityKeyB64,
    ratchetHeader: first.header,
    ciphertextB64: first.ciphertextB64,
    nonceB64: first.nonceB64,
  };
  rememberOutgoingPlaintext(userId, envelope, plaintext);
  protocolLog('[DR] Ratchet encrypt (DEV ONLY)', {
    header: JSON.stringify(first.header),
    ciphertext: first.ciphertextB64,
    nonce: first.nonceB64,
  });
  return { state: first.state, envelope };
}

export async function decryptRatchetEnvelope(
  state: RatchetState,
  envelope: ChatEnvelope,
  fromUserId: string,
  toUserId: string,
  device?: { fromDeviceId?: string; toDeviceId?: string; sesameSessionId?: string },
) {
  if (!envelope.ratchetHeader || !envelope.nonceB64) throw new Error('Missing ratchet payload');
  const result = await ratchetDecrypt(
    state,
    envelope.ratchetHeader,
    envelope.ciphertextB64,
    envelope.nonceB64,
    associatedData(fromUserId, toUserId, envelope.senderIdentityKeyB64, device),
  );
  protocolLog('[DR] Ratchet decrypt (DEV ONLY)', {
    header: JSON.stringify(envelope.ratchetHeader),
    ciphertext: envelope.ciphertextB64,
    nonce: envelope.nonceB64,
    plaintext: result.plaintext,
  });
  return result;
}

export function cacheMessagePlaintext(userId: string, messageId: string, plaintext: string): void {
  saveMessagePlaintext(userId, messageId, plaintext);
}

export function readCachedMessagePlaintext(userId: string, messageId: string): string | null {
  return loadMessagePlaintext(userId, messageId);
}

export function resolveOutgoingPlaintext(userId: string, envelope: ChatEnvelope): string | null {
  return consumeOutgoingPlaintext(userId, envelope);
}

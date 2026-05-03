import type { ChatEnvelope } from '../protocol';
import { findOneTimePreKeyPrivate, removeOneTimePreKeyPrivate } from './localOneTimePreKeys';
import { loadReceiverHandshakeKeys } from './localAccountKeys';
import { protocolLog } from './protocolLog';
import { createSessionFromX3DH } from './sessionManager';
import { fromBase64, toBase64 } from './signalKeys';
import { initializeReceiverSessionDetailed } from './x3dh';

function shortSecret(bytes: Uint8Array): string {
  return toBase64(bytes).slice(0, 16);
}

export async function handleInitialEnvelope(
  selfUserId: string,
  fromUserId: string,
  envelope: ChatEnvelope,
): Promise<{ sharedSecretPrefix: string }> {
  const receiverKeys = loadReceiverHandshakeKeys(selfUserId);
  if (!receiverKeys || !envelope.senderEphemeralKeyB64) throw new Error('Missing receiver handshake keys');
  protocolLog('[X3DH] Initial envelope received, no session found', { from: fromUserId.slice(0, 8) });
  protocolLog('[X3DH] Receiver session initializing', { peer: fromUserId.slice(0, 8) });
  protocolLog('[X3DH] Sender identity public key received', { value: envelope.senderIdentityKeyB64 });
  protocolLog('[X3DH] Sender ephemeral public key received', { value: envelope.senderEphemeralKeyB64 });
  const oneTimePreKey = envelope.usedOneTimePreKeyId
    ? findOneTimePreKeyPrivate(selfUserId, envelope.usedOneTimePreKeyId)
    : null;
  if (envelope.usedOneTimePreKeyId && !oneTimePreKey) {
    throw new Error(`Missing local one-time prekey ${envelope.usedOneTimePreKeyId}`);
  }
  protocolLog('[X3DH] Using one-time prekey', { id: envelope.usedOneTimePreKeyId ?? 'none' });
  const result = initializeReceiverSessionDetailed(
    receiverKeys.identityPrivateKey,
    receiverKeys.signedPreKeyPrivateKey,
    oneTimePreKey ? fromBase64(oneTimePreKey.privateKeyB64) : null,
    fromBase64(envelope.senderIdentityKeyB64),
    fromBase64(envelope.senderEphemeralKeyB64),
  );
  protocolLog('[X3DH] Performing receiver DH calculations (DEV ONLY)', {
    dh1: toBase64(result.dh1),
    dh2: toBase64(result.dh2),
    dh3: toBase64(result.dh3),
    dh4: result.dh4 ? toBase64(result.dh4) : undefined,
  });
  protocolLog('[X3DH] Receiver sharedSecretPrefix', { value: shortSecret(result.sharedSecret) });
  createSessionFromX3DH(selfUserId, fromUserId, envelope.senderIdentityKeyB64, toBase64(result.sharedSecret));
  protocolLog('[X3DH] Receiver session saved', { peer: fromUserId.slice(0, 8) });
  if (envelope.usedOneTimePreKeyId) {
    removeOneTimePreKeyPrivate(selfUserId, envelope.usedOneTimePreKeyId);
    protocolLog('[X3DH] Consumed local one-time prekey', { id: envelope.usedOneTimePreKeyId });
  }
  return { sharedSecretPrefix: shortSecret(result.sharedSecret) };
}

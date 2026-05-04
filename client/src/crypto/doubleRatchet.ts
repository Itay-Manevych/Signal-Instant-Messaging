import { decryptAead, encryptAead } from './ratchetAead';
import { kdfChainKey, kdfRootKey } from './ratchetKdf';
import { calculateX25519 } from './signalCrypto';
import { fromBase64, generateEphemeralKeyPair, toBase64 } from './signalKeys';
import type { RatchetDecryptResult, RatchetEncryptResult, RatchetHeader, RatchetState } from './ratchetTypes';

function skippedKey(header: RatchetHeader): string {
  return `${header.senderRatchetPublicKeyB64}:${header.messageNumber}`;
}

async function ratchetSendKey(state: RatchetState) {
  if (!state.sendingChainKeyB64) throw new Error('Missing sending chain key');
  const next = kdfChainKey(fromBase64(state.sendingChainKeyB64));
  return { ...next, messageKeyB64: toBase64(next.messageKey) };
}

function skipMessageKeys(state: RatchetState, until: number): RatchetState {
  let next = { ...state, skippedMessageKeys: { ...state.skippedMessageKeys } };
  while (next.receivedMessageCount < until && next.receivingChainKeyB64) {
    const step = kdfChainKey(fromBase64(next.receivingChainKeyB64));
    next.receivingChainKeyB64 = toBase64(step.nextChainKey);
    next.skippedMessageKeys[`${next.remoteRatchetPublicKeyB64}:${next.receivedMessageCount}`] = toBase64(step.messageKey);
    next.receivedMessageCount += 1;
  }
  return next;
}

function performDhRatchet(state: RatchetState, remoteRatchetPublicKeyB64: string): RatchetState {
  const receive = kdfRootKey(
    fromBase64(state.rootKeyB64),
    calculateX25519(fromBase64(state.selfRatchetPrivateKeyB64), fromBase64(remoteRatchetPublicKeyB64)),
  );
  const selfRatchet = generateEphemeralKeyPair();
  const send = kdfRootKey(receive.rootKey, calculateX25519(selfRatchet.privateKey, fromBase64(remoteRatchetPublicKeyB64)));
  return {
    ...state,
    rootKeyB64: toBase64(send.rootKey),
    receivingChainKeyB64: toBase64(receive.chainKey),
    sendingChainKeyB64: toBase64(send.chainKey),
    selfRatchetPrivateKeyB64: toBase64(selfRatchet.privateKey),
    selfRatchetPublicKeyB64: toBase64(selfRatchet.publicKey),
    remoteRatchetPublicKeyB64,
    previousSendingChainLength: state.sentMessageCount,
    sentMessageCount: 0,
    receivedMessageCount: 0,
  };
}

export async function ratchetEncrypt(state: RatchetState, plaintext: string, associatedData: string): Promise<RatchetEncryptResult> {
  const step = await ratchetSendKey(state);
  const header = { senderRatchetPublicKeyB64: state.selfRatchetPublicKeyB64, previousSendingChainLength: state.previousSendingChainLength, messageNumber: state.sentMessageCount };
  const payload = await encryptAead(step.messageKeyB64, plaintext, associatedData);
  return { state: { ...state, sendingChainKeyB64: toBase64(step.nextChainKey), sentMessageCount: state.sentMessageCount + 1 }, header, ...payload };
}

export async function ratchetDecrypt(state: RatchetState, header: RatchetHeader, ciphertextB64: string, nonceB64: string, associatedData: string): Promise<RatchetDecryptResult> {
  const skipped = state.skippedMessageKeys[skippedKey(header)];
  if (skipped) {
    const plaintext = await decryptAead(skipped, ciphertextB64, nonceB64, associatedData);
    const nextSkipped = { ...state.skippedMessageKeys };
    delete nextSkipped[skippedKey(header)];
    return { state: { ...state, skippedMessageKeys: nextSkipped }, plaintext };
  }
  let next = header.senderRatchetPublicKeyB64 !== state.remoteRatchetPublicKeyB64 ? performDhRatchet(skipMessageKeys(state, header.previousSendingChainLength), header.senderRatchetPublicKeyB64) : state;
  next = skipMessageKeys(next, header.messageNumber);
  if (!next.receivingChainKeyB64) throw new Error('Missing receiving chain key');
  const step = kdfChainKey(fromBase64(next.receivingChainKeyB64));
  const plaintext = await decryptAead(toBase64(step.messageKey), ciphertextB64, nonceB64, associatedData);
  return { state: { ...next, receivingChainKeyB64: toBase64(step.nextChainKey), receivedMessageCount: next.receivedMessageCount + 1 }, plaintext };
}

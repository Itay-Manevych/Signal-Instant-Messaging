import { aesEncrypt, aesDecrypt, calculateX25519, hkdfSha256, toBase64, fromBase64, compare } from './signalCrypto.js';
import { generateOneTimePreKeyPair } from './signalKeys.js';

/**
 * Double Ratchet implementation based on Signal Protocol specs.
 */

export interface RatchetHeader {
  dhPublicKey: Uint8Array;
  pn: number; // Previous sending chain length
  n: number;  // Message index in current chain
}

export interface RatchetState {
  rootKey: Uint8Array;
  activeDHKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array };
  remoteDHPublicKey: Uint8Array | null;
  sendingChainKey: Uint8Array | null;
  receivingChainKey: Uint8Array | null;
  sendingIndex: number;
  receivingIndex: number;
  previousSendingChainLength: number;
  skippedMessageKeys: { [key: string]: Uint8Array };
}

const MAX_SKIP = 2000;

/**
 * KDF_RK(rk, dh_out): Derives a new Root Key and a Chain Key.
 */
function kdfRK(rk: Uint8Array, dhOut: Uint8Array): { nextRootKey: Uint8Array; nextChainKey: Uint8Array } {
  const info = new TextEncoder().encode('RatchetRoot');
  const res = hkdfSha256(dhOut, rk, info, 64);
  const nextRootKey = res.slice(0, 32);
  const nextChainKey = res.slice(32);
  console.log('⛓️  KDF_RK:', {
    prevRK: toBase64(rk),
    dhOut: toBase64(dhOut),
    nextRK: toBase64(nextRootKey),
    nextCK: toBase64(nextChainKey)
  });
  return { nextRootKey, nextChainKey };
}

function kdfCK(ck: Uint8Array): { nextChainKey: Uint8Array; messageKey: Uint8Array } {
  const constant0x01 = new Uint8Array([0x01]);
  const constant0x02 = new Uint8Array([0x02]);
  
  // Symmetric Ratchet KDF uses HMAC normally, but we use HKDF here for simplicity 
  // since WebCrypto/Noble HMAC is more verbose.
  const nextChainKey = hkdfSha256(ck, undefined, constant0x01);
  const messageKey = hkdfSha256(ck, undefined, constant0x02);
  return { nextChainKey, messageKey };
}

function generateIdentifier(pub: Uint8Array, n: number): string {
  return `${toBase64(pub)}:${n}`;
}

function skipMessageKeys(state: RatchetState, until: number): void {
  if (state.receivingIndex + MAX_SKIP < until) {
    throw new Error('Too many messages skipped');
  }
  if (state.receivingChainKey) {
    while (state.receivingIndex < until) {
      const { nextChainKey, messageKey } = kdfCK(state.receivingChainKey);
      state.receivingChainKey = nextChainKey;
      const id = generateIdentifier(state.remoteDHPublicKey!, state.receivingIndex);
      state.skippedMessageKeys[id] = messageKey;
      state.receivingIndex++;
    }
  }
}

export function ratchetEncrypt(state: RatchetState): { header: RatchetHeader; messageKey: Uint8Array } {
  if (!state.sendingChainKey) {
    throw new Error('Sending chain not initialized');
  }
  const { nextChainKey, messageKey } = kdfCK(state.sendingChainKey);
  state.sendingChainKey = nextChainKey;
  
  const header: RatchetHeader = {
    dhPublicKey: state.activeDHKeyPair.publicKey,
    pn: state.previousSendingChainLength,
    n: state.sendingIndex,
  };
  state.sendingIndex++;
  return { header, messageKey };
}

export function ratchetDecrypt(state: RatchetState, header: RatchetHeader): Uint8Array {
  // 1. Try skipped keys first
  const id = generateIdentifier(header.dhPublicKey, header.n);
  if (state.skippedMessageKeys[id]) {
    const mk = state.skippedMessageKeys[id];
    delete state.skippedMessageKeys[id];
    console.log('✅ Used skipped message key:', id);
    return mk;
  }

  // 2. DH Ratchet?
  if (state.remoteDHPublicKey && compare(header.dhPublicKey, state.remoteDHPublicKey)) {
    // Current chain
    console.log(`⛓️  Current chain decryption: n=${header.n}, expected >= ${state.receivingIndex}`);
    skipMessageKeys(state, header.n);
    const { nextChainKey, messageKey } = kdfCK(state.receivingChainKey!);
    state.receivingChainKey = nextChainKey;
    state.receivingIndex++;
    return messageKey;
  }

  // New chain!
  console.log('🆕 New DH Ratchet step triggered by message header');
  if (state.remoteDHPublicKey) {
    skipMessageKeys(state, header.pn);
  }
  
  // Step root chain with old DH
  state.previousSendingChainLength = state.sendingIndex;
  state.sendingIndex = 0;
  state.receivingIndex = 0;
  state.remoteDHPublicKey = header.dhPublicKey;
  
  const { nextRootKey: nrk1, nextChainKey: nck1 } = kdfRK(state.rootKey, calculateX25519(state.activeDHKeyPair.privateKey, state.remoteDHPublicKey));
  state.rootKey = nrk1;
  state.receivingChainKey = nck1;
  
  // Generate new local DH
  state.activeDHKeyPair = generateOneTimePreKeyPair();
  
  const { nextRootKey: nrk2, nextChainKey: nck2 } = kdfRK(state.rootKey, calculateX25519(state.activeDHKeyPair.privateKey, state.remoteDHPublicKey));
  state.rootKey = nrk2;
  state.sendingChainKey = nck2;

  // Now process the target message in the new receiving chain
  skipMessageKeys(state, header.n);
  const { nextChainKey, messageKey } = kdfCK(state.receivingChainKey!);
  state.receivingChainKey = nextChainKey;
  state.receivingIndex++;
  
  return messageKey;
}

export function initializeRatchet(
  sk: Uint8Array,
  isInitiator: boolean,
  peerPublicKey: Uint8Array,
  ourDHKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array },
): RatchetState {
  const state: RatchetState = {
    rootKey: sk,
    activeDHKeyPair: ourDHKeyPair,
    remoteDHPublicKey: isInitiator ? peerPublicKey : null,
    sendingChainKey: null,
    receivingChainKey: null,
    sendingIndex: 0,
    receivingIndex: 0,
    previousSendingChainLength: 0,
    skippedMessageKeys: {},
  };

  if (isInitiator) {
    const dh = calculateX25519(state.activeDHKeyPair.privateKey, peerPublicKey);
    const { nextRootKey, nextChainKey } = kdfRK(sk, dh);
    state.rootKey = nextRootKey;
    state.sendingChainKey = nextChainKey;
  }

  return state;
}

export async function encryptMessage(state: RatchetState, text: string): Promise<{ ciphertextB64: string; ivB64: string; header: RatchetHeader }> {
  const { header, messageKey } = ratchetEncrypt(state);
  const plaintext = new TextEncoder().encode(text);
  const { ciphertext, iv } = await aesEncrypt(messageKey, plaintext);
  
  return {
    ciphertextB64: toBase64(ciphertext),
    ivB64: toBase64(iv),
    header,
  };
}

export async function decryptMessage(state: RatchetState, header: RatchetHeader, ciphertextB64: string, ivB64: string): Promise<string> {
  const messageKey = ratchetDecrypt(state, header);
  const ciphertext = fromBase64(ciphertextB64);
  const iv = fromBase64(ivB64);
  const plaintext = await aesDecrypt(messageKey, ciphertext, iv);
  return new TextDecoder().decode(plaintext);
}

export function serializeRatchetState(state: RatchetState): string {
  return JSON.stringify({
    ...state,
    rootKey: toBase64(state.rootKey),
    activeDHKeyPair: {
      publicKey: toBase64(state.activeDHKeyPair.publicKey),
      privateKey: toBase64(state.activeDHKeyPair.privateKey),
    },
    remoteDHPublicKey: state.remoteDHPublicKey ? toBase64(state.remoteDHPublicKey) : null,
    sendingChainKey: state.sendingChainKey ? toBase64(state.sendingChainKey) : null,
    receivingChainKey: state.receivingChainKey ? toBase64(state.receivingChainKey) : null,
    skippedMessageKeys: Object.fromEntries(
      Object.entries(state.skippedMessageKeys).map(([k, v]) => [k, toBase64(v)])
    ),
  });
}

export function deserializeRatchetState(json: string): RatchetState {
  const data = JSON.parse(json);
  return {
    ...data,
    rootKey: fromBase64(data.rootKey),
    activeDHKeyPair: {
      publicKey: fromBase64(data.activeDHKeyPair.publicKey),
      privateKey: fromBase64(data.activeDHKeyPair.privateKey),
    },
    remoteDHPublicKey: data.remoteDHPublicKey ? fromBase64(data.remoteDHPublicKey) : null,
    sendingChainKey: data.sendingChainKey ? fromBase64(data.sendingChainKey) : null,
    receivingChainKey: data.receivingChainKey ? fromBase64(data.receivingChainKey) : null,
    skippedMessageKeys: Object.fromEntries(
      Object.entries(data.skippedMessageKeys).map(([k, v]) => [k, fromBase64(v as string)])
    ),
  };
}

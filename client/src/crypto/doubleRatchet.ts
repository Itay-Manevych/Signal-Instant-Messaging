import { calculateX25519, toBase64, fromBase64, compare } from './signalCrypto';
import { generateOneTimePreKeyPair } from './signalKeys';
import { aesEncrypt, aesDecrypt } from './aes';
import { 
  kdfRK, 
  kdfCK, 
  type RatchetState, 
  type RatchetHeader 
} from './ratchetUtils';

export { serializeRatchetState, deserializeRatchetState, type RatchetState, type RatchetHeader } from './ratchetUtils';

const MAX_SKIP = 100;

function skipMessageKeys(state: RatchetState, until: number) {
  if (state.receivingIndex >= until) return;
  if (until - state.receivingIndex > MAX_SKIP) throw new Error('Too many messages skipped');
  
  while (state.receivingIndex < until) {
    const { nextChainKey, messageKey } = kdfCK(state.receivingChainKey!);
    const key = `${toBase64(state.remoteDHPublicKey!)}-${state.receivingIndex}`;
    state.skippedMessageKeys[key] = messageKey;
    state.receivingChainKey = nextChainKey;
    state.receivingIndex++;
  }
}

export function ratchetEncrypt(state: RatchetState): { header: RatchetHeader; messageKey: Uint8Array } {
  if (!state.sendingChainKey) {
    console.log('🆕 Rotating DH key for new sending chain');
    state.previousSendingChainLength = state.sendingIndex;
    state.sendingIndex = 0;
    state.activeDHKeyPair = generateOneTimePreKeyPair();
    
    if (state.remoteDHPublicKey) {
      const dh = calculateX25519(state.activeDHKeyPair.privateKey, state.remoteDHPublicKey);
      const { nextRootKey, nextChainKey } = kdfRK(state.rootKey, dh);
      state.rootKey = nextRootKey;
      state.sendingChainKey = nextChainKey;
    } else {
      throw new Error('Cannot rotate DH without remote public key');
    }
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
  // 1. Check skipped keys
  const key = `${toBase64(header.dhPublicKey)}-${header.n}`;
  if (state.skippedMessageKeys[key]) {
    const mk = state.skippedMessageKeys[key];
    delete state.skippedMessageKeys[key];
    return mk;
  }

  // 2. DH Ratchet?
  if (state.remoteDHPublicKey) {
    const match = compare(header.dhPublicKey, state.remoteDHPublicKey);
    console.log('📡 DH Comparison (DEBUG: Temporary):', {
      headerDH: toBase64(header.dhPublicKey),
      stateRemoteDH: toBase64(state.remoteDHPublicKey),
      match,
      hasReceivingChain: !!state.receivingChainKey
    });

    if (state.receivingChainKey && match) {
      // Current chain
      console.log(`⛓️  Current chain decryption: n=${header.n}, expected >= ${state.receivingIndex}`);
      skipMessageKeys(state, header.n);
      const { nextChainKey, messageKey } = kdfCK(state.receivingChainKey!);
      state.receivingChainKey = nextChainKey;
      state.receivingIndex++;
      return messageKey;
    }
  }

  // New chain!
  console.log('🆕 New DH Ratchet step triggered (DEBUG: Temporary)');
  if (state.remoteDHPublicKey) {
    skipMessageKeys(state, header.pn);
  }
  
  state.previousSendingChainLength = state.sendingIndex;
  state.sendingIndex = 0;
  state.receivingIndex = 0;
  state.remoteDHPublicKey = header.dhPublicKey;
  
  // Step root chain to get new receiving chain
  const dh = calculateX25519(state.activeDHKeyPair.privateKey, state.remoteDHPublicKey);
  const { nextRootKey, nextChainKey } = kdfRK(state.rootKey, dh);
  
  state.rootKey = nextRootKey;
  state.receivingChainKey = nextChainKey;
  state.sendingChainKey = null; // Force rotation on next send

  // Now process the target message in the new receiving chain
  skipMessageKeys(state, header.n);
  const { nextChainKey: ck, messageKey } = kdfCK(state.receivingChainKey!);
  state.receivingChainKey = ck;
  state.receivingIndex++;
  
  return messageKey;
}

export function initializeRatchet(
  sk: Uint8Array, 
  isInitiator: boolean, 
  peerPublicKey: Uint8Array, 
  ourDHKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array }
): RatchetState {
  const state: RatchetState = {
    rootKey: sk,
    sendingChainKey: null,
    receivingChainKey: null,
    sendingIndex: 0,
    receivingIndex: 0,
    previousSendingChainLength: 0,
    activeDHKeyPair: ourDHKeyPair,
    remoteDHPublicKey: null,
    skippedMessageKeys: {},
  };

  if (isInitiator) {
    // Alice: We step the root chain once to get the initial sending chain.
    const dh = calculateX25519(state.activeDHKeyPair.privateKey, peerPublicKey);
    const { nextRootKey, nextChainKey } = kdfRK(sk, dh);
    state.rootKey = nextRootKey;
    state.sendingChainKey = nextChainKey;
    state.remoteDHPublicKey = peerPublicKey;
  } else {
    // Bob: We just store the remote key and SK. We will step on first decryption.
    state.remoteDHPublicKey = peerPublicKey;
    state.receivingChainKey = null;
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

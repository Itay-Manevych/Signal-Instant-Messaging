import { toBase64, fromBase64 } from './signalCrypto';
import { hkdfSha256 } from './kdf';

export interface RatchetHeader {
  dhPublicKey: Uint8Array;
  pn: number; // Previous chain length
  n: number;  // Message number in current chain
  x3dh?: {
    identityKeyB64: string;
    ephemeralKeyB64: string;
    oneTimePreKeyId?: number;
  };
}

export interface RatchetState {
  rootKey: Uint8Array;
  sendingChainKey: Uint8Array | null;
  receivingChainKey: Uint8Array | null;
  sendingIndex: number;
  receivingIndex: number;
  previousSendingChainLength: number;
  activeDHKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array };
  remoteDHPublicKey: Uint8Array | null;
  skippedMessageKeys: Record<string, Uint8Array>;
}

export function kdfRK(rk: Uint8Array, dhOut: Uint8Array): { nextRootKey: Uint8Array; nextChainKey: Uint8Array } {
  const info = new TextEncoder().encode('RatchetRoot');
  const res = hkdfSha256(dhOut, rk, info, 64);
  const nextRootKey = res.slice(0, 32);
  const nextChainKey = res.slice(32);
  
  console.log('🗝️ KDF_RK (DEBUG: Temporary):', { 
    prevRK: toBase64(rk), 
    dhOut: toBase64(dhOut), 
    nextRK: toBase64(nextRootKey), 
    nextCK: toBase64(nextChainKey) 
  });
  
  return { nextRootKey, nextChainKey };
}

export function kdfCK(ck: Uint8Array): { nextChainKey: Uint8Array; messageKey: Uint8Array } {
  const constant0x01 = new Uint8Array([0x01]);
  const constant0x02 = new Uint8Array([0x02]);
  
  const nextChainKey = hkdfSha256(ck, undefined, constant0x01);
  const messageKey = hkdfSha256(ck, undefined, constant0x02);
  return { nextChainKey, messageKey };
}

export function serializeRatchetState(state: RatchetState): string {
  const obj: any = { ...state };
  obj.rootKey = toBase64(state.rootKey);
  obj.sendingChainKey = state.sendingChainKey ? toBase64(state.sendingChainKey) : null;
  obj.receivingChainKey = state.receivingChainKey ? toBase64(state.receivingChainKey) : null;
  obj.activeDHKeyPair = {
    publicKey: toBase64(state.activeDHKeyPair.publicKey),
    privateKey: toBase64(state.activeDHKeyPair.privateKey),
  };
  obj.remoteDHPublicKey = state.remoteDHPublicKey ? toBase64(state.remoteDHPublicKey) : null;
  
  const skipped: any = {};
  for (const k in state.skippedMessageKeys) {
    skipped[k] = toBase64(state.skippedMessageKeys[k]);
  }
  obj.skippedMessageKeys = skipped;
  
  return JSON.stringify(obj);
}

export function deserializeRatchetState(json: string): RatchetState {
  const obj = JSON.parse(json);
  return {
    ...obj,
    rootKey: fromBase64(obj.rootKey),
    sendingChainKey: obj.sendingChainKey ? fromBase64(obj.sendingChainKey) : null,
    receivingChainKey: obj.receivingChainKey ? fromBase64(obj.receivingChainKey) : null,
    activeDHKeyPair: {
      publicKey: fromBase64(obj.activeDHKeyPair.publicKey),
      privateKey: fromBase64(obj.activeDHKeyPair.privateKey),
    },
    remoteDHPublicKey: obj.remoteDHPublicKey ? fromBase64(obj.remoteDHPublicKey) : null,
    skippedMessageKeys: Object.fromEntries(
      Object.entries(obj.skippedMessageKeys).map(([k, v]) => [k, fromBase64(v as string)])
    ),
  };
}

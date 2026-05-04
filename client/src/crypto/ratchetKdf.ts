import { hkdfSha256, hmacSha256 } from './signalCrypto';

function byte(value: number): Uint8Array {
  return new Uint8Array([value]);
}

export function kdfRootKey(rootKey: Uint8Array, dhOut: Uint8Array) {
  const material = hkdfSha256(dhOut, rootKey, undefined, 64);
  return {
    rootKey: material.slice(0, 32),
    chainKey: material.slice(32, 64),
  };
}

export function kdfChainKey(chainKey: Uint8Array) {
  return {
    nextChainKey: hmacSha256(chainKey, byte(2)),
    messageKey: hmacSha256(chainKey, byte(1)),
  };
}

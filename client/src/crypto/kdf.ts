import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

export function hkdfSha256(keyMaterial: Uint8Array, salt?: Uint8Array, info?: Uint8Array, length = 32): Uint8Array {
  return hkdf(sha256, keyMaterial, salt || new Uint8Array(32).fill(0), info, length);
}

export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  return hmac(sha256, key, message);
}

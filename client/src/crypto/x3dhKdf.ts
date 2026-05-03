import { hkdfSha256 } from './signalCrypto';

const X25519_HKDF_DISCONTINUITY = new Uint8Array(32).fill(0xff);
const X3DH_HKDF_INFO = new TextEncoder().encode('WhisperText');

export function signalKdf(dhValues: Uint8Array[]): Uint8Array {
  const kmLen = dhValues.reduce((acc, v) => acc + v.length, 0);
  const keyMaterial = new Uint8Array(X25519_HKDF_DISCONTINUITY.length + kmLen);
  keyMaterial.set(X25519_HKDF_DISCONTINUITY, 0);
  let offset = X25519_HKDF_DISCONTINUITY.length;
  for (const value of dhValues) {
    keyMaterial.set(value, offset);
    offset += value.length;
  }
  return hkdfSha256(keyMaterial, undefined, X3DH_HKDF_INFO);
}


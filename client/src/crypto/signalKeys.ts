import { x25519 } from '@noble/curves/ed25519.js';

/** Helpers for Base64 conversion (Web-compatible). Loop avoids TS spread quirks on iterable targets. */
export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

export function fromBase64(base64: string): Uint8Array {
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}

function clampX25519Scalar(bytes: Uint8Array): Uint8Array {
  const scalar = new Uint8Array(bytes);
  scalar[0] &= 248;
  scalar[31] &= 127;
  scalar[31] |= 64;
  return scalar;
}

export function generateX25519KeyPair() {
  const entropy = crypto.getRandomValues(new Uint8Array(32));
  const privateKey = clampX25519Scalar(entropy);
  const publicKey = x25519.getPublicKey(privateKey);

  return {
    publicKey,
    privateKey,
  };
}

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export function generateIdentityKeyPair(): KeyPair {
  return generateX25519KeyPair();
}

export function generateSignedPreKeyPair(): KeyPair {
  return generateX25519KeyPair();
}

export function generateOneTimePreKeyPair(): KeyPair {
  return generateX25519KeyPair();
}

export function generateEphemeralKeyPair(): KeyPair {
  return generateX25519KeyPair();
}

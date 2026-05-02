import { randomBytes } from 'node:crypto';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';

function toBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

function fromBase64(value) {
  return Uint8Array.from(Buffer.from(value, 'base64'));
}

function clampX25519Scalar(bytes) {
  const scalar = Uint8Array.from(bytes);
  scalar[0] &= 248;
  scalar[31] &= 127;
  scalar[31] |= 64;
  return scalar;
}

export function encodePublicKey(publicKey) {
  return toBase64(publicKey);
}

export function encodePrivateKey(privateKey) {
  return toBase64(privateKey);
}

export function decodePublicKey(publicKeyB64) {
  return fromBase64(publicKeyB64);
}

export function decodePrivateKey(privateKeyB64) {
  return fromBase64(privateKeyB64);
}

export function generateX25519KeyPair() {
  const privateKey = clampX25519Scalar(randomBytes(32));
  const publicKey = x25519.getPublicKey(privateKey);

  return {
    publicKey: encodePublicKey(publicKey),
    privateKey: encodePrivateKey(privateKey),
  };
}

export function generateEd25519KeyPair() {
  const { secretKey, publicKey } = ed25519.keygen();

  return {
    publicKey: encodePublicKey(publicKey),
    privateKey: encodePrivateKey(secretKey),
  };
}

export function generateIdentityKeyPair() {
  return generateX25519KeyPair();
}

export function generateSignedPreKeyPair() {
  return generateX25519KeyPair();
}

export function generateOneTimePreKeyPair() {
  return generateX25519KeyPair();
}

export function generateEphemeralKeyPair() {
  return generateX25519KeyPair();
}


import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';

const Fp = ed25519.Point.Fp;
const Q = ed25519.Point.Fn.ORDER;

/** 32-byte constant for XEd25519 deterministic nonce derivation: 0xFE followed by 31 0xFFs */
const XED25519_PREFIX = new Uint8Array(32).fill(0xff);
XED25519_PREFIX[0] = 0xfe;

function leToInt(bytes: Uint8Array): bigint {
  let res = 0n;
  for (let i = 0; i < bytes.length; i++) {
    res += BigInt(bytes[i]) << BigInt(i * 8);
  }
  return res;
}

function intToLe(value: bigint, length = 32): Uint8Array {
  const res = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    res[i] = Number((value >> BigInt(i * 8)) & 0xffn);
  }
  return res;
}

function hashModQ(...parts: Uint8Array[]): bigint {
  const h = sha512(concat(parts));
  return leToInt(h) % Q;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const totalLength = parts.reduce((acc, part) => acc + part.length, 0);
  const res = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    res.set(part, offset);
    offset += part.length;
  }
  return res;
}

export function edPublicFromMontgomery(publicKey: Uint8Array): InstanceType<typeof ed25519.Point> {
  const u = leToInt(publicKey);
  if (u >= Fp.ORDER) throw new Error('Invalid X25519 public key');
  const y = Fp.div(Fp.sub(u, 1n), Fp.add(u, 1n));
  const encoded = Fp.toBytes(y);
  encoded[31] &= 127;
  return ed25519.Point.fromBytes(encoded);
}

function xeddsaKeyPair(privateKey: Uint8Array) {
  const k = leToInt(privateKey) % Q;
  if (k === 0n) throw new Error('Invalid X25519 private key');
  const point = ed25519.Point.BASE.multiply(k);
  const encoded = point.toBytes();
  const a = (encoded[31] & 128) === 0 ? k : (Q - k) % Q;
  encoded[31] &= 127;
  return { publicKey: encoded, privateScalar: a };
}

export function calculateX25519(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(privateKey, publicKey);
}

export function sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array {
  const { publicKey, privateScalar } = xeddsaKeyPair(privateKey);
  const Z = new Uint8Array(64).fill(0);
  const r = hashModQ(XED25519_PREFIX, intToLe(privateScalar), message, Z);
  const rPoint = ed25519.Point.BASE.multiply(r).toBytes();
  const h = hashModQ(rPoint, publicKey, message);
  const s = (r + h * privateScalar) % Q;
  return concat([rPoint, intToLe(s)]);
}

export function verify(publicKeyB64: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  try {
    if (signature.length !== 64) return false;
    const rPointBytes = signature.subarray(0, 32);
    const s = leToInt(signature.subarray(32));
    if (s >= (1n << 253n)) return false;
    const publicKey = edPublicFromMontgomery(publicKeyB64);
    const h = hashModQ(rPointBytes, publicKey.toBytes(), message);
    const check = ed25519.Point.BASE.multiply(s % Q)
      .subtract(publicKey.multiply(h))
      .toBytes();
    return compare(check, rPointBytes);
  } catch {
    return false;
  }
}

export function compare(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

export function fromBase64(base64: string): Uint8Array {
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}

export function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

// Re-exports for backward compatibility
export { aesEncrypt, aesDecrypt } from './aes';
export { hkdfSha256, hmacSha256 } from './kdf';

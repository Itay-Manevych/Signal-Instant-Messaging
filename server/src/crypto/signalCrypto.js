import { createHash, createHmac, hkdfSync, randomBytes as nodeRandomBytes } from 'node:crypto';
import { ed25519, x25519 as nobleX25519 } from '@noble/curves/ed25519.js';
import { decodePrivateKey, decodePublicKey } from './signalKeys.js';

const Fp = ed25519.Point.Fp;
const Q = ed25519.Point.Fn.ORDER;
const TWO_253 = 1n << 253n;

function toBytes(value, encoding = 'base64') {
  return Buffer.isBuffer(value) ? value : Buffer.from(value, encoding);
}

function toBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

function leToInt(bytes) {
  return [...bytes].reduceRight((n, b) => (n << 8n) + BigInt(b), 0n);
}

function intToLe(value) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number((value >> BigInt(8 * i)) & 255n);
  return out;
}

function sha512(...parts) {
  const hash = createHash('sha512');
  parts.forEach((part) => hash.update(part));
  return hash.digest();
}

function hashMod(...parts) {
  return leToInt(sha512(...parts)) % Q;
}

function edPublicFromMontgomery(publicKey) {
  const u = leToInt(publicKey);
  if (u >= Fp.ORDER) throw new Error('Invalid X25519 public key');
  const y = Fp.div(Fp.sub(u, 1n), Fp.add(u, 1n));
  const encoded = Fp.toBytes(y);
  encoded[31] &= 127;
  return ed25519.Point.fromBytes(encoded);
}

function xeddsaKeyPair(privateKey) {
  const k = leToInt(privateKey) % Q;
  if (k === 0n) throw new Error('Invalid X25519 private key');
  const point = ed25519.Point.BASE.multiply(k);
  const encoded = point.toBytes();
  const a = (encoded[31] & 128) === 0 ? k : (Q - k) % Q;
  encoded[31] &= 127;
  return { publicKey: encoded, privateScalar: a };
}
export function x25519(privateKeyB64, publicKeyB64) {
  const privateKey = decodePrivateKey(privateKeyB64);
  const publicKey = decodePublicKey(publicKeyB64);

  return toBase64(nobleX25519.getSharedSecret(privateKey, publicKey));
}
export function sign(privateKeyB64, message) {
  const { publicKey, privateScalar } = xeddsaKeyPair(decodePrivateKey(privateKeyB64));
  const msg = toBytes(message);
  const r = hashMod(intToLe(privateScalar), msg, nodeRandomBytes(64));
  const rPoint = ed25519.Point.BASE.multiply(r).toBytes();
  const h = hashMod(rPoint, publicKey, msg);
  const s = (r + h * privateScalar) % Q;

  return toBase64(Buffer.concat([rPoint, intToLe(s)]));
}
export function verify(publicKeyB64, message, signatureB64) {
  try {
    const msg = toBytes(message);
    const sig = toBytes(signatureB64);
    if (sig.length !== 64) return false;
    const rPointBytes = sig.subarray(0, 32);
    const s = leToInt(sig.subarray(32));
    if (s >= TWO_253) return false;
    const publicKey = edPublicFromMontgomery(decodePublicKey(publicKeyB64));
    const h = hashMod(rPointBytes, publicKey.toBytes(), msg);
    const check = ed25519.Point.BASE.multiply(s % Q).subtract(publicKey.multiply(h)).toBytes();
    return Buffer.from(check).equals(rPointBytes);
  } catch {
    return false;
  }
}
export function hkdfSha256(keyMaterialB64, saltB64 = '', info = '', length = 32) {
  const salt = saltB64 ? toBytes(saltB64) : Buffer.alloc(32, 0);
  return toBase64(hkdfSync('sha256', toBytes(keyMaterialB64), salt, toBytes(info, 'utf8'), length));
}
export function hmacSha256(keyB64, message) {
  return createHmac('sha256', toBytes(keyB64)).update(toBytes(message)).digest('base64');
}
export function randomBytes(length) {
  return toBase64(nodeRandomBytes(length));
}

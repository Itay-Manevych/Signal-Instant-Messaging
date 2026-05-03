/**
 * Double Ratchet — classical EC variant without header encryption (Signal spec §3).
 *
 * Instantiate KDF primitives with HKDF-SHA256 / HMAC-SHA256 (PRF-grade KDF).
 * Payload encryption uses AES-256-GCM (spec allows AEAD with random nonce transmitted).
 *
 * Initial ratchet DH public key = recipient’s signed pre-key public key (SPKB),
 * paired with SK from X3DH (Signal spec §7.1 integration).
 */

import { calculateX25519, hkdfSha256, randomBytes } from './signalCrypto';
import { toBase64, type KeyPair } from './signalKeys';

const MAX_SKIP = 2000;

const KDF_RK_INFO = new TextEncoder().encode('DoubleRatchet-RK-KDF');

/** Symmetric CK step: HKDF-Expand from chain key material (distinct info from root KDF). */
const KDF_CK_INFO = new TextEncoder().encode('DoubleRatchet-CK-step');

/** Derive AES-GCM KEY from single-use message key. */
const ENCRYPT_MK_INFO = new TextEncoder().encode('DoubleRatchet-AES-GCM');

export interface RatchetHeader {
  dhPub: Uint8Array;
  pn: number;
  n: number;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

function u8equal(x: Uint8Array, y: Uint8Array): boolean {
  if (x.length !== y.length) return false;
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}

function skippedMapKey(pub: Uint8Array, n: number): string {
  return `${toBase64(pub)}:${n}`;
}

/** KDF_CK(ck): (new_chain_key_32, message_key_32). */
export function kdfCk(ck: Uint8Array): [Uint8Array, Uint8Array] {
  const out = hkdfSha256(ck, new Uint8Array(32).fill(0), KDF_CK_INFO, 64);
  return [out.subarray(0, 32), out.subarray(32, 64)];
}

/** KDF_RK(rk_as_salt_material, dh_out_as_ikm): (rk_out_32, chain_key_32). */
export function kdfRk(rootKeyLike: Uint8Array, dhOut: Uint8Array): [Uint8Array, Uint8Array] {
  const expanded = hkdfSha256(dhOut, rootKeyLike, KDF_RK_INFO, 64);
  return [expanded.subarray(0, 32), expanded.subarray(32, 64)];
}

export function encodeHeader(h: RatchetHeader): Uint8Array {
  const out = new Uint8Array(32 + 8);
  out.set(h.dhPub, 0);
  const dv = new DataView(out.buffer, 32, 8);
  dv.setUint32(0, h.pn >>> 0);
  dv.setUint32(4, h.n >>> 0);
  return out;
}

export function decodeHeader(raw: Uint8Array): RatchetHeader {
  if (raw.length < 40) throw new Error('ratchet header too short');
  const dhPub = raw.subarray(0, 32);
  const dv = new DataView(raw.buffer, raw.byteOffset + 32, 8);
  return { dhPub: new Uint8Array(dhPub), pn: dv.getUint32(0), n: dv.getUint32(4) };
}

async function aesGcmEncrypt(mk: Uint8Array, plaintext: Uint8Array, ad: Uint8Array): Promise<Uint8Array> {
  const keyRaw = hkdfSha256(mk, undefined, ENCRYPT_MK_INFO, 32);
  const iv = randomBytes(12);
  const key = await crypto.subtle.importKey('raw', keyRaw, 'AES-GCM', false, ['encrypt']);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: ad },
    key,
    plaintext,
  );
  return concat(iv, new Uint8Array(ct));
}

async function aesGcmDecrypt(mk: Uint8Array, ciphertextWithIv: Uint8Array, ad: Uint8Array): Promise<Uint8Array> {
  if (ciphertextWithIv.length < 28) throw new Error('ciphertext truncated');
  const iv = ciphertextWithIv.subarray(0, 12);
  const ct = ciphertextWithIv.subarray(12);
  const keyRaw = hkdfSha256(mk, undefined, ENCRYPT_MK_INFO, 32);
  const key = await crypto.subtle.importKey('raw', keyRaw, 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: ad }, key, ct);
  return new Uint8Array(pt);
}

export class DoubleRatchetSession {
  private DHs!: KeyPair;

  /** Remote ratchet pubkey (their current sending DH). */
  private DHr: Uint8Array | null = null;

  private RK!: Uint8Array;

  private CKs: Uint8Array | null = null;

  private CKr: Uint8Array | null = null;

  private Ns = 0;

  private Nr = 0;

  private PN = 0;

  /** Skipped receive message keys: key = skippedMapKey(dh_pub, msgN). */
  private readonly skipped = new Map<string, Uint8Array>();

  private readonly generateDhPair: () => KeyPair;

  private constructor(generateDhPair: () => KeyPair) {
    this.generateDhPair = generateDhPair;
  }

  /** Alice/initiator side (sends first). SPKB pubkey from X3DH bundle. */
  static createInitiator(
    skFromX3dh: Uint8Array,
    remoteSignedPreKeyPublic: Uint8Array,
    generateDhPair: () => KeyPair,
  ): DoubleRatchetSession {
    const session = new DoubleRatchetSession(generateDhPair);
    session.DHr = remoteSignedPreKeyPublic;
    session.DHs = generateDhPair();
    const dh1 = calculateX25519(session.DHs.privateKey, session.DHr);
    const [rk, cks] = kdfRk(skFromX3dh, dh1);
    session.RK = rk;
    session.CKs = cks;
    session.CKr = null;
    session.Ns = 0;
    session.Nr = 0;
    session.PN = 0;
    return session;
  }

  /** Bob/responder side. signedPreKeyPair must be the SAME pair used as SPKB in X3DH. */
  static createResponder(
    skFromX3dh: Uint8Array,
    localSignedPreKeyPair: KeyPair,
    generateDhPair: () => KeyPair,
  ): DoubleRatchetSession {
    const session = new DoubleRatchetSession(generateDhPair);
    session.DHs = {
      privateKey: new Uint8Array(localSignedPreKeyPair.privateKey),
      publicKey: new Uint8Array(localSignedPreKeyPair.publicKey),
    };
    session.DHr = null;
    session.RK = skFromX3dh;
    session.CKs = null;
    session.CKr = null;
    session.Ns = 0;
    session.Nr = 0;
    session.PN = 0;
    return session;
  }

  private ratchetSendKey(): { n: number; mk: Uint8Array } {
    if (this.CKs === null) throw new Error('sending chain key not initialized');
    const [nextCk, mk] = kdfCk(this.CKs);
    this.CKs = nextCk;
    const n = this.Ns;
    this.Ns += 1;
    return { n, mk };
  }

  /** Symmetric ciphertext: 12-byte IV || GCM ciphertext+tag */
  async ratchetEncrypt(plaintext: Uint8Array, associatedData: Uint8Array): Promise<{ headerBytes: Uint8Array; ciphertext: Uint8Array }> {
    const { n, mk } = this.ratchetSendKey();
    const header: RatchetHeader = { dhPub: this.DHs.publicKey, pn: this.PN, n };
    const headerBytes = encodeHeader(header);
    const ciphertext = await aesGcmEncrypt(mk, plaintext, concat(associatedData, headerBytes));
    return { headerBytes, ciphertext };
  }

  private trySkippedMessageKeys(header: RatchetHeader): Uint8Array | null {
    const k = skippedMapKey(header.dhPub, header.n);
    const mk = this.skipped.get(k);
    if (mk === undefined) return null;
    this.skipped.delete(k);
    return mk;
  }

  private skipMessageKeys(until: number): void {
    if (this.Nr + MAX_SKIP < until) {
      throw new Error('skipped message gap exceeds MAX_SKIP');
    }
    if (this.CKr === null || this.DHr === null) return;
    while (this.Nr < until) {
      const [nextCk, mk] = kdfCk(this.CKr);
      this.CKr = nextCk;
      const key = skippedMapKey(this.DHr, this.Nr);
      this.skipped.set(key, mk);
      this.Nr += 1;
      if (this.skipped.size > MAX_SKIP + 128) throw new Error('MKSKIPPED too large');
    }
  }

  private dhRatchet(header: RatchetHeader): void {
    this.PN = this.Ns;
    this.Ns = 0;
    this.Nr = 0;
    this.DHr = new Uint8Array(header.dhPub);
    const rk1pair = kdfRk(this.RK, calculateX25519(this.DHs.privateKey, this.DHr));
    this.RK = rk1pair[0];
    this.CKr = rk1pair[1];
    this.DHs = this.generateDhPair();
    const rk2pair = kdfRk(this.RK, calculateX25519(this.DHs.privateKey, this.DHr));
    this.RK = rk2pair[0];
    this.CKs = rk2pair[1];
  }

  private ratchetReceiveKey(header: RatchetHeader): Uint8Array {
    let mkFound = this.trySkippedMessageKeys(header);
    if (mkFound !== null) return mkFound;

    const needDhStep = this.DHr === null || !u8equal(header.dhPub, this.DHr);
    if (needDhStep) {
      this.skipMessageKeys(header.pn);
      this.dhRatchet(header);
    }
    this.skipMessageKeys(header.n);

    if (this.CKr === null) throw new Error('receiving chain key missing after DH step');
    const [nextCk, mk] = kdfCk(this.CKr);
    this.CKr = nextCk;
    this.Nr += 1;
    return mk;
  }

  async ratchetDecrypt(
    headerBytes: Uint8Array,
    ciphertext: Uint8Array,
    associatedData: Uint8Array,
  ): Promise<Uint8Array> {
    const header = decodeHeader(headerBytes);
    const mk = this.ratchetReceiveKey(header);
    return aesGcmDecrypt(mk, ciphertext, concat(associatedData, headerBytes));
  }
}

import { calculateX25519, hkdfSha256, verify } from './signalCrypto';
import { generateEphemeralKeyPair } from './signalKeys';

/**
 * You already computed several Diffie-Hellman results (three or four blobs, each 32 bytes).
 *
 * Plain English: push those blobs through HKDF (a standard “mix-down” function), not XOR or
 * concat alone—that step is called the X3DH key derivation function (X3DH KDF). You get back
 * one 32-byte key `SK`.
 *
 * Concretely, HKDF is fed:
 *   input  = thirty-two 0xFF bytes glued in front of (DH₁ ‖ DH₂ ‖ DH₃ [, DH₄]),
 *   salt   = 32 zero bytes when using HKDF‑SHA‑256,
 *   label  = the ASCII bytes of "WhisperText" — Signal chooses that label here.
 *
 * Full normative wording: Signal’s X3DH spec §2.2 (“KDF(KM)”).
 * URL: https://signal.org/docs/specifications/x3dh/
 */
const X25519_HKDF_DISCONTINUITY = new Uint8Array(32).fill(0xff);
const X3DH_HKDF_INFO = new TextEncoder().encode('WhisperText');

function signalKdf(dhValues: Uint8Array[]): Uint8Array {
  const kmLen = dhValues.reduce((acc, v) => acc + v.length, 0);
  const keyMaterial = new Uint8Array(X25519_HKDF_DISCONTINUITY.length + kmLen);
  keyMaterial.set(X25519_HKDF_DISCONTINUITY, 0);
  let offset = X25519_HKDF_DISCONTINUITY.length;
  for (const v of dhValues) {
    keyMaterial.set(v, offset);
    offset += v.length;
  }
  return hkdfSha256(keyMaterial, undefined, X3DH_HKDF_INFO);
}

export interface PreKeyBundle {
  identityPublicKey: Uint8Array;
  signedPreKeyPublicKey: Uint8Array;
  signedPreKeySignature: Uint8Array;
  oneTimePreKeyId?: string;
  oneTimePreKeyPublicKey?: Uint8Array;
}

export interface SenderHandshakeResult {
  sharedSecret: Uint8Array;
  ephemeralPublicKey: Uint8Array;
  usedOneTimePreKeyId?: string;
}

/**
 * Initiates an X3DH handshake as the sender.
 */
export function initializeSenderSession(
  senderIdentityPrivateKey: Uint8Array,
  bundle: PreKeyBundle
): SenderHandshakeResult {
  // 1. Verify Signed PreKey Signature
  const valid = verify(
    bundle.identityPublicKey,
    bundle.signedPreKeyPublicKey,
    bundle.signedPreKeySignature
  );
  if (!valid) throw new Error('Invalid Signed PreKey signature');

  // 2. Generate Ephemeral Key Pair
  const ephemeral = generateEphemeralKeyPair();

  // 3. Perform DH exchanges
  // DH1 = DH(IK_A, SPK_B)
  // DH2 = DH(EK_A, IK_B)
  // DH3 = DH(EK_A, SPK_B)
  const dhValues = [
    calculateX25519(senderIdentityPrivateKey, bundle.signedPreKeyPublicKey),
    calculateX25519(ephemeral.privateKey, bundle.identityPublicKey),
    calculateX25519(ephemeral.privateKey, bundle.signedPreKeyPublicKey),
  ];

  // DH4 = DH(EK_A, OPK_B) (optional)
  if (bundle.oneTimePreKeyPublicKey) {
    dhValues.push(calculateX25519(ephemeral.privateKey, bundle.oneTimePreKeyPublicKey));
  }

  // 4. Calculate Shared Secret
  const sharedSecret = signalKdf(dhValues);

  return {
    sharedSecret,
    ephemeralPublicKey: ephemeral.publicKey,
    usedOneTimePreKeyId: bundle.oneTimePreKeyId,
  };
}

/**
 * Responds to an X3DH handshake as the receiver.
 */
export function initializeReceiverSession(
  receiverIdentityPrivateKey: Uint8Array,
  receiverSignedPreKeyPrivateKey: Uint8Array,
  receiverOneTimePreKeyPrivateKey: Uint8Array | null,
  senderIdentityPublicKey: Uint8Array,
  senderEphemeralPublicKey: Uint8Array
): Uint8Array {
  // DH1 = DH(SPK_B, IK_A)
  // DH2 = DH(IK_B, EK_A)
  // DH3 = DH(SPK_B, EK_A)
  const dhValues = [
    calculateX25519(receiverSignedPreKeyPrivateKey, senderIdentityPublicKey),
    calculateX25519(receiverIdentityPrivateKey, senderEphemeralPublicKey),
    calculateX25519(receiverSignedPreKeyPrivateKey, senderEphemeralPublicKey),
  ];

  // DH4 = DH(OPK_B, EK_A) (optional)
  if (receiverOneTimePreKeyPrivateKey) {
    dhValues.push(calculateX25519(receiverOneTimePreKeyPrivateKey, senderEphemeralPublicKey));
  }

  return signalKdf(dhValues);
}

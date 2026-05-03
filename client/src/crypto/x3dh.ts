import { calculateX25519, hkdfSha256, sign, verify } from './signalCrypto';
import { generateEphemeralKeyPair } from './signalKeys';

const X3DH_INFO = new TextEncoder().encode('X3DH');

/**
 * Signal X3DH KDF: SK = HKDF(DH1 || DH2 || DH3 || DH4)
 * Note: DH4 is optional if One-Time Pre-Key is not used.
 */
function signalKdf(dhValues: Uint8Array[]): Uint8Array {
  const totalLength = dhValues.reduce((acc, v) => acc + v.length, 0);
  const keyMaterial = new Uint8Array(totalLength);
  let offset = 0;
  for (const v of dhValues) {
    keyMaterial.set(v, offset);
    offset += v.length;
  }
  return hkdfSha256(keyMaterial, undefined, X3DH_INFO);
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

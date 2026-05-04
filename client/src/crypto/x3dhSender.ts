import { calculateX25519, verify } from './signalCrypto';
import { generateEphemeralKeyPair } from './signalKeys';
import { signalKdf } from './x3dhKdf';
import type { PreKeyBundle, SenderHandshakeResult } from './x3dhTypes';

export function initializeSenderSession(
  senderIdentityPrivateKey: Uint8Array,
  bundle: PreKeyBundle,
): SenderHandshakeResult {
  const valid = verify(
    bundle.identityPublicKey,
    bundle.signedPreKeyPublicKey,
    bundle.signedPreKeySignature,
  );
  if (!valid) throw new Error('Invalid Signed PreKey signature');
  const ephemeral = generateEphemeralKeyPair();
  const dhValues = [
    calculateX25519(senderIdentityPrivateKey, bundle.signedPreKeyPublicKey),
    calculateX25519(ephemeral.privateKey, bundle.identityPublicKey),
    calculateX25519(ephemeral.privateKey, bundle.signedPreKeyPublicKey),
  ];
  if (bundle.oneTimePreKeyPublicKey) {
    dhValues.push(calculateX25519(ephemeral.privateKey, bundle.oneTimePreKeyPublicKey));
  }
  return {
    sharedSecret: signalKdf(dhValues),
    ephemeralPublicKey: ephemeral.publicKey,
    ephemeralPrivateKey: ephemeral.privateKey,
    usedOneTimePreKeyId: bundle.oneTimePreKeyId,
    dh1: dhValues[0],
    dh2: dhValues[1],
    dh3: dhValues[2],
    dh4: dhValues[3],
  };
}

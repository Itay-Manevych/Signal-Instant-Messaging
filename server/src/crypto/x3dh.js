import { generateEphemeralKeyPair } from './signalKeys.js';
import { hkdfSha256, sign, verify, x25519 } from './signalCrypto.js';

const X3DH_INFO = 'WhisperText';
const X25519_KDF_PREFIX = Buffer.alloc(32, 0xff);

function need(value, name) {
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}

function bytes(value) {
  return Buffer.isBuffer(value) ? value : Buffer.from(value, 'base64');
}

function signalKdf(dhValues) {
  const keyMaterial = Buffer.concat([X25519_KDF_PREFIX, ...dhValues.map(bytes)])
    .toString('base64');
  return hkdfSha256(keyMaterial, '', X3DH_INFO);
}

function findOneTimePreKey(receiverKeys, preKeyId) {
  if (!preKeyId) return null;
  const keys = [receiverKeys.oneTimePreKey, ...(receiverKeys.oneTimePreKeys ?? [])]
    .filter(Boolean);
  return keys.find((key) => key.id === preKeyId) ?? null;
}

export function createReceiverPreKeyBundle(receiverKeys) {
  const identityKeyPair = need(receiverKeys.identityKeyPair, 'identityKeyPair');
  const signedPreKeyPair = need(receiverKeys.signedPreKeyPair, 'signedPreKeyPair');
  const oneTimePreKey = receiverKeys.oneTimePreKey ?? receiverKeys.oneTimePreKeys?.[0];

  return {
    receiverIdentityPublicKey: need(identityKeyPair.publicKey, 'identity public key'),
    receiverSignedPreKeyPublicKey: need(signedPreKeyPair.publicKey, 'signed prekey public key'),
    signedPreKeySignature: receiverKeys.signedPreKeySignature
      ?? sign(need(identityKeyPair.privateKey, 'identity private key'), signedPreKeyPair.publicKey),
    oneTimePreKeyId: oneTimePreKey?.id,
    oneTimePreKeyPublicKey: oneTimePreKey?.publicKey,
  };
}

export function initializeSenderSession(senderKeys, receiverPreKeyBundle) {
  const senderIdentity = need(senderKeys.identityKeyPair, 'sender identityKeyPair');
  const receiverIdentityPublicKey = need(receiverPreKeyBundle.receiverIdentityPublicKey, 'receiver identity public key');
  const receiverSignedPreKeyPublicKey = need(receiverPreKeyBundle.receiverSignedPreKeyPublicKey, 'receiver signed prekey public key');

  const validSignature = verify(
    receiverIdentityPublicKey,
    receiverSignedPreKeyPublicKey,
    need(receiverPreKeyBundle.signedPreKeySignature, 'signed prekey signature'),
  );
  if (!validSignature) throw new Error('Invalid receiver signed prekey signature');

  const senderEphemeral = generateEphemeralKeyPair();
  const dhValues = [
    x25519(need(senderIdentity.privateKey, 'sender identity private key'), receiverSignedPreKeyPublicKey),
    x25519(senderEphemeral.privateKey, receiverIdentityPublicKey),
    x25519(senderEphemeral.privateKey, receiverSignedPreKeyPublicKey),
  ];

  if (receiverPreKeyBundle.oneTimePreKeyPublicKey) {
    dhValues.push(x25519(senderEphemeral.privateKey, receiverPreKeyBundle.oneTimePreKeyPublicKey));
  }

  return {
    sharedSecret: signalKdf(dhValues),
    senderEphemeralPublicKey: senderEphemeral.publicKey,
    usedOneTimePreKeyId: receiverPreKeyBundle.oneTimePreKeyId,
  };
}

export function initializeReceiverSession(receiverKeys, senderInitialMessage) {
  const identityKeyPair = need(receiverKeys.identityKeyPair, 'receiver identityKeyPair');
  const signedPreKeyPair = need(receiverKeys.signedPreKeyPair, 'receiver signedPreKeyPair');
  const senderIdentityPublicKey = need(senderInitialMessage.senderIdentityPublicKey, 'sender identity public key');
  const senderEphemeralPublicKey = need(senderInitialMessage.senderEphemeralPublicKey, 'sender ephemeral public key');
  const oneTimePreKey = findOneTimePreKey(receiverKeys, senderInitialMessage.usedOneTimePreKeyId);
  const dhValues = [
    x25519(need(signedPreKeyPair.privateKey, 'signed prekey private key'), senderIdentityPublicKey),
    x25519(need(identityKeyPair.privateKey, 'receiver identity private key'), senderEphemeralPublicKey),
    x25519(signedPreKeyPair.privateKey, senderEphemeralPublicKey),
  ];

  if (senderInitialMessage.usedOneTimePreKeyId) {
    dhValues.push(x25519(need(oneTimePreKey?.privateKey, 'one-time prekey private key'), senderEphemeralPublicKey));
  }

  return { sharedSecret: signalKdf(dhValues) };
}

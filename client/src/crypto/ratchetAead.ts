import { fromBase64, toBase64 } from './signalKeys';

function encode(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export async function encryptAead(messageKeyB64: string, plaintext: string, associatedData: string) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey('raw', fromBase64(messageKeyB64), 'AES-GCM', false, ['encrypt']);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: encode(associatedData) },
    key,
    encode(plaintext),
  );
  return { ciphertextB64: toBase64(new Uint8Array(ciphertext)), nonceB64: toBase64(nonce) };
}

export async function decryptAead(
  messageKeyB64: string,
  ciphertextB64: string,
  nonceB64: string,
  associatedData: string,
) {
  const key = await crypto.subtle.importKey('raw', fromBase64(messageKeyB64), 'AES-GCM', false, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(nonceB64), additionalData: encode(associatedData) },
    key,
    fromBase64(ciphertextB64),
  );
  return new TextDecoder().decode(plaintext);
}

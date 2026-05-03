import { toBase64, randomBytes } from './signalCrypto';

export async function aesEncrypt(key: Uint8Array, plaintext: Uint8Array): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
  const iv = randomBytes(12);
  console.log('🔒 AES Encrypt (DEBUG: Temporary): Key=', toBase64(key).slice(0, 8) + '...', 'IV=', toBase64(iv));
  const cryptoKey = await crypto.subtle.importKey('raw', key as any, { name: 'AES-GCM' }, false, ['encrypt']);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as any }, cryptoKey, plaintext as any);
  return { ciphertext: new Uint8Array(encrypted), iv };
}

export async function aesDecrypt(key: Uint8Array, ciphertext: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
  console.log('🔓 AES Decrypt (DEBUG: Temporary): Key=', toBase64(key).slice(0, 8) + '...', 'IV=', toBase64(iv));
  try {
    const cryptoKey = await crypto.subtle.importKey('raw', key as any, { name: 'AES-GCM' }, false, ['decrypt']);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as any }, cryptoKey, ciphertext as any);
    return new Uint8Array(decrypted);
  } catch (err) {
    console.error('🔓 AES Decrypt Error:', err);
    if (err instanceof Error && err.name === 'OperationError') {
      throw new Error('Decryption failed: Integrity check failed (wrong key or corrupted data)');
    }
    throw err;
  }
}

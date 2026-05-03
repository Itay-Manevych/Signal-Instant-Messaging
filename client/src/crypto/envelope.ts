import type { ChatEnvelope } from '../protocol';
import { loadStoredAccountKeys } from './localAccountKeys';

type LocalKeys = {
  identityKey?: { publicKeyB64?: string };
};

// utf8 is regular text format
function utf8ToBase64(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function devBase64ToUtf8(value: string): string {
  const binary = atob(value);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}


// load users Indentity Key from browser localStorage (will be changed to be stored in server in the future)
export function loadSenderIdentityKeyB64(userId: string): string {
  const parsed = loadStoredAccountKeys(userId) as LocalKeys | null;
  return parsed?.identityKey?.publicKeyB64 ?? 'dev-missing-identity-key';
}

export function createDevEnvelope(
  plaintext: string,
  envelope: Pick<ChatEnvelope, 'kind' | 'senderIdentityKeyB64'> & Partial<ChatEnvelope>,
): ChatEnvelope {
  return {
    version: 1,
    kind: envelope.kind,
    senderIdentityKeyB64: envelope.senderIdentityKeyB64,
    senderEphemeralKeyB64: envelope.senderEphemeralKeyB64,
    usedOneTimePreKeyId: envelope.usedOneTimePreKeyId,
    ratchetHeader: envelope.ratchetHeader,
    // TODO: Replace this dev placeholder with Double Ratchet AEAD ciphertext.
    ciphertextB64: utf8ToBase64(plaintext),
    nonceB64: envelope.nonceB64,
  };
}

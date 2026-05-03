import type { ChatEnvelope } from '../protocol';

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
  try {
    const raw = localStorage.getItem(`signal-keys-${userId}`);
    if (!raw) return 'dev-missing-identity-key';
    const parsed = JSON.parse(raw) as LocalKeys;
    return parsed.identityKey?.publicKeyB64 ?? 'dev-missing-identity-key';
  } catch {
    return 'dev-missing-identity-key';
  }
}

export function createDevEnvelope(plaintext: string, senderIdentityKeyB64: string): ChatEnvelope {
  return {
    version: 1,
    kind: 'initial',
    senderIdentityKeyB64,
    // TODO: Replace this dev placeholder with Double Ratchet AEAD ciphertext.
    ciphertextB64: utf8ToBase64(plaintext),
  };
}


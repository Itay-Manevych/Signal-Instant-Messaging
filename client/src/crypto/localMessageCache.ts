import type { ChatEnvelope } from '../protocol';

type MessageCache = Record<string, string>;

const msgKey = (userId: string) => `signal-message-cache-${userId}`;
const pendingKey = (userId: string) => `signal-pending-cache-${userId}`;

function load(key: string): MessageCache {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as MessageCache) : {};
  } catch {
    return {};
  }
}

function save(key: string, cache: MessageCache): void {
  localStorage.setItem(key, JSON.stringify(cache));
}

function fingerprint(envelope: ChatEnvelope): string {
  return `${envelope.kind}:${envelope.ciphertextB64}:${envelope.nonceB64 ?? ''}`;
}

export function rememberOutgoingPlaintext(userId: string, envelope: ChatEnvelope, plaintext: string): void {
  const cache = load(pendingKey(userId));
  cache[fingerprint(envelope)] = plaintext;
  save(pendingKey(userId), cache);
}

export function consumeOutgoingPlaintext(userId: string, envelope: ChatEnvelope): string | null {
  const cache = load(pendingKey(userId));
  const key = fingerprint(envelope);
  const plaintext = cache[key] ?? null;
  delete cache[key];
  save(pendingKey(userId), cache);
  return plaintext;
}

export function saveMessagePlaintext(userId: string, messageId: string, plaintext: string): void {
  const cache = load(msgKey(userId));
  cache[messageId] = plaintext;
  save(msgKey(userId), cache);
}

export function loadMessagePlaintext(userId: string, messageId: string): string | null {
  return load(msgKey(userId))[messageId] ?? null;
}

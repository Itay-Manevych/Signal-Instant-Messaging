/** Plain JSON transport. Envelopes are opaque to the server. */

export type RatchetHeader = {
  senderRatchetPublicKeyB64: string;
  previousSendingChainLength: number;
  messageNumber: number;
};

export type ChatEnvelope = {
  version: 1;
  kind: 'initial' | 'ratchet';
  senderIdentityKeyB64: string;
  senderEphemeralKeyB64?: string;
  usedOneTimePreKeyId?: string;
  ratchetHeader?: RatchetHeader;
  ciphertextB64: string;
  nonceB64?: string;
};

export function isChatEnvelope(value: unknown): value is ChatEnvelope {
  if (!value || typeof value !== 'object') return false;
  const e = value as Partial<ChatEnvelope>;
  if (e.version !== 1) return false;
  if (e.kind !== 'initial' && e.kind !== 'ratchet') return false;
  if (typeof e.senderIdentityKeyB64 !== 'string' || !e.senderIdentityKeyB64) return false;
  if (typeof e.ciphertextB64 !== 'string' || !e.ciphertextB64) return false;
  if (e.senderEphemeralKeyB64 !== undefined && typeof e.senderEphemeralKeyB64 !== 'string') return false;
  if (e.usedOneTimePreKeyId !== undefined && typeof e.usedOneTimePreKeyId !== 'string') return false;
  if (e.nonceB64 !== undefined && typeof e.nonceB64 !== 'string') return false;
  if (e.ratchetHeader === undefined) return true;
  const h = e.ratchetHeader as Partial<RatchetHeader> & { dh?: string; pn?: number; n?: number };
  const dh = h.senderRatchetPublicKeyB64 ?? h.dh;
  const pn = h.previousSendingChainLength ?? h.pn;
  const n = h.messageNumber ?? h.n;
  return (
    typeof dh === 'string' &&
    Number.isSafeInteger(pn) &&
    Number.isSafeInteger(n) &&
    typeof pn === 'number' &&
    typeof n === 'number' &&
    pn >= 0 &&
    n >= 0
  );
}

export type WsClientMessage =
  | { type: 'ping' }
  | { type: 'chat'; toUserId: string; text: string }
  | { type: 'chat'; toUserId: string; envelope: ChatEnvelope };

export type WsServerMessage =
  | { type: 'connected'; userId: string; username: string }
  | { type: 'pong' }
  | { type: 'presence'; online: { userId: string; username: string }[] }
  | {
      type: 'chat';
      id: string;
      fromUserId: string;
      fromUsername: string;
      toUserId: string;
      text?: string;
      envelope?: ChatEnvelope;
      sentAt: string;
    }
  | { type: 'error'; message: string };

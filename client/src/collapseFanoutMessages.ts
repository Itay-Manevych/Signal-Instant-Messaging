import type { WsServerMessage } from './protocol';

type ChatMsg = Extract<WsServerMessage, { type: 'chat' }>;

/** One logical send can fan out to several devices (different ciphertext each). Collapse to one row for UI. */
export function collapseFanoutMessages(messages: ChatMsg[]): ChatMsg[] {
  const sorted = [...messages].sort((a, b) => a.sentAt.localeCompare(b.sentAt));
  const groups = new Map<string, ChatMsg[]>();
  const order: string[] = [];
  for (const m of sorted) {
    const key = fanoutKey(m);
    if (!groups.has(key)) order.push(key);
    const list = groups.get(key) ?? [];
    list.push(m);
    groups.set(key, list);
  }
  const out: ChatMsg[] = [];
  for (const key of order) {
    const list = groups.get(key)!;
    if (list.length === 1) {
      out.push(list[0]);
      continue;
    }
    out.push(pickBestDuplicate(list));
  }
  return out.sort((a, b) => a.sentAt.localeCompare(b.sentAt));
}

function fanoutKey(m: ChatMsg): string {
  if (!m.clientMessageId) return `id:${m.id}`;
  // Do not include toDeviceId: one logical send fans out to many recipient devices (same ciphertext group).
  const peerId = m.syncPeerUserId ?? m.toUserId;
  return [
    'cm',
    m.clientMessageId,
    m.fromUserId,
    peerId,
    m.fromDeviceId ?? '',
  ].join(':');
}

function pickBestDuplicate(list: ChatMsg[]): ChatMsg {
  const withText = list.find((m) => m.text?.trim());
  if (withText) return withText;
  const noEnvelope = list.find((m) => !m.envelope);
  if (noEnvelope) return noEnvelope;
  return { ...list[0], toDeviceId: undefined };
}

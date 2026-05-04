import type { ChatEnvelope } from '../protocol';
import { authHeaders, readJsonOrThrow } from './http';

export type ConversationMessage = {
  id: string;
  fromUserId: string;
  fromUsername: string;
  fromDeviceId?: string;
  toUserId: string;
  toDeviceId?: string;
  sesameSessionId?: string;
  clientMessageId?: string;
  syncPeerUserId?: string;
  text?: string;
  envelope?: ChatEnvelope;
  sentAt: string;
};

export async function fetchConversation(token: string, peerId: string, deviceId?: string, deviceSecret?: string): Promise<ConversationMessage[]> {
  const params = new URLSearchParams();
  if (deviceId) params.set('deviceId', deviceId);
  if (deviceSecret) params.set('deviceSecret', deviceSecret);
  const suffix = params.toString() ? `?${params}` : '';
  const response = await fetch(`/api/messages/${encodeURIComponent(peerId)}${suffix}`, {
    headers: authHeaders(token),
  });
  const data = await readJsonOrThrow(response);
  if (
    !data ||
    typeof data !== 'object' ||
    !('messages' in data) ||
    !Array.isArray((data as { messages: unknown }).messages)
  ) {
    throw new Error('Invalid response');
  }
  return (data as { messages: ConversationMessage[] }).messages;
}


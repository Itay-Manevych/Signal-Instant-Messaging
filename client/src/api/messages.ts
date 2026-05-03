import type { ChatEnvelope } from '../protocol';
import { authHeaders, readJsonOrThrow } from './http';

export type ConversationMessage = {
  id: string;
  fromUserId: string;
  fromUsername: string;
  toUserId: string;
  text?: string;
  envelope?: ChatEnvelope;
  sentAt: string;
};

export async function fetchConversation(token: string, peerId: string): Promise<ConversationMessage[]> {
  const response = await fetch(`/api/messages/${encodeURIComponent(peerId)}`, {
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


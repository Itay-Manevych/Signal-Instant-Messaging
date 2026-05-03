import type { WsServerMessage } from './protocol';

export interface Session {
  token: string;
  userId: string;
  username: string;
}

export type ChatMessage = Extract<WsServerMessage, { type: 'chat' }>;

export type Theme = 'dark' | 'light';

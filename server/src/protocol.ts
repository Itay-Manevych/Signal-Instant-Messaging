/** Plain JSON messages over WebSocket (not end-to-end encrypted yet). */

export type WsClientMessage =
  | { type: 'ping' }
  | { type: 'chat'; toUserId: string; text: string };

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
      text: string;
      sentAt: string;
    }
  | { type: 'error'; message: string };

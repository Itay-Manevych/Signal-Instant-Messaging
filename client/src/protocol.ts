/** Mirrors server WebSocket message shapes (plaintext until E2EE is added). */

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
      ciphertext?: string;
      header?: {
        dhPublicKeyB64: string;
        pn: number;
        n: number;
        ivB64: string;
        x3dh?: {
          identityKeyB64: string;
          ephemeralKeyB64: string;
          oneTimePreKeyId?: string;
        };
      };
      sentAt: string;
    }
  | { type: 'error'; message: string };

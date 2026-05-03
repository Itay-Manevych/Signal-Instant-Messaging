/** E2EE Messages over WebSocket. */

export interface RatchetHeaderB64 {
  dhPublicKeyB64: string;
  pn: number; // previous chain length
  n: number;  // message index
  ivB64: string; // AES-GCM IV
  /** Optional X3DH handshake data (only sent in the very first message) */
  x3dh?: {
    identityKeyB64: string;
    ephemeralKeyB64: string;
    oneTimePreKeyId?: number;
  };
}

export type WsClientMessage =
  | { type: 'ping' }
  | { 
      type: 'chat'; 
      toUserId: string; 
      text?: string; // legacy plaintext
      ciphertext?: string; 
      header?: RatchetHeaderB64;
    };

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
      text?: string; // legacy plaintext
      ciphertext?: string;
      header?: RatchetHeaderB64;
      sentAt: string;
    }
  | { type: 'error'; message: string };

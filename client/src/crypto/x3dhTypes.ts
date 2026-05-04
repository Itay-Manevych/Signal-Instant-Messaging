export interface PreKeyBundle {
  identityPublicKey: Uint8Array;
  signedPreKeyPublicKey: Uint8Array;
  signedPreKeySignature: Uint8Array;
  oneTimePreKeyId?: string;
  oneTimePreKeyPublicKey?: Uint8Array;
}

export interface SenderHandshakeResult {
  sharedSecret: Uint8Array;
  ephemeralPublicKey: Uint8Array;
  ephemeralPrivateKey?: Uint8Array;
  usedOneTimePreKeyId?: string;
  dh1?: Uint8Array;
  dh2?: Uint8Array;
  dh3?: Uint8Array;
  dh4?: Uint8Array;
}

export interface ReceiverHandshakeResult {
  sharedSecret: Uint8Array;
  dh1: Uint8Array;
  dh2: Uint8Array;
  dh3: Uint8Array;
  dh4?: Uint8Array;
}

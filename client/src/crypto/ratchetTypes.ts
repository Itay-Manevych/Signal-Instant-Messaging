export type RatchetHeader = {
  senderRatchetPublicKeyB64: string;
  previousSendingChainLength: number;
  messageNumber: number;
};

export type RatchetState = {
  rootKeyB64: string;
  sendingChainKeyB64?: string;
  receivingChainKeyB64?: string;
  selfRatchetPrivateKeyB64: string;
  selfRatchetPublicKeyB64: string;
  remoteRatchetPublicKeyB64?: string;
  sentMessageCount: number;
  receivedMessageCount: number;
  previousSendingChainLength: number;
  skippedMessageKeys: Record<string, string>;
};

export type RatchetEncryptResult = {
  state: RatchetState;
  header: RatchetHeader;
  ciphertextB64: string;
  nonceB64: string;
};

export type RatchetDecryptResult = {
  state: RatchetState;
  plaintext: string;
};

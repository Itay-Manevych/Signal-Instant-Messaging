export type DeviceAddress = {
  userId: string;
  deviceId: string;
};

export type SesameSession = {
  sessionId: string;
  peer: DeviceAddress;
  peerIdentityKeyB64: string;
  sharedSecretB64?: string;
  ratchetState?: unknown;
  createdAt: string;
  updatedAt: string;
  active: boolean;
};

export type SesameStore = {
  userId: string;
  deviceId: string;
  sessions: Record<string, SesameSession>;
  active: Record<string, string>;
};

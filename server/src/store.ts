import { randomUUID } from 'node:crypto';
import { createHash } from 'node:crypto';
import bcrypt from 'bcryptjs';
import type { Db } from './db.js';
import { isChatEnvelope, type ChatEnvelope } from './protocol.js';

export type PublicUser = { id: string; username: string };
export type IdentityKeyPublic = { keyType: 'x25519'; publicKeyB64: string };
export type PendingChatMessage = {
  id: string;
  fromUserId: string;
  fromUsername: string;
  fromDeviceId?: string;
  toUserId: string;
  toDeviceId?: string;
  sesameSessionId?: string;
  clientMessageId?: string;
  syncPeerUserId?: string;
  senderVisible?: boolean;
  text?: string;
  envelope?: ChatEnvelope;
  sentAt: string;
};

export type SignedPreKeyPublic = {
  publicKeyB64: string;
  signatureB64: string;
};

export type OneTimePreKeyPublic = {
  id: string;
  publicKeyB64: string;
};

export type PreKeyBundle = {
  identityKey: IdentityKeyPublic;
  signedPreKey: SignedPreKeyPublic;
  oneTimePreKey?: OneTimePreKeyPublic;
};

export type DeviceRecord = { userId: string; deviceId: string; name: string; createdAt?: string; lastSeenAt?: string };
export type DevicePreKeyBundle = PreKeyBundle & { userId: string; deviceId: string };

function hashDeviceSecret(secret: string): string {
  return createHash('sha256').update(secret).digest('hex');
}

type UserRecord = {
  id: string;
  username: string;
  passwordHash: string;
};

function parseEnvelope(json: string | null): ChatEnvelope | undefined {
  if (!json) return undefined;
  try {
    const parsed = JSON.parse(json) as unknown;
    return isChatEnvelope(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function rowToMessage(row: PendingChatMessage & { envelopeJson: string | null }): PendingChatMessage {
  const envelope = parseEnvelope(row.envelopeJson);
  return {
    id: row.id,
    fromUserId: row.fromUserId,
    fromUsername: row.fromUsername,
    ...(row.fromDeviceId ? { fromDeviceId: row.fromDeviceId } : {}),
    toUserId: row.toUserId,
    ...(row.toDeviceId ? { toDeviceId: row.toDeviceId } : {}),
    ...(row.sesameSessionId ? { sesameSessionId: row.sesameSessionId } : {}),
    ...(row.clientMessageId ? { clientMessageId: row.clientMessageId } : {}),
    ...(row.syncPeerUserId ? { syncPeerUserId: row.syncPeerUserId } : {}),
    ...(row.text ? { text: row.text } : {}),
    ...(envelope ? { envelope } : {}),
    sentAt: row.sentAt,
  };
}

export class UserStore {
  constructor(private db: Db) {}

  private normalizeUsername(username: string): string {
    return username.trim().toLowerCase();
  }

  async register(username: string, password: string): Promise<PublicUser> {
    const id = randomUUID();
    const passwordHash = await bcrypt.hash(password, 10);
    const usernameTrimmed = username.trim();
    const normalized = this.normalizeUsername(usernameTrimmed);
    try {
      this.db
        .prepare(
          `
          INSERT INTO users (id, username_norm, username, password_hash, created_at)
          VALUES (@id, @username_norm, @username, @password_hash, @created_at)
        `,
        )
        .run({
          id,
          username_norm: normalized,
          username: usernameTrimmed,
          password_hash: passwordHash,
          created_at: new Date().toISOString(),
        });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.toLowerCase().includes('unique')) {
        throw new Error('Username already taken');
      }
      throw e;
    }
    return { id, username: usernameTrimmed };
  }

  async verifyPassword(username: string, password: string): Promise<PublicUser | null> {
    const normalized = this.normalizeUsername(username);
    const row = this.db
      .prepare(
        `
        SELECT id, username, password_hash AS passwordHash
        FROM users
        WHERE username_norm = ?
        LIMIT 1
      `,
      )
      .get(normalized) as UserRecord | undefined;
    if (!row) return null;
    const ok = await bcrypt.compare(password, row.passwordHash);
    if (!ok) return null;
    return { id: row.id, username: row.username };
  }

  getById(id: string): PublicUser | null {
    const row = this.db
      .prepare(
        `
        SELECT id, username
        FROM users
        WHERE id = ?
        LIMIT 1
      `,
      )
      .get(id) as { id: string; username: string } | undefined;
    return row ?? null;
  }

  listUsers(): PublicUser[] {
    const rows = this.db
      .prepare(
        `
        SELECT id, username
        FROM users
        ORDER BY username_norm ASC
      `,
      )
      .all() as { id: string; username: string }[];
    return rows;
  }

  getIdByUsername(username: string): string | null {
    const normalized = this.normalizeUsername(username);
    const row = this.db
      .prepare('SELECT id FROM users WHERE username_norm = ? LIMIT 1')
      .get(normalized) as { id: string } | undefined;
    return row?.id ?? null;
  }

  upsertDevice(userId: string, deviceId: string, name = 'Browser', deviceSecret?: string): DeviceRecord {
    const now = new Date().toISOString();
    this.db.prepare(`
      INSERT INTO devices (user_id, device_id, name, device_secret_hash, created_at, last_seen_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(user_id, device_id) DO UPDATE SET
        name = excluded.name,
        device_secret_hash = COALESCE(excluded.device_secret_hash, devices.device_secret_hash),
        last_seen_at = excluded.last_seen_at
    `).run(userId, deviceId, name, deviceSecret ? hashDeviceSecret(deviceSecret) : null, now, now);
    return { userId, deviceId, name };
  }

  verifyDeviceSecret(userId: string, deviceId: string, deviceSecret: string): boolean {
    const row = this.db.prepare(`
      SELECT device_secret_hash AS deviceSecretHash
      FROM devices
      WHERE user_id = ? AND device_id = ?
      LIMIT 1
    `).get(userId, deviceId) as { deviceSecretHash: string | null } | undefined;
    return Boolean(row?.deviceSecretHash && row.deviceSecretHash === hashDeviceSecret(deviceSecret));
  }

  listDevices(userId: string): DeviceRecord[] {
    return this.db.prepare(`
      SELECT
        user_id AS userId,
        device_id AS deviceId,
        name,
        created_at AS createdAt,
        last_seen_at AS lastSeenAt
      FROM devices
      WHERE user_id = ?
      ORDER BY created_at ASC
    `).all(userId) as DeviceRecord[];
  }

  touchDevice(userId: string, deviceId: string): void {
    this.db.prepare(`
      UPDATE devices SET last_seen_at = ? WHERE user_id = ? AND device_id = ?
    `).run(new Date().toISOString(), userId, deviceId);
  }

  upsertIdentityKey(userId: string, key: IdentityKeyPublic): void {
    this.db
      .prepare(
        `
        INSERT INTO identity_keys (user_id, key_type, public_key_b64, updated_at)
        VALUES (@user_id, @key_type, @public_key_b64, @updated_at)
        ON CONFLICT(user_id)
        DO UPDATE SET
          key_type = excluded.key_type,
          public_key_b64 = excluded.public_key_b64,
          updated_at = excluded.updated_at
      `,
      )
      .run({
        user_id: userId,
        key_type: key.keyType,
        public_key_b64: key.publicKeyB64,
        updated_at: new Date().toISOString(),
      });
  }

  getIdentityKey(userId: string): IdentityKeyPublic | null {
    const row = this.db
      .prepare(
        `
        SELECT key_type AS keyType, public_key_b64 AS publicKeyB64
        FROM identity_keys
        WHERE user_id = ?
        LIMIT 1
      `,
      )
      .get(userId) as { keyType: string; publicKeyB64: string } | undefined;
    if (!row) return null;
    if (row.keyType !== 'x25519') return null;
    return { keyType: 'x25519', publicKeyB64: row.publicKeyB64 };
  }

  upsertSignedPreKey(userId: string, key: SignedPreKeyPublic): void {
    this.db
      .prepare(
        `
        INSERT INTO signed_prekeys (user_id, public_key_b64, signature_b64, created_at)
        VALUES (@user_id, @public_key_b64, @signature_b64, @created_at)
        ON CONFLICT(user_id)
        DO UPDATE SET
          public_key_b64 = excluded.public_key_b64,
          signature_b64 = excluded.signature_b64,
          created_at = excluded.created_at
      `,
      )
      .run({
        user_id: userId,
        public_key_b64: key.publicKeyB64,
        signature_b64: key.signatureB64,
        created_at: new Date().toISOString(),
      });
  }

  addOneTimePreKeys(userId: string, keys: OneTimePreKeyPublic[]): void {
    const insert = this.db.prepare(`
      INSERT INTO one_time_prekeys (key_id, user_id, public_key_b64, created_at)
      VALUES (?, ?, ?, ?)
    `);

    const createdAt = new Date().toISOString();
    const transaction = this.db.transaction((items: OneTimePreKeyPublic[]) => {
      for (const key of items) {
        insert.run(key.id, userId, key.publicKeyB64, createdAt);
      }
    });

    transaction(keys);
  }

  publishDeviceKeys(userId: string, deviceId: string, deviceSecret: string | undefined, key: {
    identityKey: IdentityKeyPublic;
    signedPreKey: SignedPreKeyPublic;
    oneTimePreKeys: OneTimePreKeyPublic[];
  }): void {
    this.upsertDevice(userId, deviceId, 'Browser', deviceSecret);
    const now = new Date().toISOString();
    this.db.prepare(`
      INSERT INTO device_identity_keys (user_id, device_id, key_type, public_key_b64, updated_at)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(user_id, device_id) DO UPDATE SET
        key_type = excluded.key_type,
        public_key_b64 = excluded.public_key_b64,
        updated_at = excluded.updated_at
    `).run(userId, deviceId, key.identityKey.keyType, key.identityKey.publicKeyB64, now);
    this.db.prepare(`
      INSERT INTO device_signed_prekeys (user_id, device_id, public_key_b64, signature_b64, created_at)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(user_id, device_id) DO UPDATE SET
        public_key_b64 = excluded.public_key_b64,
        signature_b64 = excluded.signature_b64,
        created_at = excluded.created_at
    `).run(userId, deviceId, key.signedPreKey.publicKeyB64, key.signedPreKey.signatureB64, now);
    this.addDeviceOneTimePreKeys(userId, deviceId, key.oneTimePreKeys);
  }

  addDeviceOneTimePreKeys(userId: string, deviceId: string, keys: OneTimePreKeyPublic[]): void {
    const insert = this.db.prepare(`
      INSERT INTO device_one_time_prekeys (key_id, user_id, device_id, public_key_b64, created_at)
      VALUES (?, ?, ?, ?, ?)
    `);
    const createdAt = new Date().toISOString();
    const transaction = this.db.transaction((items: OneTimePreKeyPublic[]) => {
      for (const key of items) insert.run(key.id, userId, deviceId, key.publicKeyB64, createdAt);
    });
    transaction(keys);
  }

  getPreKeyBundle(userId: string): PreKeyBundle | null {
    const identityKey = this.getIdentityKey(userId);
    if (!identityKey) return null;

    const signedPreKey = this.db
      .prepare(
        `
        SELECT public_key_b64 AS publicKeyB64, signature_b64 AS signatureB64
        FROM signed_prekeys
        WHERE user_id = ?
        LIMIT 1
      `,
      )
      .get(userId) as SignedPreKeyPublic | undefined;

    if (!signedPreKey) return null;

    // Fetch one random one-time prekey
    const otpk = this.db
      .prepare(
        `
        SELECT id, public_key_b64 AS publicKeyB64
        , COALESCE(key_id, CAST(id AS TEXT)) AS keyId
        FROM one_time_prekeys
        WHERE user_id = ?
        ORDER BY key_id IS NULL, RANDOM()
        LIMIT 1
      `,
      )
      .get(userId) as { id: number; keyId: string; publicKeyB64: string } | undefined;

    // If we found one, delete it so it's truly "one-time"
    if (otpk) {
      this.db.prepare(`DELETE FROM one_time_prekeys WHERE id = ?`).run(otpk.id);
    }

    return {
      identityKey,
      signedPreKey,
      oneTimePreKey: otpk ? { id: otpk.keyId, publicKeyB64: otpk.publicKeyB64 } : undefined,
    };
  }

  getDevicePreKeyBundle(userId: string, deviceId: string): DevicePreKeyBundle | null {
    const identityKey = this.db.prepare(`
      SELECT key_type AS keyType, public_key_b64 AS publicKeyB64
      FROM device_identity_keys
      WHERE user_id = ? AND device_id = ?
      LIMIT 1
    `).get(userId, deviceId) as IdentityKeyPublic | undefined;
    const signedPreKey = this.db.prepare(`
      SELECT public_key_b64 AS publicKeyB64, signature_b64 AS signatureB64
      FROM device_signed_prekeys
      WHERE user_id = ? AND device_id = ?
      LIMIT 1
    `).get(userId, deviceId) as SignedPreKeyPublic | undefined;
    if (!identityKey || identityKey.keyType !== 'x25519' || !signedPreKey) return null;
    const otpk = this.db.prepare(`
      SELECT id, key_id AS keyId, public_key_b64 AS publicKeyB64
      FROM device_one_time_prekeys
      WHERE user_id = ? AND device_id = ?
      ORDER BY RANDOM()
      LIMIT 1
    `).get(userId, deviceId) as { id: number; keyId: string; publicKeyB64: string } | undefined;
    if (otpk) this.db.prepare(`DELETE FROM device_one_time_prekeys WHERE id = ?`).run(otpk.id);
    return {
      userId,
      deviceId,
      identityKey,
      signedPreKey,
      oneTimePreKey: otpk ? { id: otpk.keyId, publicKeyB64: otpk.publicKeyB64 } : undefined,
    };
  }

  listDevicePreKeyBundles(userId: string, exceptDeviceId?: string): DevicePreKeyBundle[] {
    return this.listDevices(userId)
      .filter((device) => device.deviceId !== exceptDeviceId)
      .flatMap((device) => {
        const bundle = this.getDevicePreKeyBundle(userId, device.deviceId);
        return bundle ? [bundle] : [];
      });
  }

  saveMessage(msg: PendingChatMessage): void {
    this.db
      .prepare(
        `
        INSERT INTO messages (
          id, from_user_id, from_username, from_device_id, to_user_id, to_device_id,
          sesame_session_id, client_message_id, sync_peer_user_id, sender_visible, text, envelope_json, sent_at, created_at
        )
        VALUES (
          @id, @from_user_id, @from_username, @from_device_id, @to_user_id, @to_device_id,
          @sesame_session_id, @client_message_id, @sync_peer_user_id, @sender_visible, @text, @envelope_json, @sent_at, @created_at
        )
      `,
      )
      .run({
        id: msg.id,
        from_user_id: msg.fromUserId,
        from_username: msg.fromUsername,
        from_device_id: msg.fromDeviceId ?? 'default',
        to_user_id: msg.toUserId,
        to_device_id: msg.toDeviceId ?? 'default',
        sesame_session_id: msg.sesameSessionId ?? null,
        client_message_id: msg.clientMessageId ?? null,
        sync_peer_user_id: msg.syncPeerUserId ?? null,
        sender_visible: msg.senderVisible === false ? 0 : 1,
        text: msg.text ?? '',
        envelope_json: msg.envelope ? JSON.stringify(msg.envelope) : null,
        sent_at: msg.sentAt,
        created_at: new Date().toISOString(),
      });
  }

  listConversation(userId: string, peerId: string, limit = 200): PendingChatMessage[] {
    const rows = this.db
      .prepare(
        `
        SELECT
          id,
          from_user_id AS fromUserId,
          from_username AS fromUsername,
          from_device_id AS fromDeviceId,
          to_user_id AS toUserId,
          to_device_id AS toDeviceId,
          sesame_session_id AS sesameSessionId,
          client_message_id AS clientMessageId,
          sync_peer_user_id AS syncPeerUserId,
          text,
          envelope_json AS envelopeJson,
          sent_at AS sentAt
        FROM messages
        WHERE
          (from_user_id = @me AND to_user_id = @peer)
          OR
          (from_user_id = @peer AND to_user_id = @me)
        ORDER BY sent_at ASC
        LIMIT @limit
      `,
      )
      .all({ me: userId, peer: peerId, limit }) as (PendingChatMessage & { envelopeJson: string | null })[];
    return rows.map(rowToMessage);
  }

  listConversationForDevice(userId: string, deviceId: string, peerId: string, limit = 200): PendingChatMessage[] {
    const rows = this.db.prepare(`
      SELECT
        id,
        from_user_id AS fromUserId,
        from_username AS fromUsername,
        from_device_id AS fromDeviceId,
        to_user_id AS toUserId,
        to_device_id AS toDeviceId,
        sesame_session_id AS sesameSessionId,
        client_message_id AS clientMessageId,
        sync_peer_user_id AS syncPeerUserId,
        text,
        envelope_json AS envelopeJson,
        sent_at AS sentAt
      FROM messages
      WHERE
        (from_user_id = @peer AND to_user_id = @me)
        OR
        (from_user_id = @me AND to_user_id = @peer AND from_device_id = @device AND sender_visible = 1)
        OR
        (from_user_id = @me AND to_user_id = @me AND to_device_id = @device AND sync_peer_user_id = @peer)
      ORDER BY sent_at ASC
      LIMIT @limit
    `).all({ me: userId, device: deviceId, peer: peerId, limit }) as (PendingChatMessage & { envelopeJson: string | null })[];
    return rows.map(rowToMessage);
  }

  enqueuePendingMessage(msg: PendingChatMessage): void {
    this.db
      .prepare(
        `
        INSERT INTO pending_messages (
          id, from_user_id, from_username, from_device_id, to_user_id, to_device_id,
          sesame_session_id, client_message_id, sync_peer_user_id, text, envelope_json, sent_at, created_at
        )
        VALUES (
          @id, @from_user_id, @from_username, @from_device_id, @to_user_id, @to_device_id,
          @sesame_session_id, @client_message_id, @sync_peer_user_id, @text, @envelope_json, @sent_at, @created_at
        )
      `,
      )
      .run({
        id: msg.id,
        from_user_id: msg.fromUserId,
        from_username: msg.fromUsername,
        from_device_id: msg.fromDeviceId ?? 'default',
        to_user_id: msg.toUserId,
        to_device_id: msg.toDeviceId ?? 'default',
        sesame_session_id: msg.sesameSessionId ?? null,
        client_message_id: msg.clientMessageId ?? null,
        sync_peer_user_id: msg.syncPeerUserId ?? null,
        text: msg.text ?? '',
        envelope_json: msg.envelope ? JSON.stringify(msg.envelope) : null,
        sent_at: msg.sentAt,
        created_at: new Date().toISOString(),
      });
  }

  listPendingMessagesForUser(toUserId: string, limit = 200): PendingChatMessage[] {
    const rows = this.db
      .prepare(
        `
        SELECT
          id,
          from_user_id AS fromUserId,
          from_username AS fromUsername,
          from_device_id AS fromDeviceId,
          to_user_id AS toUserId,
          to_device_id AS toDeviceId,
          sesame_session_id AS sesameSessionId,
          client_message_id AS clientMessageId,
          sync_peer_user_id AS syncPeerUserId,
          text,
          envelope_json AS envelopeJson,
          sent_at AS sentAt
        FROM pending_messages
        WHERE to_user_id = ?
        ORDER BY created_at ASC
        LIMIT ?
      `,
      )
      .all(toUserId, limit) as (PendingChatMessage & { envelopeJson: string | null })[];
    return rows.map(rowToMessage);
  }

  listPendingMessagesForDevice(toUserId: string, toDeviceId: string, limit = 200): PendingChatMessage[] {
    const rows = this.db.prepare(`
      SELECT
        id,
        from_user_id AS fromUserId,
        from_username AS fromUsername,
        from_device_id AS fromDeviceId,
        to_user_id AS toUserId,
        to_device_id AS toDeviceId,
        sesame_session_id AS sesameSessionId,
        client_message_id AS clientMessageId,
        sync_peer_user_id AS syncPeerUserId,
        text,
        envelope_json AS envelopeJson,
        sent_at AS sentAt
      FROM pending_messages
      WHERE to_user_id = ? AND to_device_id = ?
      ORDER BY created_at ASC
      LIMIT ?
    `).all(toUserId, toDeviceId, limit) as (PendingChatMessage & { envelopeJson: string | null })[];
    return rows.map(rowToMessage);
  }

  deletePendingMessages(ids: string[]): void {
    if (ids.length === 0) return;
    const placeholders = ids.map(() => '?').join(', ');
    this.db.prepare(`DELETE FROM pending_messages WHERE id IN (${placeholders})`).run(...ids);
  }
}

export type ClientSocket = {
  send(data: string): void;
  close(code?: number, reason?: string): void;
};

export class ConnectionHub {
  private sockets = new Map<string, Map<string, Set<ClientSocket>>>();

  add(userId: string, deviceId: string, socket: ClientSocket): void {
    const devices = this.sockets.get(userId) ?? new Map<string, Set<ClientSocket>>();
    const sockets = devices.get(deviceId) ?? new Set<ClientSocket>();
    sockets.add(socket);
    devices.set(deviceId, sockets);
    this.sockets.set(userId, devices);
  }

  remove(userId: string, deviceId?: string, socket?: ClientSocket): void {
    if (!deviceId) {
      this.sockets.delete(userId);
      return;
    }
    const devices = this.sockets.get(userId);
    const sockets = devices?.get(deviceId);
    if (socket) sockets?.delete(socket);
    else devices?.delete(deviceId);
    if (sockets?.size === 0) devices?.delete(deviceId);
    if (devices?.size === 0) this.sockets.delete(userId);
  }

  isOnline(userId: string): boolean {
    return this.sockets.has(userId);
  }

  sendTo(userId: string, payload: unknown): boolean {
    const sockets = this.sockets.get(userId)?.values().next().value as Set<ClientSocket> | undefined;
    const socket = sockets?.values().next().value;
    if (!socket) return false;
    socket.send(JSON.stringify(payload));
    return true;
  }

  sendToUserDevices(userId: string, payload: unknown): number {
    const devices = this.sockets.get(userId);
    if (!devices) return 0;
    const data = JSON.stringify(payload);
    let sent = 0;
    for (const sockets of devices.values()) {
      for (const socket of sockets) {
        socket.send(data);
        sent += 1;
      }
    }
    return sent;
  }

  sendToDevice(userId: string, deviceId: string, payload: unknown): boolean {
    const sockets = this.sockets.get(userId)?.get(deviceId);
    if (!sockets?.size) return false;
    const data = JSON.stringify(payload);
    for (const socket of sockets) socket.send(data);
    return true;
  }

  onlineUserIds(): string[] {
    return [...this.sockets.keys()];
  }
}

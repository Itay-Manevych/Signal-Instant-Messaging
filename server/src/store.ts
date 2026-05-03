import { randomUUID } from 'node:crypto';
import bcrypt from 'bcryptjs';
import type { Db } from './db.js';

export type PublicUser = { id: string; username: string };
export type IdentityKeyPublic = { keyType: 'x25519'; publicKeyB64: string };
export type PendingChatMessage = {
  id: string;
  fromUserId: string;
  fromUsername: string;
  toUserId: string;
  text: string;
  sentAt: string;
};

export type SignedPreKeyPublic = {
  publicKeyB64: string;
  signatureB64: string;
};

export type PreKeyBundle = {
  identityKey: IdentityKeyPublic;
  signedPreKey: SignedPreKeyPublic;
  oneTimePreKey?: {
    id: number;
    publicKeyB64: string;
  };
};

type UserRecord = {
  id: string;
  username: string;
  passwordHash: string;
};

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

  addOneTimePreKeys(userId: string, publicKeysB64: string[]): void {
    const insert = this.db.prepare(`
      INSERT INTO one_time_prekeys (user_id, public_key_b64, created_at)
      VALUES (?, ?, ?)
    `);

    const createdAt = new Date().toISOString();
    const transaction = this.db.transaction((keys: string[]) => {
      for (const key of keys) {
        insert.run(userId, key, createdAt);
      }
    });

    transaction(publicKeysB64);
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
        FROM one_time_prekeys
        WHERE user_id = ?
        ORDER BY RANDOM()
        LIMIT 1
      `,
      )
      .get(userId) as { id: number; publicKeyB64: string } | undefined;

    // If we found one, delete it so it's truly "one-time"
    if (otpk) {
      this.db.prepare(`DELETE FROM one_time_prekeys WHERE id = ?`).run(otpk.id);
    }

    return {
      identityKey,
      signedPreKey,
      oneTimePreKey: otpk,
    };
  }

  saveMessage(msg: PendingChatMessage): void {
    this.db
      .prepare(
        `
        INSERT INTO messages (
          id, from_user_id, from_username, to_user_id, text, sent_at, created_at
        )
        VALUES (
          @id, @from_user_id, @from_username, @to_user_id, @text, @sent_at, @created_at
        )
      `,
      )
      .run({
        id: msg.id,
        from_user_id: msg.fromUserId,
        from_username: msg.fromUsername,
        to_user_id: msg.toUserId,
        text: msg.text,
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
          to_user_id AS toUserId,
          text,
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
      .all({ me: userId, peer: peerId, limit }) as PendingChatMessage[];
    return rows;
  }

  enqueuePendingMessage(msg: PendingChatMessage): void {
    this.db
      .prepare(
        `
        INSERT INTO pending_messages (
          id, from_user_id, from_username, to_user_id, text, sent_at, created_at
        )
        VALUES (
          @id, @from_user_id, @from_username, @to_user_id, @text, @sent_at, @created_at
        )
      `,
      )
      .run({
        id: msg.id,
        from_user_id: msg.fromUserId,
        from_username: msg.fromUsername,
        to_user_id: msg.toUserId,
        text: msg.text,
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
          to_user_id AS toUserId,
          text,
          sent_at AS sentAt
        FROM pending_messages
        WHERE to_user_id = ?
        ORDER BY created_at ASC
        LIMIT ?
      `,
      )
      .all(toUserId, limit) as PendingChatMessage[];
    return rows;
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
  private sockets = new Map<string, ClientSocket>();

  add(userId: string, socket: ClientSocket): void {
    const existing = this.sockets.get(userId);
    existing?.close(4000, 'Replaced by new connection');
    this.sockets.set(userId, socket);
  }

  remove(userId: string): void {
    this.sockets.delete(userId);
  }

  isOnline(userId: string): boolean {
    return this.sockets.has(userId);
  }

  sendTo(userId: string, payload: unknown): boolean {
    const socket = this.sockets.get(userId);
    if (!socket) return false;
    socket.send(JSON.stringify(payload));
    return true;
  }

  onlineUserIds(): string[] {
    return [...this.sockets.keys()];
  }
}

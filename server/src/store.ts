import { randomUUID } from 'node:crypto';
import bcrypt from 'bcryptjs';
import type { Db } from './db.js';

export type PublicUser = { id: string; username: string };
export type IdentityKeyPublic = { keyType: 'x25519'; publicKeyB64: string };

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

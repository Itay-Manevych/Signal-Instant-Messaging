import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

export type Db = Database.Database;

function ensureDirForFile(path: string): void {
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true });
}

export function openDb(dbPath: string): Db {
  const absPath = resolve(dbPath);
  ensureDirForFile(absPath);
  const db = new Database(absPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  return db;
}

export function migrate(db: Db): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username_norm TEXT NOT NULL UNIQUE,
      username TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS identity_keys (
      user_id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL DEFAULT 'default',
      key_type TEXT NOT NULL,
      public_key_b64 TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS signed_prekeys (
      user_id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL DEFAULT 'default',
      public_key_b64 TEXT NOT NULL,
      signature_b64 TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS devices (
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      name TEXT NOT NULL,
      device_secret_hash TEXT,
      created_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL,
      PRIMARY KEY (user_id, device_id),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS device_identity_keys (
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      key_type TEXT NOT NULL,
      public_key_b64 TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      PRIMARY KEY (user_id, device_id),
      FOREIGN KEY (user_id, device_id) REFERENCES devices(user_id, device_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS device_signed_prekeys (
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      public_key_b64 TEXT NOT NULL,
      signature_b64 TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (user_id, device_id),
      FOREIGN KEY (user_id, device_id) REFERENCES devices(user_id, device_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS device_one_time_prekeys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      public_key_b64 TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id, device_id) REFERENCES devices(user_id, device_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS one_time_prekeys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key_id TEXT,
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL DEFAULT 'default',
      public_key_b64 TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    -- Legacy text stays for compatibility; envelope_json is opaque ciphertext transport.
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      from_user_id TEXT NOT NULL,
      from_username TEXT NOT NULL,
      from_device_id TEXT NOT NULL DEFAULT 'default',
      to_user_id TEXT NOT NULL,
      to_device_id TEXT NOT NULL DEFAULT 'default',
      sesame_session_id TEXT,
      client_message_id TEXT,
      sync_peer_user_id TEXT,
      sender_visible INTEGER NOT NULL DEFAULT 1,
      text TEXT NOT NULL,
      envelope_json TEXT,
      sent_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (from_user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (to_user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_messages_pair_created_at
      ON messages(from_user_id, to_user_id, created_at);

    -- Legacy text stays for compatibility; envelope_json is opaque ciphertext transport.
    CREATE TABLE IF NOT EXISTS pending_messages (
      id TEXT PRIMARY KEY,
      from_user_id TEXT NOT NULL,
      from_username TEXT NOT NULL,
      from_device_id TEXT NOT NULL DEFAULT 'default',
      to_user_id TEXT NOT NULL,
      to_device_id TEXT NOT NULL DEFAULT 'default',
      sesame_session_id TEXT,
      client_message_id TEXT,
      sync_peer_user_id TEXT,
      text TEXT NOT NULL,
      envelope_json TEXT,
      sent_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (from_user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (to_user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_pending_messages_to_user_created_at
      ON pending_messages(to_user_id, created_at);
  `);

  addColumnIfMissing(db, 'messages', 'envelope_json TEXT');
  addColumnIfMissing(db, 'pending_messages', 'envelope_json TEXT');
  addColumnIfMissing(db, 'one_time_prekeys', 'key_id TEXT');
  addColumnIfMissing(db, 'devices', 'device_secret_hash TEXT');
  addColumnIfMissing(db, 'identity_keys', "device_id TEXT NOT NULL DEFAULT 'default'");
  addColumnIfMissing(db, 'signed_prekeys', "device_id TEXT NOT NULL DEFAULT 'default'");
  addColumnIfMissing(db, 'one_time_prekeys', "device_id TEXT NOT NULL DEFAULT 'default'");
  addColumnIfMissing(db, 'messages', "from_device_id TEXT NOT NULL DEFAULT 'default'");
  addColumnIfMissing(db, 'messages', "to_device_id TEXT NOT NULL DEFAULT 'default'");
  addColumnIfMissing(db, 'messages', 'sesame_session_id TEXT');
  addColumnIfMissing(db, 'messages', 'client_message_id TEXT');
  addColumnIfMissing(db, 'messages', 'sync_peer_user_id TEXT');
  addColumnIfMissing(db, 'messages', 'sender_visible INTEGER NOT NULL DEFAULT 1');
  addColumnIfMissing(db, 'pending_messages', "from_device_id TEXT NOT NULL DEFAULT 'default'");
  addColumnIfMissing(db, 'pending_messages', "to_device_id TEXT NOT NULL DEFAULT 'default'");
  addColumnIfMissing(db, 'pending_messages', 'sesame_session_id TEXT');
  addColumnIfMissing(db, 'pending_messages', 'client_message_id TEXT');
  addColumnIfMissing(db, 'pending_messages', 'sync_peer_user_id TEXT');
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_one_time_prekeys_user_key_id
      ON one_time_prekeys(user_id, device_id, key_id);
    CREATE INDEX IF NOT EXISTS idx_device_one_time_prekeys_device_key
      ON device_one_time_prekeys(user_id, device_id, key_id);
    CREATE INDEX IF NOT EXISTS idx_devices_user_id
      ON devices(user_id);
    CREATE INDEX IF NOT EXISTS idx_messages_device_pair_created_at
      ON messages(from_user_id, to_user_id, from_device_id, to_device_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_pending_messages_to_device_created_at
      ON pending_messages(to_user_id, to_device_id, created_at);
  `);
}

function addColumnIfMissing(db: Db, table: string, columnSql: string): void {
  const column = columnSql.split(/\s+/)[0];
  const rows = db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[];
  if (!rows.some((row) => row.name === column)) {
    db.prepare(`ALTER TABLE ${table} ADD COLUMN ${columnSql}`).run();
  }
}


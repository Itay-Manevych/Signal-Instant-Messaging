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
      key_type TEXT NOT NULL,
      public_key_b64 TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS signed_prekeys (
      user_id TEXT PRIMARY KEY,
      public_key_b64 TEXT NOT NULL,
      signature_b64 TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS one_time_prekeys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      public_key_b64 TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    -- Legacy text stays for compatibility; envelope_json is opaque ciphertext transport.
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      from_user_id TEXT NOT NULL,
      from_username TEXT NOT NULL,
      to_user_id TEXT NOT NULL,
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
      to_user_id TEXT NOT NULL,
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
}

function addColumnIfMissing(db: Db, table: string, columnSql: string): void {
  const column = columnSql.split(/\s+/)[0];
  const rows = db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[];
  if (!rows.some((row) => row.name === column)) {
    db.prepare(`ALTER TABLE ${table} ADD COLUMN ${columnSql}`).run();
  }
}


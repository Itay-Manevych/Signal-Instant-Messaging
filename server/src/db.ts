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
  `);
}


import 'dotenv/config';
import { copyFileSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import { migrate, openDb } from './db.js';

function timestamp(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

function backupAndDelete(dbPath: string): void {
  const abs = resolve(dbPath);
  const dir = dirname(abs);
  mkdirSync(dir, { recursive: true });

  const base = basename(abs);
  const backupBase = `${base}.backup-${timestamp()}`;
  // Delete WAL/SHM first; on Windows the main DB may be locked by a running process.
  const candidates = [`${abs}-wal`, `${abs}-shm`, abs];

  // Backup main DB if it exists.
  if (existsSync(abs)) {
    copyFileSync(abs, resolve(dir, backupBase));
  }

  // Delete db + wal/shm if present.
  for (const p of candidates) {
    if (!existsSync(p)) continue;
    try {
      rmSync(p, { force: true });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      // eslint-disable-next-line no-console
      console.error(
        [
          `Failed to delete ${p}.`,
          'This usually means the DB is in use by a running server process.',
          'Stop the server (or anything holding the SQLite file) and run db:reset again.',
          msg,
        ].join('\n'),
      );
      process.exitCode = 1;
      return;
    }
  }
}

const DB_PATH = process.env.DB_PATH ?? './data/dev.sqlite';

backupAndDelete(DB_PATH);

const db = openDb(DB_PATH);
migrate(db);
db.close();

// eslint-disable-next-line no-console
console.log(`Reset DB at ${DB_PATH}`);


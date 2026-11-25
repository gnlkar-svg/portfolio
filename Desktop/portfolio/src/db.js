import { DatabaseSync } from "node:sqlite";

/** Opens (and creates if needed) the SQLite database. Use ":memory:" in tests. */
export function openDb(path) {
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      password_changed_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS password_resets (
      id INTEGER PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at INTEGER NOT NULL,
      used_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS password_resets_user ON password_resets(user_id);
  `);
  return db;
}

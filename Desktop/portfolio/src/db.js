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
      email_verified INTEGER DEFAULT 0,
      email_verified_at INTEGER,
      totp_secret TEXT,
      totp_enabled INTEGER DEFAULT 0,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS password_resets (
      id INTEGER PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at INTEGER NOT NULL,
      used_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS email_verifications (
      id INTEGER PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at INTEGER NOT NULL,
      verified_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS user_profiles (
      id INTEGER PRIMARY KEY,
      user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      full_name TEXT,
      avatar_url TEXT,
      bio TEXT,
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS oauth_accounts (
      id INTEGER PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      provider TEXT NOT NULL,
      provider_id TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      UNIQUE(provider, provider_id)
    );
    CREATE INDEX IF NOT EXISTS password_resets_user ON password_resets(user_id);
    CREATE INDEX IF NOT EXISTS email_verifications_user ON email_verifications(user_id);
    CREATE INDEX IF NOT EXISTS oauth_accounts_user ON oauth_accounts(user_id);
  `);
  return db;
}

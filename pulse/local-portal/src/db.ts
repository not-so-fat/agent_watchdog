import type BetterSqlite3 from "better-sqlite3";
// eslint-disable-next-line @typescript-eslint/no-var-requires
const BetterSqlite3Ctor: typeof BetterSqlite3 = require("better-sqlite3");

// Simple SQLite wrapper for MVP.

const DB_PATH = process.env.LOCAL_PORTAL_DB_PATH || "local-portal.db";

// For MVP we don't care about the concrete Database type here.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const db: any = new BetterSqlite3Ctor(DB_PATH);

// Basic migrations aligned with dev/ERD (MVP subset).
export function runMigrations() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS Delegation_Sessions (
      session_id TEXT PRIMARY KEY,
      user_id TEXT,
      agent_id TEXT,
      node_id TEXT,
      policy_hash TEXT,
      policy_version INTEGER,
      max_total_spend INTEGER,
      max_per_tx INTEGER,
      total_spent_atomic INTEGER DEFAULT 0,
      allowed_domains TEXT,
      allowed_apis TEXT,
      allowed_recipients TEXT,
      rate_limit INTEGER,
      ttl_seconds INTEGER,
      expires_at INTEGER,
      last_counter INTEGER,
      revoked_at INTEGER,
      revoked_reason TEXT,
      client_fingerprint TEXT,
      summary TEXT,
      description TEXT,
      created_at INTEGER,
      capabilities TEXT
    );

    CREATE TABLE IF NOT EXISTS Transaction_Logs (
      tx_id TEXT PRIMARY KEY,
      session_id TEXT,
      operation TEXT,
      amount TEXT,
      recipient TEXT,
      domain TEXT,
      api_path TEXT,
      method TEXT,
      decision TEXT,
      deny_code TEXT,
      counter INTEGER,
      idempotency_key TEXT,
      http_402_proof_hash TEXT,
      tx_hash TEXT,
      created_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS Local_API_Requests (
      request_id TEXT PRIMARY KEY,
      session_id TEXT,
      operation TEXT,
      params_hash TEXT,
      auth_valid INTEGER,
      counter INTEGER,
      ip TEXT,
      created_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS Users (
      user_id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS Passkey_Credentials (
      credential_id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      public_key BLOB NOT NULL,
      counter INTEGER NOT NULL DEFAULT 0,
      transports TEXT,
      device_name TEXT,
      created_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES Users(user_id)
    );

    CREATE TABLE IF NOT EXISTS Browser_Sessions (
      session_token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES Users(user_id)
    );

    CREATE TABLE IF NOT EXISTS Watchdog_Events (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      timestamp INTEGER NOT NULL,
      pid INTEGER NOT NULL,
      ppid INTEGER NOT NULL DEFAULT 0,
      command TEXT NOT NULL DEFAULT '',
      args TEXT NOT NULL DEFAULT '[]',
      source_pid_set TEXT NOT NULL DEFAULT 'unknown',
      detail TEXT NOT NULL DEFAULT '',
      dismissed INTEGER NOT NULL DEFAULT 0
    );
  `);

  // Migration: add allowed_apis column if it doesn't exist
  try {
    db.exec(`ALTER TABLE Delegation_Sessions ADD COLUMN allowed_apis TEXT`);
  } catch (e: any) {
    if (!e.message.includes("duplicate column name")) {
      throw e;
    }
  }

  // Migration: add summary and description columns if they don't exist
  try {
    db.exec(`ALTER TABLE Delegation_Sessions ADD COLUMN summary TEXT`);
  } catch (e: any) {
    if (!e.message.includes("duplicate column name")) {
      throw e;
    }
  }

  try {
    db.exec(`ALTER TABLE Delegation_Sessions ADD COLUMN description TEXT`);
  } catch (e: any) {
    if (!e.message.includes("duplicate column name")) {
      throw e;
    }
  }

  // Migration: add capabilities column if it doesn't exist
  try {
    db.exec(`ALTER TABLE Delegation_Sessions ADD COLUMN capabilities TEXT`);
  } catch (e: any) {
    if (!e.message.includes("duplicate column name")) {
      throw e;
    }
  }

  // Migration: add api_path and method to Transaction_Logs
  try {
    db.exec(`ALTER TABLE Transaction_Logs ADD COLUMN api_path TEXT`);
  } catch (e: any) {
    if (!e.message.includes("duplicate column name")) {
      throw e;
    }
  }

  try {
    db.exec(`ALTER TABLE Transaction_Logs ADD COLUMN method TEXT`);
  } catch (e: any) {
    if (!e.message.includes("duplicate column name")) {
      throw e;
    }
  }

  // Migration: add network to Transaction_Logs for explorer URL
  try {
    db.exec(`ALTER TABLE Transaction_Logs ADD COLUMN network TEXT`);
  } catch (e: any) {
    if (!e.message.includes("duplicate column name")) {
      throw e;
    }
  }
}


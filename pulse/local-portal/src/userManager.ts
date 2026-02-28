import { db } from "./db";
import crypto from "crypto";

// --- Types ---

export interface User {
  user_id: string;
  email: string;
  created_at: number;
}

export interface PasskeyCredential {
  credential_id: string;
  user_id: string;
  public_key: Buffer;
  counter: number;
  transports: string | null;
  device_name: string | null;
  created_at: number;
}

export interface BrowserSession {
  session_token: string;
  user_id: string;
  expires_at: number;
  created_at: number;
}

const DEFAULT_SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

// --- Users ---

export function findOrCreateUserByEmail(email: string): User {
  const existing = db
    .prepare("SELECT user_id, email, created_at FROM Users WHERE email = ?")
    .get(email) as User | undefined;
  if (existing) return existing;

  const user_id = crypto.randomUUID();
  const now = Date.now();
  db.prepare("INSERT INTO Users (user_id, email, created_at) VALUES (?, ?, ?)").run(
    user_id,
    email,
    now
  );
  return { user_id, email, created_at: now };
}

export function getUserById(userId: string): User | null {
  return (
    (db
      .prepare("SELECT user_id, email, created_at FROM Users WHERE user_id = ?")
      .get(userId) as User | undefined) ?? null
  );
}

// --- Passkey Credentials ---

export function addPasskeyCredential(
  userId: string,
  credentialId: string,
  publicKey: Buffer,
  counter: number,
  transports?: string[],
  deviceName?: string
): void {
  db.prepare(
    `INSERT INTO Passkey_Credentials
       (credential_id, user_id, public_key, counter, transports, device_name, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(
    credentialId,
    userId,
    publicKey,
    counter,
    transports ? JSON.stringify(transports) : null,
    deviceName ?? null,
    Date.now()
  );
}

export function getPasskeyCredentialsByUserId(userId: string): PasskeyCredential[] {
  return db
    .prepare("SELECT * FROM Passkey_Credentials WHERE user_id = ?")
    .all(userId) as PasskeyCredential[];
}

export function getPasskeyCredentialById(credentialId: string): PasskeyCredential | null {
  return (
    (db
      .prepare("SELECT * FROM Passkey_Credentials WHERE credential_id = ?")
      .get(credentialId) as PasskeyCredential | undefined) ?? null
  );
}

export function getAllPasskeyCredentials(): PasskeyCredential[] {
  return db.prepare("SELECT * FROM Passkey_Credentials").all() as PasskeyCredential[];
}

export function updatePasskeyCounter(credentialId: string, counter: number): void {
  db.prepare("UPDATE Passkey_Credentials SET counter = ? WHERE credential_id = ?").run(
    counter,
    credentialId
  );
}

export function deletePasskeyCredential(credentialId: string): void {
  db.prepare("DELETE FROM Passkey_Credentials WHERE credential_id = ?").run(credentialId);
}

// --- Browser Sessions ---

export function createBrowserSession(
  userId: string,
  ttlMs: number = DEFAULT_SESSION_TTL_MS
): string {
  const sessionToken = crypto.randomBytes(32).toString("hex");
  const now = Date.now();
  db.prepare(
    `INSERT INTO Browser_Sessions (session_token, user_id, expires_at, created_at)
     VALUES (?, ?, ?, ?)`
  ).run(sessionToken, userId, now + ttlMs, now);
  return sessionToken;
}

export function getBrowserSession(sessionToken: string): BrowserSession | null {
  const row = db
    .prepare(
      "SELECT session_token, user_id, expires_at, created_at FROM Browser_Sessions WHERE session_token = ? AND expires_at > ?"
    )
    .get(sessionToken, Date.now()) as BrowserSession | undefined;
  return row ?? null;
}

export function deleteBrowserSession(sessionToken: string): void {
  db.prepare("DELETE FROM Browser_Sessions WHERE session_token = ?").run(sessionToken);
}

export function cleanExpiredSessions(): void {
  db.prepare("DELETE FROM Browser_Sessions WHERE expires_at <= ?").run(Date.now());
}

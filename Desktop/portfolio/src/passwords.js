import { createHash, randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scryptAsync = promisify(scrypt);
const KEY_LEN = 64;

/** "scrypt$<salt hex>$<hash hex>" */
export async function hashPassword(password) {
  const salt = randomBytes(16);
  const key = await scryptAsync(password, salt, KEY_LEN);
  return `scrypt$${salt.toString("hex")}$${key.toString("hex")}`;
}

export async function verifyPassword(password, stored) {
  const [scheme, saltHex, keyHex] = String(stored).split("$");
  if (scheme !== "scrypt" || !saltHex || !keyHex) return false;
  const expected = Buffer.from(keyHex, "hex");
  const actual = await scryptAsync(password, Buffer.from(saltHex, "hex"), expected.length);
  return timingSafeEqual(actual, expected);
}

/** A random URL-safe reset token; only its hash is ever stored. */
export function newResetToken() {
  return randomBytes(32).toString("base64url");
}

export function hashToken(token) {
  return createHash("sha256").update(String(token)).digest("hex");
}

export function checkNewPassword(password, confirm) {
  if (typeof password !== "string" || password.length < 8) return "Şifre en az 8 karakter olmalı.";
  if (password.length > 200) return "Şifre en fazla 200 karakter olabilir.";
  if (confirm !== undefined && password !== confirm) return "Şifreler birbiriyle aynı değil.";
  return null;
}

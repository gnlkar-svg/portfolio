import { randomBytes } from "node:crypto";
import speakeasy from "speakeasy";
import QRCode from "qrcode";

// Email Verification
export function newEmailVerificationToken() {
  return randomBytes(32).toString("base64url");
}

export async function generateTOTPSecret(email, issuer = "Portfolio") {
  return speakeasy.generateSecret({
    name: `Portfolio (${email})`,
    issuer,
    length: 32,
  });
}

export function verifyTOTPToken(secret, token) {
  return speakeasy.totp.verify({
    secret,
    encoding: "base32",
    token: String(token),
    window: 2,
  });
}

export async function getTOTPQRCode(secret) {
  return QRCode.toDataURL(secret.otpauth_url);
}

// Profile
export function getDefaultProfile(userId) {
  return {
    user_id: userId,
    full_name: "",
    avatar_url: "",
    bio: "",
    updated_at: Date.now(),
  };
}

import { createHmac, randomBytes } from 'node:crypto';
import { constantTimeStringEqual } from './crypto.js';

// Base32 RFC 4648 character set
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function generateTotpSecret(byteLength = 20): string {
  const bytes = randomBytes(byteLength);
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | (bytes[i] ?? 0);
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

function base32ToBuffer(base32: string): Buffer {
  const cleaned = base32.toUpperCase().replace(/=+$/, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (let i = 0; i < cleaned.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(cleaned[i] ?? '');
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

/**
 * Computes an RFC 6238 TOTP code for a given secret at a given counter step.
 */
export function computeTotpCode(secretBase32: string, stepOffset = 0, timeStepSeconds = 30): string {
  const keyBuffer = base32ToBuffer(secretBase32);
  const currentStep = Math.floor(Date.now() / 1000 / timeStepSeconds) + stepOffset;

  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigInt64BE(BigInt(currentStep), 0);

  const hmac = createHmac('sha1', keyBuffer).update(counterBuffer).digest();
  const offset = (hmac[hmac.length - 1] ?? 0) & 0x0f;
  const binary =
    (((hmac[offset] ?? 0) & 0x7f) << 24) |
    (((hmac[offset + 1] ?? 0) & 0xff) << 16) |
    (((hmac[offset + 2] ?? 0) & 0xff) << 8) |
    ((hmac[offset + 3] ?? 0) & 0xff);

  const otp = binary % 1_000_000;
  return otp.toString().padStart(6, '0');
}

/**
 * Verifies a 6-digit TOTP code against a secret with a +/- 1 step window (tolerating +/- 30s clock drift).
 */
export function verifyTotpCode(secretBase32: string, candidateCode: string): boolean {
  if (!/^\d{6}$/.test(candidateCode)) {
    return false;
  }

  // Check window: previous, current, next
  for (const offset of [-1, 0, 1]) {
    const validCode = computeTotpCode(secretBase32, offset);
    if (constantTimeStringEqual(validCode, candidateCode)) {
      return true;
    }
  }

  return false;
}

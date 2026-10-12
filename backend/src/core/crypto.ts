import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import argon2 from 'argon2';

/**
 * OWASP recommended Argon2id parameters for high-security identity providers:
 * - Variant: Argon2id (resists both GPU cracking and side-channel attacks)
 * - Memory cost: 64 MiB (65536 KiB)
 * - Time cost: 3 iterations
 * - Parallelism: 4 lanes
 */
const ARGON2_OPTIONS: argon2.Options = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4,
};

/**
 * Hashes user passwords or confidential OAuth client secrets using Argon2id.
 */
export async function hashSecretArgon2id(plainSecret: string): Promise<string> {
  return argon2.hash(plainSecret, ARGON2_OPTIONS);
}

/**
 * Verifies a plaintext password or client secret against an Argon2id PHC string.
 * Argon2's internal verification uses constant-time comparison on the derived tag.
 */
export async function verifySecretArgon2id(
  argon2Hash: string,
  plainSecret: string,
): Promise<boolean> {
  try {
    return await argon2.verify(argon2Hash, plainSecret);
  } catch {
    return false;
  }
}

/**
 * Generates a cryptographically strong, URL-safe Base64 opaque token or authorization code.
 * 32 bytes = 256 bits of CSPRNG entropy (exceeds RFC 6749 Section 10.10 128-bit minimum).
 */
export function generateOpaqueToken(byteLength = 32): string {
  return randomBytes(byteLength).toString('base64url');
}

/**
 * Computes a deterministic SHA-256 hex digest for indexing opaque tokens (auth codes,
 * refresh tokens, and session tokens) in Redis and PostgreSQL so raw tokens are never stored.
 */
export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * Computes the OIDC `at_hash` claim (OpenID Connect Core 1.0 Section 3.1.3.6):
 * Base64url encoding of the left-most 128 bits (16 bytes) of the SHA-256 hash of the ASCII access_token.
 */
export function computeOidcAtHash(accessToken: string): string {
  const fullDigest = createHash('sha256').update(accessToken, 'ascii').digest();
  return fullDigest.subarray(0, 16).toString('base64url');
}

/**
 * Constant-time string comparison to mitigate timing side-channel attacks when comparing
 * PKCE challenges, redirect URIs, or state values.
 *
 * Security Note: To prevent leaking the target string's length via execution time,
 * both strings are hashed with SHA-256 (fixed 32-byte buffers) before `timingSafeEqual`,
 * combined with an explicit byte-length check.
 */
export function constantTimeStringEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  const digestA = createHash('sha256').update(bufA).digest();
  const digestB = createHash('sha256').update(bufB).digest();

  const hashesMatch = timingSafeEqual(digestA, digestB);
  return hashesMatch && bufA.byteLength === bufB.byteLength;
}

/**
 * RFC 7636 Section 4.6 PKCE S256 Verification:
 * Computes BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) and compares it in constant time
 * against the stored `code_challenge`.
 *
 * Also enforces RFC 7636 Section 4.1 length constraints (43 <= length <= 128) and character set.
 */
const PKCE_VERIFIER_REGEX = /^[A-Za-z0-9\-._~]{43,128}$/;

export function verifyPkceS256(codeVerifier: string, storedCodeChallenge: string): boolean {
  if (!PKCE_VERIFIER_REGEX.test(codeVerifier)) {
    return false;
  }
  const computedChallenge = createHash('sha256')
    .update(codeVerifier, 'ascii')
    .digest('base64url');

  return constantTimeStringEqual(computedChallenge, storedCodeChallenge);
}

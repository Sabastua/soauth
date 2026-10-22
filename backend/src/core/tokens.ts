import { randomUUID } from 'node:crypto';
import {
  exportJWK,
  exportPKCS8,
  exportSPKI,
  generateKeyPair,
  importPKCS8,
  importSPKI,
  jwtVerify,
  SignJWT,
  type JWK,
  type KeyLike,
} from 'jose';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { computeOidcAtHash } from './crypto.js';
import type { AccessTokenPayload, IdTokenPayload } from '../types/oauth.types.js';

export type SupportedSigningAlg = 'RS256' | 'ES256';

interface ActiveSigningKeyMaterial {
  kid: string;
  alg: SupportedSigningAlg;
  privateKey: KeyLike;
  publicKey: KeyLike;
  publicJwk: JWK;
}

/**
 * Manages asymmetric signing keys (RS256 / ES256), JWT issuance, and RFC 7517 JWKS exposure.
 * Supports persistent loading/saving from disk or environment variables.
 */
function resolveDefaultIssuer(): string {
  if (process.env.OIDC_ISSUER) return process.env.OIDC_ISSUER.replace(/\/$/, '');
  if (process.env.ISSUER_URL) return process.env.ISSUER_URL.replace(/\/$/, '');
  if (process.env.NODE_ENV !== 'test') {
    if (process.env.VERCEL_PROJECT_PRODUCTION_URL) {
      return `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`;
    }
    if (process.env.VERCEL_URL) {
      return `https://${process.env.VERCEL_URL}`;
    }
  }
  return 'https://auth.soauth.internal';
}

export class TokenCryptoManager {
  private activeKey: ActiveSigningKeyMaterial | null = null;
  private retiredPublicKeys: Map<string, ActiveSigningKeyMaterial> = new Map();
  private readonly issuer: string;
  private readonly alg: SupportedSigningAlg;
  private kid: string;
  private readonly keysDir?: string | undefined;

  constructor(
    issuer = resolveDefaultIssuer(),
    alg: SupportedSigningAlg = (process.env.SIGNING_ALG as SupportedSigningAlg) ?? 'RS256',
    kid = process.env.KEY_ID ?? 'soauth-key-2026-10',
    keysDir = process.env.KEYS_DIR ?? (process.env.VERCEL ? '/tmp/soauth-keys' : undefined),
  ) {
    this.issuer = issuer;
    this.alg = alg;
    this.kid = kid;
    this.keysDir = keysDir;
  }

  /**
   * Initializes or loads the asymmetric key pair.
   * Order of precedence:
   * 1. PRIVATE_KEY_PEM environment variable
   * 2. Persistent file in keysDir (e.g. keys/private.pem)
   * 3. Ephemeral keypair generation (persisted to keysDir if configured)
   */
  public async initializeKeys(): Promise<void> {
    if (this.activeKey) return;

    // 1. Check environment variable PEM (supports escaped \n in serverless env vars)
    if (process.env.PRIVATE_KEY_PEM && process.env.PUBLIC_KEY_PEM) {
      try {
        const normalizedPrivPem = process.env.PRIVATE_KEY_PEM.replace(/\\n/g, '\n');
        const normalizedPubPem = process.env.PUBLIC_KEY_PEM.replace(/\\n/g, '\n');
        const privateKey = await importPKCS8(normalizedPrivPem, this.alg);
        const publicKey = await importSPKI(normalizedPubPem, this.alg);
        const exportedPublicJwk = await exportJWK(publicKey);
        this.activeKey = {
          kid: this.kid,
          alg: this.alg,
          privateKey,
          publicKey,
          publicJwk: { ...exportedPublicJwk, kid: this.kid, alg: this.alg, use: 'sig' },
        };
        return;
      } catch (err) {
        console.warn('[tokens] Failed to import keys from environment PEM; falling back to file/generation.', err);
      }
    }

    // 2. Check disk persistence directory
    if (this.keysDir) {
      const privPath = join(this.keysDir, 'private.pem');
      const pubPath = join(this.keysDir, 'public.pem');

      if (existsSync(privPath) && existsSync(pubPath)) {
        try {
          const privPem = await readFile(privPath, 'utf8');
          const pubPem = await readFile(pubPath, 'utf8');
          const privateKey = await importPKCS8(privPem, this.alg);
          const publicKey = await importSPKI(pubPem, this.alg);
          const exportedPublicJwk = await exportJWK(publicKey);
          this.activeKey = {
            kid: this.kid,
            alg: this.alg,
            privateKey,
            publicKey,
            publicJwk: { ...exportedPublicJwk, kid: this.kid, alg: this.alg, use: 'sig' },
          };
          return;
        } catch (err) {
          console.warn('[tokens] Failed to load keys from disk; re-generating keypair.', err);
        }
      }
    }

    // 3. Generate keypair and save to keysDir if configured
    this.activeKey = await this.generateKeyMaterial(this.kid);

    if (this.keysDir) {
      try {
        await mkdir(this.keysDir, { recursive: true });
        const privPem = await exportPKCS8(this.activeKey.privateKey);
        const pubPem = await exportSPKI(this.activeKey.publicKey);
        await writeFile(join(this.keysDir, 'private.pem'), privPem, 'utf8');
        await writeFile(join(this.keysDir, 'public.pem'), pubPem, 'utf8');
      } catch (err) {
        console.warn('[tokens] Failed to persist generated keypair to disk:', err);
      }
    }
  }

  /**
   * Rotates the active signing key while preserving the previous key in `retiredPublicKeys`
   * so tokens signed immediately prior to rotation continue to validate via JWKS.
   */
  public async rotateSigningKey(newKid: string): Promise<void> {
    if (this.activeKey) {
      this.retiredPublicKeys.set(this.activeKey.kid, this.activeKey);
    }
    this.kid = newKid;
    this.activeKey = await this.generateKeyMaterial(newKid);
  }

  private async generateKeyMaterial(kid: string): Promise<ActiveSigningKeyMaterial> {
    const { publicKey, privateKey } = await generateKeyPair(this.alg, {
      modulusLength: 2048,
      extractable: true,
    });

    const exportedPublicJwk = await exportJWK(publicKey);
    const publicJwk: JWK = {
      ...exportedPublicJwk,
      kid,
      alg: this.alg,
      use: 'sig',
    };

    return {
      kid,
      alg: this.alg,
      privateKey,
      publicKey,
      publicJwk,
    };
  }

  private ensureKeyInitialized(): ActiveSigningKeyMaterial {
    if (!this.activeKey) {
      throw new Error('TokenCryptoManager keys have not been initialized. Call initializeKeys() on startup.');
    }
    return this.activeKey;
  }

  /**
   * Signs an RFC 9068 compliant JWT Access Token (default TTL: 15 minutes = 900s).
   */
  public async signAccessToken(params: {
    userId: string;
    clientId: string;
    sessionId: string;
    scope: string;
    role?: string;
    audience?: string | string[];
    ttlSeconds?: number;
  }): Promise<{ token: string; expiresIn: number; jti: string }> {
    const key = this.ensureKeyInitialized();
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = params.ttlSeconds ?? 900;
    const jti = randomUUID();
    const resolvedRole = params.role ?? 'member';

    const payload: AccessTokenPayload = {
      iss: this.issuer,
      sub: params.userId,
      aud: params.audience ?? params.clientId,
      client_id: params.clientId,
      iat: now,
      exp: now + expiresIn,
      jti,
      sid: params.sessionId,
      scope: params.scope,
      token_use: 'access',
      role: resolvedRole,
      roles: [resolvedRole],
    };

    const token = await new SignJWT(payload)
      .setProtectedHeader({ alg: key.alg, typ: 'at+jwt', kid: key.kid })
      .sign(key.privateKey);

    return { token, expiresIn, jti };
  }

  /**
   * Signs an OpenID Connect Core 1.0 compliant ID Token with asymmetric RS256/ES256 signature.
   * Includes `at_hash` binding the ID Token to the issued `access_token`.
   */
  public async signIdToken(params: {
    userId: string;
    clientId: string;
    sessionId: string;
    authTime: number;
    accessToken: string;
    nonce?: string;
    email?: string;
    emailVerified?: boolean;
    role?: string;
    ttlSeconds?: number;
  }): Promise<string> {
    const key = this.ensureKeyInitialized();
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = params.ttlSeconds ?? 3600;
    const resolvedRole = params.role ?? 'member';

    const payload: IdTokenPayload = {
      iss: this.issuer,
      sub: params.userId,
      aud: params.clientId,
      iat: now,
      exp: now + expiresIn,
      auth_time: params.authTime,
      sid: params.sessionId,
      at_hash: computeOidcAtHash(params.accessToken),
      role: resolvedRole,
      roles: [resolvedRole],
      ...(params.nonce !== undefined ? { nonce: params.nonce } : {}),
      ...(params.email !== undefined
        ? { email: params.email, email_verified: params.emailVerified ?? true }
        : {}),
    };

    return new SignJWT(payload)
      .setProtectedHeader({ alg: key.alg, typ: 'JWT', kid: key.kid })
      .sign(key.privateKey);
  }

  /**
   * Verifies a signed Access Token against the active or recently rotated public keys.
   */
  public async verifyAccessToken(token: string, expectedAudience?: string): Promise<AccessTokenPayload> {
    const active = this.ensureKeyInitialized();
    const candidateKeys = [active, ...this.retiredPublicKeys.values()];

    let lastError: unknown;
    for (const keyMat of candidateKeys) {
      try {
        const { payload } = await jwtVerify<AccessTokenPayload>(token, keyMat.publicKey, {
          issuer: this.issuer,
          algorithms: [keyMat.alg],
          ...(expectedAudience !== undefined ? { audience: expectedAudience } : {}),
        });
        return payload;
      } catch (err) {
        lastError = err;
      }
    }
    throw lastError ?? new Error('Token signature verification failed');
  }

  /**
   * Returns the RFC 7517 JSON Web Key Set (JWKS) containing active and retiring public keys.
   */
  public getPublicJwks(): { keys: JWK[] } {
    const active = this.ensureKeyInitialized();
    const retired = Array.from(this.retiredPublicKeys.values()).map((k) => k.publicJwk);
    return {
      keys: [active.publicJwk, ...retired],
    };
  }

  public getIssuer(): string {
    return this.issuer;
  }
}

export const tokenCryptoManager = new TokenCryptoManager();

import { randomUUID } from 'node:crypto';
import {
  exportJWK,
  generateKeyPair,
  jwtVerify,
  SignJWT,
  type JWK,
  type KeyLike,
} from 'jose';
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
 */
export class TokenCryptoManager {
  private activeKey: ActiveSigningKeyMaterial | null = null;
  private readonly issuer: string;
  private readonly alg: SupportedSigningAlg;
  private readonly kid: string;

  constructor(
    issuer = process.env.OIDC_ISSUER ?? 'https://auth.soauth.internal',
    alg: SupportedSigningAlg = (process.env.SIGNING_ALG as SupportedSigningAlg) ?? 'RS256',
    kid = process.env.KEY_ID ?? 'soauth-key-2026-10',
  ) {
    this.issuer = issuer;
    this.alg = alg;
    this.kid = kid;
  }

  /**
   * Initializes or loads the asymmetric key pair in memory.
   * In production, inject PEM/JWK from KMS/HSM or Vault; falls back to generating an ephemeral keypair.
   */
  public async initializeKeys(): Promise<void> {
    if (this.activeKey) return;

    const { publicKey, privateKey } = await generateKeyPair(this.alg, {
      modulusLength: 2048,
      extractable: true,
    });

    const exportedPublicJwk = await exportJWK(publicKey);
    const publicJwk: JWK = {
      ...exportedPublicJwk,
      kid: this.kid,
      alg: this.alg,
      use: 'sig',
    };

    this.activeKey = {
      kid: this.kid,
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
    audience?: string | string[];
    ttlSeconds?: number;
  }): Promise<{ token: string; expiresIn: number; jti: string }> {
    const key = this.ensureKeyInitialized();
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = params.ttlSeconds ?? 900;
    const jti = randomUUID();

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
    ttlSeconds?: number;
  }): Promise<string> {
    const key = this.ensureKeyInitialized();
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = params.ttlSeconds ?? 3600;

    const payload: IdTokenPayload = {
      iss: this.issuer,
      sub: params.userId,
      aud: params.clientId,
      iat: now,
      exp: now + expiresIn,
      auth_time: params.authTime,
      sid: params.sessionId,
      at_hash: computeOidcAtHash(params.accessToken),
      ...(params.nonce !== undefined ? { nonce: params.nonce } : {}),
      ...(params.email !== undefined ? { email: params.email, email_verified: true } : {}),
    };

    return new SignJWT(payload)
      .setProtectedHeader({ alg: key.alg, typ: 'JWT', kid: key.kid })
      .sign(key.privateKey);
  }

  /**
   * Verifies a signed Access Token against the active public key and issuer.
   */
  public async verifyAccessToken(token: string, expectedAudience?: string): Promise<AccessTokenPayload> {
    const key = this.ensureKeyInitialized();
    const { payload } = await jwtVerify<AccessTokenPayload>(token, key.publicKey, {
      issuer: this.issuer,
      algorithms: [key.alg],
      ...(expectedAudience !== undefined ? { audience: expectedAudience } : {}),
    });
    return payload;
  }

  /**
   * Returns the RFC 7517 JSON Web Key Set (JWKS) containing only public key parameters.
   */
  public getPublicJwks(): { keys: JWK[] } {
    const key = this.ensureKeyInitialized();
    return {
      keys: [key.publicJwk],
    };
  }

  public getIssuer(): string {
    return this.issuer;
  }
}

export const tokenCryptoManager = new TokenCryptoManager();

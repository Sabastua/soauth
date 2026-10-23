import { redis } from '../database/connection.js';
import {
  generateOpaqueToken,
  hashSecretArgon2id,
  sha256Hex,
  verifySecretArgon2id,
} from '../core/crypto.js';
import { clientRepository } from '../repositories/client.repo.js';
import { userRepository } from '../repositories/user.repo.js';
import { sessionAndTokenRepository } from '../repositories/session.repo.js';
import { verifyTotpCode } from '../core/totp.js';
import { saasService } from './saas.service.js';
import {
  OAuthProtocolError,
  type AuthorizeRequestQuery,
  type RedisAuthorizationCodeState,
} from '../types/oauth.types.js';

const AUTH_CODE_TTL_SECONDS = 300; // 5 minutes per RFC 6749 Section 4.1.2
const PKCE_CHALLENGE_REGEX = /^[A-Za-z0-9\-._~]{43,128}$/;

// Pre-computed dummy Argon2id hash to equalize response timing when a user email does not exist
let dummyArgon2HashPromise: Promise<string> | null = null;
function getDummyArgon2Hash(): Promise<string> {
  if (!dummyArgon2HashPromise) {
    dummyArgon2HashPromise = hashSecretArgon2id('dummy-timing-equalizer-secret-value');
  }
  return dummyArgon2HashPromise;
}

export class AuthorizationService {
  /**
   * Step 1 of GET /authorize:
   * Validates client_id, strict exact-match redirect_uri, scopes, and PKCE S256 parameters.
   *
   * Security Note: `client_id` and `redirect_uri` MUST be validated BEFORE any redirect back
   * to the client occurs. If either is invalid, we MUST NOT redirect to `redirect_uri` (RFC 6749 4.1.2.1).
   */
  public async validateAuthorizeRequest(query: AuthorizeRequestQuery) {
    const client = await clientRepository.findById(query.client_id);
    if (!client) {
      throw new OAuthProtocolError(
        'unauthorized_client',
        'Unknown client_id. Cannot redirect to untrusted callback.',
        400,
      );
    }

    // Security Constraint #3: Byte-exact constant-time string matching on redirect_uri
    if (!clientRepository.isRedirectUriAllowed(client, query.redirect_uri)) {
      throw new OAuthProtocolError(
        'invalid_request',
        'The provided redirect_uri does not strictly match any registered callback URI.',
        400,
      );
    }

    if (query.response_type !== 'code') {
      throw new OAuthProtocolError(
        'invalid_request',
        'Only response_type=code (Authorization Code Flow) is supported.',
        400,
      );
    }

    // Security Constraint #1: Enforce PKCE with S256 only
    if (query.code_challenge_method !== 'S256') {
      throw new OAuthProtocolError(
        'invalid_request',
        'PKCE is mandatory and only code_challenge_method=S256 is permitted.',
        400,
      );
    }

    if (!PKCE_CHALLENGE_REGEX.test(query.code_challenge)) {
      throw new OAuthProtocolError(
        'invalid_request',
        'Invalid code_challenge format (must be 43-128 URL-safe base64 characters).',
        400,
      );
    }

    const requestedScopes = query.scope
      .split(' ')
      .map((s) => s.trim())
      .filter(Boolean);

    if (!clientRepository.areScopesAllowed(client, requestedScopes)) {
      throw new OAuthProtocolError(
        'invalid_scope',
        'One or more requested scopes are not permitted for this client.',
        400,
      );
    }

    return {
      client,
      normalizedScope: requestedScopes.join(' '),
    };
  }

  /**
   * Authenticates end-user credentials (Password, Passwordless Email OTP, or WebAuthn Passkey)
   * and creates a bound session row.
   */
  public async authenticateUser(params: {
    email: string;
    passwordPlain?: string;
    otpCode?: string;
    passkeyCredentialId?: string;
    clientId: string;
    totpCode?: string;
    ipAddress: string | null;
    userAgent: string | null;
  }) {
    const normalizedEmail = params.email.toLowerCase().trim();
    let user = await userRepository.findByEmail(normalizedEmail);
    let authMethodLabel = 'password';

    if (params.otpCode) {
      authMethodLabel = 'passwordless_otp';
      const expectedOtp = await redis.get(`soauth:passwordless_otp:${normalizedEmail}`);
      if (!expectedOtp || expectedOtp !== params.otpCode.trim()) {
        saasService.record({
          eventType: 'auth.passwordless.failed',
          actorEmail: normalizedEmail,
          clientId: params.clientId,
          ipAddress: params.ipAddress,
          status: 'failure',
          details: `Invalid or expired passwordless OTP code for ${normalizedEmail}`,
        });
        throw new OAuthProtocolError(
          'access_denied',
          'Invalid or expired 6-digit passwordless login code.',
          401,
        );
      }

      await redis.del(`soauth:passwordless_otp:${normalizedEmail}`);

      // Auto-provision passwordless user if they don't have an account yet
      if (!user) {
        const randomPasswordHash = await hashSecretArgon2id(generateOpaqueToken(32));
        user = await userRepository.create({
          email: normalizedEmail,
          password_hash: randomPasswordHash,
          email_verified: true,
          role: 'member',
          is_mfa_enabled: false,
          mfa_secret_encrypted: null,
          is_active: true,
        });
      } else if (!user.email_verified) {
        await userRepository.markEmailVerified(user.id);
        user.email_verified = true;
      }
    } else if (params.passkeyCredentialId) {
      authMethodLabel = 'passkey';
      const passkey = saasService.findPasskeyForAuthentication({
        email: normalizedEmail,
        credentialId:
          params.passkeyCredentialId === 'auto' ? undefined : params.passkeyCredentialId,
      });

      if (!passkey) {
        saasService.record({
          eventType: 'auth.passkey.failed',
          actorEmail: normalizedEmail,
          clientId: params.clientId,
          ipAddress: params.ipAddress,
          status: 'failure',
          details: `No registered passkey found for ${normalizedEmail}`,
        });
        throw new OAuthProtocolError(
          'access_denied',
          'No registered passkey found for this account. Please sign in with password or email code first and register a passkey.',
          401,
        );
      }

      user = await userRepository.findById(passkey.user_id);
      if (!user) {
        throw new OAuthProtocolError('access_denied', 'User account not found for passkey.', 401);
      }
    } else {
      const targetHash = user ? user.password_hash : await getDummyArgon2Hash();
      const isPasswordValid = await verifySecretArgon2id(
        targetHash,
        params.passwordPlain ?? '',
      );
      if (!user || !isPasswordValid) {
        saasService.record({
          eventType: 'auth.login.failed',
          actorEmail: normalizedEmail,
          clientId: params.clientId,
          ipAddress: params.ipAddress,
          status: 'failure',
          details: `Failed password login attempt for ${normalizedEmail}`,
        });
        throw new OAuthProtocolError('access_denied', 'Invalid email or password.', 401);
      }

      if (user.is_mfa_enabled) {
        if (!params.totpCode) {
          throw new OAuthProtocolError('access_denied', 'MFA_REQUIRED', 401);
        }
        if (
          !user.mfa_secret_encrypted ||
          !verifyTotpCode(user.mfa_secret_encrypted, params.totpCode)
        ) {
          saasService.record({
            eventType: 'auth.mfa.failed',
            actorUserId: user.id,
            actorEmail: user.email,
            clientId: params.clientId,
            ipAddress: params.ipAddress,
            status: 'failure',
            details: `Invalid 6-digit TOTP MFA code for ${user.email}`,
          });
          throw new OAuthProtocolError('access_denied', 'Invalid 6-digit MFA code.', 401);
        }
      }
    }

    const rawSessionToken = generateOpaqueToken(32);
    const sessionTokenHash = sha256Hex(rawSessionToken);
    const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000); // 8 hours

    const session = await sessionAndTokenRepository.createSession({
      user_id: user.id,
      client_id: params.clientId,
      session_token_hash: sessionTokenHash,
      ip_address: params.ipAddress,
      user_agent: params.userAgent,
      expires_at: expiresAt,
    });

    saasService.record({
      eventType: 'auth.login.success',
      actorUserId: user.id,
      actorEmail: user.email,
      clientId: params.clientId,
      ipAddress: params.ipAddress,
      status: 'success',
      details: `User ${user.email} authenticated via ${authMethodLabel} for client ${params.clientId}`,
    });

    const client = await clientRepository.findById(params.clientId);
    if (client?.webhook_url) {
      void saasService.dispatchWebhook(client, 'user.logged_in', {
        user_id: user.id,
        email: user.email,
        role: user.role ?? 'member',
        auth_method: authMethodLabel,
        session_id: session.id,
        ip_address: params.ipAddress,
      });
    }

    return { user, session, rawSessionToken };
  }

  /**
   * Issues a short-lived (300s) single-use Authorization Code and caches the PKCE challenge
   * in Redis keyed by `oauth:code:<sha256(code)>`.
   *
   * Security Note: Storing the SHA-256 hash of the authorization code in Redis prevents
   * read-only Redis snapshots or logs from leaking redeemable authorization codes.
   */
  public async issueAuthorizationCode(params: {
    userId: string;
    clientId: string;
    sessionId: string;
    redirectUri: string;
    scope: string;
    codeChallenge: string;
    codeChallengeMethod: 'S256';
    nonce?: string;
    authTimeSeconds: number;
  }): Promise<string> {
    const rawCode = generateOpaqueToken(32);
    const codeHash = sha256Hex(rawCode);
    const redisKey = `oauth:code:${codeHash}`;

    const codeState: RedisAuthorizationCodeState = {
      userId: params.userId,
      clientId: params.clientId,
      sessionId: params.sessionId,
      redirectUri: params.redirectUri,
      scope: params.scope,
      codeChallenge: params.codeChallenge,
      codeChallengeMethod: params.codeChallengeMethod,
      ...(params.nonce !== undefined ? { nonce: params.nonce } : {}),
      authTime: params.authTimeSeconds,
      createdAt: Math.floor(Date.now() / 1000),
    };

    await redis.set(redisKey, JSON.stringify(codeState), 'EX', AUTH_CODE_TTL_SECONDS);

    return rawCode;
  }
}

export const authorizationService = new AuthorizationService();

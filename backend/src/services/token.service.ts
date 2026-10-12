import { CONSUME_AUTH_CODE_LUA, redis } from '../database/connection.js';
import {
  constantTimeStringEqual,
  generateOpaqueToken,
  sha256Hex,
  verifyPkceS256,
  verifySecretArgon2id,
} from '../core/crypto.js';
import { tokenCryptoManager } from '../core/tokens.js';
import { clientRepository } from '../repositories/client.repo.js';
import { sessionAndTokenRepository } from '../repositories/session.repo.js';
import { userRepository } from '../repositories/user.repo.js';
import {
  OAuthProtocolError,
  type RedisAuthorizationCodeState,
  type TokenRequestBody,
  type TokenSuccessResponse,
} from '../types/oauth.types.js';

const USED_CODE_TOMBSTONE_TTL_SECONDS = 3600; // 1 hour replay detection window
const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

export class TokenService {
  /**
   * Dispatches POST /token requests based on `grant_type`.
   */
  public async handleTokenRequest(body: TokenRequestBody): Promise<TokenSuccessResponse> {
    if (body.grant_type === 'authorization_code') {
      return this.exchangeAuthorizationCode(body);
    }

    if (body.grant_type === 'refresh_token') {
      return this.exchangeRefreshToken(body);
    }

    throw new OAuthProtocolError(
      'unsupported_grant_type',
      'Only authorization_code and refresh_token grant types are supported.',
      400,
    );
  }

  /**
   * Exchanges a single-use Authorization Code + PKCE `code_verifier` for tokens.
   *
   * Security Constraint #4:
   * Executes an atomic Lua script in Redis. If the authorization code was already presented,
   * immediately revokes the entire session and all issued Refresh/Access tokens for that grant.
   */
  private async exchangeAuthorizationCode(
    body: Extract<TokenRequestBody, { grant_type: 'authorization_code' }>,
  ): Promise<TokenSuccessResponse> {
    const codeHash = sha256Hex(body.code);
    const activeKey = `oauth:code:${codeHash}`;
    const usedKey = `oauth:code:used:${codeHash}`;

    const rawResult = (await redis.eval(
      CONSUME_AUTH_CODE_LUA,
      2,
      activeKey,
      usedKey,
      String(USED_CODE_TOMBSTONE_TTL_SECONDS),
    )) as [string, string];

    const [status, stateJson] = rawResult;

    if (status === 'REPLAY_DETECTED' && stateJson) {
      const compromisedState = JSON.parse(stateJson) as RedisAuthorizationCodeState;
      // Trigger immediate cascade revocation of the session and all associated tokens
      await sessionAndTokenRepository.revokeEntireSessionCascade(
        compromisedState.sessionId,
        'AUTH_CODE_REPLAY_DETECTED',
      );
      throw new OAuthProtocolError(
        'invalid_grant',
        'Authorization code has already been used. All tokens associated with this authorization grant have been revoked.',
        400,
      );
    }

    if (status !== 'CONSUMED' || !stateJson) {
      throw new OAuthProtocolError(
        'invalid_grant',
        'Authorization code is invalid or expired.',
        400,
      );
    }

    const codeState = JSON.parse(stateJson) as RedisAuthorizationCodeState;

    // Verify client identity & confidential secret (if confidential client)
    const client = await this.authenticateClient(body.client_id, body.client_secret);

    // Verify the code was issued to this exact client_id and redirect_uri in constant time
    if (
      !constantTimeStringEqual(codeState.clientId, client.id) ||
      !constantTimeStringEqual(codeState.redirectUri, body.redirect_uri)
    ) {
      await sessionAndTokenRepository.revokeEntireSessionCascade(
        codeState.sessionId,
        'CLIENT_OR_REDIRECT_URI_MISMATCH',
      );
      throw new OAuthProtocolError(
        'invalid_grant',
        'redirect_uri or client_id does not match the original authorization request.',
        400,
      );
    }

    // Security Constraint #1: Cryptographic PKCE S256 Verification
    const isPkceValid = verifyPkceS256(body.code_verifier, codeState.codeChallenge);
    if (!isPkceValid) {
      await sessionAndTokenRepository.revokeEntireSessionCascade(
        codeState.sessionId,
        'PKCE_VERIFICATION_FAILED',
      );
      throw new OAuthProtocolError(
        'invalid_grant',
        'PKCE code_verifier failed S256 cryptographic verification.',
        400,
      );
    }

    // Verify the underlying session and user are still active
    const [session, user] = await Promise.all([
      sessionAndTokenRepository.findActiveSessionById(codeState.sessionId),
      userRepository.findById(codeState.userId),
    ]);

    if (!session || !user) {
      throw new OAuthProtocolError(
        'invalid_grant',
        'The user session associated with this authorization grant is no longer active.',
        400,
      );
    }

    // 1. Issue signed JWT Access Token
    const { token: accessToken, expiresIn } = await tokenCryptoManager.signAccessToken({
      userId: user.id,
      clientId: client.id,
      sessionId: session.id,
      scope: codeState.scope,
    });

    // 2. Issue opaque Refresh Token (stored hashed in PostgreSQL)
    const rawRefreshToken = generateOpaqueToken(48);
    const refreshTokenHash = sha256Hex(rawRefreshToken);

    await sessionAndTokenRepository.createRefreshToken({
      token_hashed: refreshTokenHash,
      user_id: user.id,
      client_id: client.id,
      session_id: session.id,
      scope: codeState.scope,
      expires_at: new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
    });

    // 3. Issue OIDC ID Token if 'openid' scope was granted
    const grantedScopes = codeState.scope.split(' ');
    let idToken: string | undefined;

    if (grantedScopes.includes('openid')) {
      idToken = await tokenCryptoManager.signIdToken({
        userId: user.id,
        clientId: client.id,
        sessionId: session.id,
        authTime: codeState.authTime,
        accessToken,
        ...(codeState.nonce !== undefined ? { nonce: codeState.nonce } : {}),
        ...(grantedScopes.includes('email') ? { email: user.email } : {}),
      });
    }

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
      refresh_token: rawRefreshToken,
      ...(idToken !== undefined ? { id_token: idToken } : {}),
      scope: codeState.scope,
    };
  }

  /**
   * Rotates an active Refresh Token and detects Refresh Token Replay attacks.
   */
  private async exchangeRefreshToken(
    body: Extract<TokenRequestBody, { grant_type: 'refresh_token' }>,
  ): Promise<TokenSuccessResponse> {
    const client = await this.authenticateClient(body.client_id, body.client_secret);
    const presentedHash = sha256Hex(body.refresh_token);

    const storedToken = await sessionAndTokenRepository.findRefreshTokenByHash(presentedHash);
    if (!storedToken) {
      throw new OAuthProtocolError('invalid_grant', 'Invalid refresh token.', 400);
    }

    // If a previously rotated/revoked refresh token is replayed, revoke the entire session family
    if (storedToken.is_revoked) {
      await sessionAndTokenRepository.revokeEntireSessionCascade(
        storedToken.session_id,
        'REFRESH_TOKEN_REPLAY_DETECTED',
      );
      throw new OAuthProtocolError(
        'invalid_grant',
        'Refresh token reuse detected. Entire session family has been revoked.',
        400,
      );
    }

    if (
      !constantTimeStringEqual(storedToken.client_id, client.id) ||
      storedToken.expires_at.getTime() <= Date.now()
    ) {
      throw new OAuthProtocolError('invalid_grant', 'Refresh token expired or client mismatch.', 400);
    }

    const session = await sessionAndTokenRepository.findActiveSessionById(storedToken.session_id);
    if (!session) {
      throw new OAuthProtocolError('invalid_grant', 'Session is revoked or expired.', 400);
    }

    const { token: accessToken, expiresIn } = await tokenCryptoManager.signAccessToken({
      userId: storedToken.user_id,
      clientId: client.id,
      sessionId: session.id,
      scope: storedToken.scope,
    });

    const newRawRefreshToken = generateOpaqueToken(48);
    const newRefreshTokenHash = sha256Hex(newRawRefreshToken);

    await sessionAndTokenRepository.rotateRefreshToken(storedToken.id, {
      token_hashed: newRefreshTokenHash,
      user_id: storedToken.user_id,
      client_id: client.id,
      session_id: session.id,
      scope: storedToken.scope,
      expires_at: new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
    });

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
      refresh_token: newRawRefreshToken,
      scope: storedToken.scope,
    };
  }

  /**
   * Verifies Confidential Client credentials using Argon2id.
   */
  private async authenticateClient(clientId: string, clientSecret?: string) {
    const client = await clientRepository.findById(clientId);
    if (!client) {
      throw new OAuthProtocolError('invalid_client', 'Client authentication failed.', 401);
    }

    if (client.is_confidential) {
      if (!clientSecret || !client.client_secret_hash) {
        throw new OAuthProtocolError(
          'invalid_client',
          'Confidential client requires a valid client_secret.',
          401,
        );
      }

      const isValidSecret = await verifySecretArgon2id(client.client_secret_hash, clientSecret);
      if (!isValidSecret) {
        throw new OAuthProtocolError('invalid_client', 'Client authentication failed.', 401);
      }
    }

    return client;
  }
}

export const tokenService = new TokenService();

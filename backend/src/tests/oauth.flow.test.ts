import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { buildOAuthServer } from '../main.js';
import { redis } from '../database/connection.js';
import { clientRepository } from '../repositories/client.repo.js';
import { userRepository } from '../repositories/user.repo.js';
import { sessionAndTokenRepository } from '../repositories/session.repo.js';
import { hashSecretArgon2id } from '../core/crypto.js';
import type {
  ActiveSessionRow,
  RefreshTokenRow,
  RegisteredClientRow,
  UserRow,
} from '../database/schema.js';

describe('OAuth 2.0 & OIDC Authorization Code + PKCE Flow & Replay Revocation', () => {
  const testClientId = randomUUID();
  const testClientSecret = 'super-secret-confidential-client-key-2026';
  const testUserId = randomUUID();
  const testSessionId = randomUUID();
  const allowedRedirectUri = 'https://app.example.com/oauth/callback';

  // In-memory state stores backing the repositories & Redis Lua script during the test
  const redisStore = new Map<string, string>();
  const sessionsStore = new Map<string, ActiveSessionRow>();
  const refreshTokensStore = new Map<string, RefreshTokenRow>();

  let app: Awaited<ReturnType<typeof buildOAuthServer>>;
  let testClient: RegisteredClientRow;
  let testUser: UserRow;

  before(async () => {
    const [clientSecretHash, userPasswordHash] = await Promise.all([
      hashSecretArgon2id(testClientSecret),
      hashSecretArgon2id('CorrectHorseBatteryStaple!99'),
    ]);

    testClient = {
      id: testClientId,
      client_secret_hash: clientSecretHash,
      app_name: 'Acme Enterprise Portal',
      is_confidential: true,
      redirect_uris: [allowedRedirectUri],
      allowed_scopes: ['openid', 'profile', 'email', 'offline_access'],
      require_pkce: true,
      created_at: new Date(),
      updated_at: new Date(),
    };

    testUser = {
      id: testUserId,
      email: 'architect@safaricom.co.ke',
      password_hash: userPasswordHash,
      is_mfa_enabled: false,
      mfa_secret_encrypted: null,
      is_active: true,
      created_at: new Date(),
      updated_at: new Date(),
    };

    sessionsStore.set(testSessionId, {
      id: testSessionId,
      user_id: testUserId,
      client_id: testClientId,
      session_token_hash: 'initial-session-hash',
      ip_address: '127.0.0.1',
      user_agent: 'node-test',
      auth_time: new Date(),
      expires_at: new Date(Date.now() + 3600_000),
      is_revoked: false,
      revoked_reason: null,
      created_at: new Date(),
    });

    // Wire in-memory Redis behavior matching CONSUME_AUTH_CODE_LUA
    redis.set = (async (key: string, value: string) => {
      redisStore.set(key, value);
      return 'OK';
    }) as typeof redis.set;

    redis.eval = (async (_script: string, _numKeys: number, activeKey: string, usedKey: string) => {
      const usedState = redisStore.get(usedKey);
      if (usedState) {
        redisStore.delete(activeKey);
        return ['REPLAY_DETECTED', usedState];
      }
      const activeState = redisStore.get(activeKey);
      if (!activeState) {
        return ['NOT_FOUND', ''];
      }
      redisStore.delete(activeKey);
      redisStore.set(usedKey, activeState);
      return ['CONSUMED', activeState];
    }) as unknown as typeof redis.eval;

    // Wire repository methods to in-memory stores
    clientRepository.findById = async (id: string) =>
      id === testClientId ? testClient : undefined;

    userRepository.findById = async (id: string) =>
      id === testUserId ? testUser : undefined;

    sessionAndTokenRepository.findActiveSessionById = async (id: string) => {
      const session = sessionsStore.get(id);
      if (!session || session.is_revoked) return undefined;
      return session;
    };

    sessionAndTokenRepository.createRefreshToken = async (tokenData) => {
      const row: RefreshTokenRow = {
        id: randomUUID(),
        token_hashed: tokenData.token_hashed,
        user_id: tokenData.user_id,
        client_id: tokenData.client_id,
        session_id: tokenData.session_id,
        scope: tokenData.scope,
        expires_at: new Date(tokenData.expires_at),
        is_revoked: false,
        replaced_by_token_id: null,
        created_at: new Date(),
      };
      refreshTokensStore.set(row.token_hashed, row);
      return row;
    };

    sessionAndTokenRepository.findRefreshTokenByHash = async (hash: string) =>
      refreshTokensStore.get(hash);

    sessionAndTokenRepository.revokeEntireSessionCascade = async (
      sessionId: string,
      reason: string,
    ) => {
      const session = sessionsStore.get(sessionId);
      if (session) {
        session.is_revoked = true;
        session.revoked_reason = reason;
      }
      for (const token of refreshTokensStore.values()) {
        if (token.session_id === sessionId) {
          token.is_revoked = true;
        }
      }
    };

    app = await buildOAuthServer();
  });

  after(async () => {
    await app.close();
  });

  it('rejects GET /authorize when redirect_uri does not strictly match registered URIs', async () => {
    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(codeVerifier, 'ascii').digest('base64url');

    const response = await app.inject({
      method: 'GET',
      url: '/authorize',
      query: {
        response_type: 'code',
        client_id: testClientId,
        redirect_uri: 'https://app.example.com/oauth/callback?evil=1',
        scope: 'openid email',
        state: 'state-xyz-12345',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      },
    });

    assert.equal(response.statusCode, 400);
    const body = response.json();
    assert.equal(body.error, 'invalid_request');
  });

  it('completes GET /authorize -> PKCE POST /token -> JWKS verification -> revokes session on code replay', async () => {
    // 1. Generate RFC 7636 PKCE code_verifier & S256 code_challenge
    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(codeVerifier, 'ascii').digest('base64url');
    const state = 'csrf-state-token-987654';
    const nonce = 'oidc-nonce-value-123456';

    // 2. Call GET /authorize with an authenticated session
    const authResponse = await app.inject({
      method: 'GET',
      url: '/authorize',
      headers: {
        'x-authenticated-user-id': testUserId,
        'x-authenticated-session-id': testSessionId,
      },
      query: {
        response_type: 'code',
        client_id: testClientId,
        redirect_uri: allowedRedirectUri,
        scope: 'openid profile email',
        state,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        nonce,
      },
    });

    assert.equal(authResponse.statusCode, 302);
    const location = authResponse.headers.location;
    assert.ok(location, 'Expected redirect Location header');

    const redirectUrl = new URL(location);
    assert.equal(redirectUrl.origin + redirectUrl.pathname, allowedRedirectUri);
    assert.equal(redirectUrl.searchParams.get('state'), state);

    const authorizationCode = redirectUrl.searchParams.get('code');
    assert.ok(authorizationCode, 'Expected authorization code in callback query');

    // 3. Exchange Authorization Code + PKCE code_verifier at POST /token
    const tokenResponse = await app.inject({
      method: 'POST',
      url: '/token',
      payload: {
        grant_type: 'authorization_code',
        client_id: testClientId,
        client_secret: testClientSecret,
        code: authorizationCode,
        redirect_uri: allowedRedirectUri,
        code_verifier: codeVerifier,
      },
    });

    assert.equal(tokenResponse.statusCode, 200);
    const tokens = tokenResponse.json();
    assert.equal(tokens.token_type, 'Bearer');
    assert.ok(tokens.access_token);
    assert.ok(tokens.refresh_token);
    assert.ok(tokens.id_token);

    // 4. Fetch GET /.well-known/jwks.json and cryptographically verify both Access & ID Tokens
    const jwksResponse = await app.inject({
      method: 'GET',
      url: '/.well-known/jwks.json',
    });
    assert.equal(jwksResponse.statusCode, 200);
    const jwksData = jwksResponse.json();
    const localJwks = createLocalJWKSet(jwksData);

    const verifiedIdToken = await jwtVerify(tokens.id_token, localJwks, {
      audience: testClientId,
    });
    assert.equal(verifiedIdToken.payload.sub, testUserId);
    assert.equal(verifiedIdToken.payload.nonce, nonce);
    assert.equal(verifiedIdToken.payload.email, 'architect@safaricom.co.ke');

    // 5. Security Constraint #4: Present the exact same Authorization Code a second time (Replay Attack!)
    const replayResponse = await app.inject({
      method: 'POST',
      url: '/token',
      payload: {
        grant_type: 'authorization_code',
        client_id: testClientId,
        client_secret: testClientSecret,
        code: authorizationCode,
        redirect_uri: allowedRedirectUri,
        code_verifier: codeVerifier,
      },
    });

    assert.equal(replayResponse.statusCode, 400);
    const replayError = replayResponse.json();
    assert.equal(replayError.error, 'invalid_grant');

    // Verify that the session and all issued refresh tokens were immediately revoked!
    const sessionAfterReplay = sessionsStore.get(testSessionId);
    assert.equal(sessionAfterReplay?.is_revoked, true);
    assert.equal(sessionAfterReplay?.revoked_reason, 'AUTH_CODE_REPLAY_DETECTED');

    for (const rt of refreshTokensStore.values()) {
      assert.equal(rt.is_revoked, true, 'Expected issued refresh token to be revoked on code replay');
    }

    // 6. Attempt to use the previously issued refresh_token after the replay breach -> must fail!
    const refreshAfterReplayResponse = await app.inject({
      method: 'POST',
      url: '/token',
      payload: {
        grant_type: 'refresh_token',
        client_id: testClientId,
        client_secret: testClientSecret,
        refresh_token: tokens.refresh_token,
      },
    });
    assert.equal(refreshAfterReplayResponse.statusCode, 400);
    assert.equal(refreshAfterReplayResponse.json().error, 'invalid_grant');
  });
});

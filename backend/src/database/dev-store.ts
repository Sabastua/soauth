import { randomUUID } from 'node:crypto';
import { hashSecretArgon2id } from '../core/crypto.js';
import { clientRepository } from '../repositories/client.repo.js';
import { userRepository } from '../repositories/user.repo.js';
import { sessionAndTokenRepository } from '../repositories/session.repo.js';
import { redis } from './connection.js';
import type {
  ActiveSessionRow,
  PasswordResetTokenRow,
  RefreshTokenRow,
  RegisteredClientRow,
  UserRow,
} from './schema.js';

/**
 * Embedded in-memory store for instant local manual testing without external PostgreSQL/Redis.
 */
export async function initializeDevMemoryStore(): Promise<void> {
  const usersStore = new Map<string, UserRow>();
  const clientsStore = new Map<string, RegisteredClientRow>();
  const sessionsStore = new Map<string, ActiveSessionRow>();
  const refreshTokensStore = new Map<string, RefreshTokenRow>();
  const redisStore = new Map<string, string>();

  // 1. Seed initial admin user
  const adminPasswordHash = await hashSecretArgon2id('SoAuthAdminPassword!2026');
  const adminUser: UserRow = {
    id: '11111111-1111-4000-8000-111111111111',
    email: 'admin@soauth.internal',
    password_hash: adminPasswordHash,
    is_mfa_enabled: false,
    mfa_secret_encrypted: null,
    is_active: true,
    created_at: new Date(),
    updated_at: new Date(),
  };
  usersStore.set(adminUser.id, adminUser);
  usersStore.set(adminUser.email, adminUser);

  // 2. Seed initial reference OAuth client
  const clientSecretHash = await hashSecretArgon2id('soauth-dev-confidential-secret-2026');
  const defaultClient: RegisteredClientRow = {
    id: '00000000-0000-4000-8000-000000000001',
    client_secret_hash: clientSecretHash,
    app_name: 'soauth Reference Web App',
    is_confidential: true,
    redirect_uris: [
      'http://localhost:3000/oauth/callback',
      'http://localhost:4000/callback',
      'https://oauth.pstmn.io/v1/callback',
    ],
    allowed_scopes: ['openid', 'profile', 'email', 'offline_access'],
    require_pkce: true,
    created_at: new Date(),
    updated_at: new Date(),
  };
  clientsStore.set(defaultClient.id, defaultClient);

  // 3. Patch repository methods with in-memory implementations
  userRepository.findById = async (id: string) => usersStore.get(id);
  userRepository.findByEmail = async (email: string) => usersStore.get(email.toLowerCase().trim());
  userRepository.create = async (user) => {
    const id = randomUUID();
    const row: UserRow = {
      id,
      email: user.email.toLowerCase().trim(),
      password_hash: user.password_hash,
      is_mfa_enabled: user.is_mfa_enabled ?? false,
      mfa_secret_encrypted: user.mfa_secret_encrypted ?? null,
      is_active: user.is_active ?? true,
      created_at: new Date(),
      updated_at: new Date(),
    };
    usersStore.set(id, row);
    usersStore.set(row.email, row);
    return row;
  };

  const passwordResetStore = new Map<string, PasswordResetTokenRow>();

  userRepository.updatePassword = async (userId: string, newPasswordHash: string) => {
    const user = usersStore.get(userId);
    if (user) {
      user.password_hash = newPasswordHash;
      user.updated_at = new Date();
    }
  };

  userRepository.createPasswordResetToken = async (tokenData) => {
    const id = randomUUID();
    const row: PasswordResetTokenRow = {
      id,
      user_id: tokenData.user_id,
      token_hashed: tokenData.token_hashed,
      expires_at: new Date(tokenData.expires_at),
      is_used: false,
      created_at: new Date(),
    };
    passwordResetStore.set(row.token_hashed, row);
    return row;
  };

  userRepository.findValidPasswordResetToken = async (tokenHash: string) => {
    const token = passwordResetStore.get(tokenHash);
    if (!token || token.is_used || new Date(token.expires_at).getTime() <= Date.now()) {
      return undefined;
    }
    return token;
  };

  userRepository.markPasswordResetTokenUsed = async (tokenId: string) => {
    for (const token of passwordResetStore.values()) {
      if (token.id === tokenId) {
        token.is_used = true;
      }
    }
  };

  userRepository.revokeAllSessionsForUser = async (userId: string, reason: string) => {
    for (const session of sessionsStore.values()) {
      if (session.user_id === userId) {
        session.is_revoked = true;
        session.revoked_reason = reason;
      }
    }
    for (const token of refreshTokensStore.values()) {
      if (token.user_id === userId) {
        token.is_revoked = true;
      }
    }
  };

  clientRepository.findById = async (id: string) => clientsStore.get(id);
  clientRepository.create = async (client) => {
    const row: RegisteredClientRow = {
      id: client.id ?? randomUUID(),
      app_name: client.app_name,
      redirect_uris: client.redirect_uris,
      allowed_scopes: client.allowed_scopes ?? ['openid', 'profile', 'email'],
      is_confidential: client.is_confidential ?? true,
      client_secret_hash: client.client_secret_hash ?? null,
      require_pkce: client.require_pkce ?? true,
      created_at: new Date(),
      updated_at: new Date(),
    };
    clientsStore.set(row.id, row);
    return row;
  };

  sessionAndTokenRepository.createSession = async (session) => {
    const id = randomUUID();
    const row: ActiveSessionRow = {
      id,
      user_id: session.user_id,
      client_id: session.client_id,
      session_token_hash: session.session_token_hash,
      ip_address: session.ip_address ?? null,
      user_agent: session.user_agent ?? null,
      auth_time: new Date(),
      expires_at: new Date(session.expires_at),
      is_revoked: false,
      revoked_reason: null,
      created_at: new Date(),
    };
    sessionsStore.set(id, row);
    return row;
  };

  sessionAndTokenRepository.findActiveSessionById = async (id: string) => {
    const s = sessionsStore.get(id);
    if (!s || s.is_revoked) return undefined;
    return s;
  };

  sessionAndTokenRepository.createRefreshToken = async (tokenData) => {
    const id = randomUUID();
    const row: RefreshTokenRow = {
      id,
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

  sessionAndTokenRepository.rotateRefreshToken = async (oldTokenId, newTokenData) => {
    const newId = randomUUID();
    const newRow: RefreshTokenRow = {
      id: newId,
      token_hashed: newTokenData.token_hashed,
      user_id: newTokenData.user_id,
      client_id: newTokenData.client_id,
      session_id: newTokenData.session_id,
      scope: newTokenData.scope,
      expires_at: new Date(newTokenData.expires_at),
      is_revoked: false,
      replaced_by_token_id: null,
      created_at: new Date(),
    };
    refreshTokensStore.set(newRow.token_hashed, newRow);

    for (const rt of refreshTokensStore.values()) {
      if (rt.id === oldTokenId) {
        rt.is_revoked = true;
        rt.replaced_by_token_id = newId;
      }
    }
    return newRow;
  };

  sessionAndTokenRepository.revokeRefreshTokenById = async (tokenId: string) => {
    for (const rt of refreshTokensStore.values()) {
      if (rt.id === tokenId) {
        rt.is_revoked = true;
      }
    }
  };

  sessionAndTokenRepository.revokeEntireSessionCascade = async (sessionId, reason) => {
    const s = sessionsStore.get(sessionId);
    if (s) {
      s.is_revoked = true;
      s.revoked_reason = reason;
    }
    for (const rt of refreshTokensStore.values()) {
      if (rt.session_id === sessionId) {
        rt.is_revoked = true;
      }
    }
  };

  // 4. Patch Redis with in-memory single-use storage & Lua script
  redis.set = (async (key: string, value: string) => {
    redisStore.set(key, value);
    return 'OK';
  }) as typeof redis.set;

  redis.get = (async (key: string) => redisStore.get(key) ?? null) as typeof redis.get;

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

  console.log('[soauth] In-memory development store active.');
  console.log('         Default User:   admin@soauth.internal');
  console.log('         Password:       SoAuthAdminPassword!2026');
  console.log('         Client ID:      00000000-0000-4000-8000-000000000001');
  console.log('         Client Secret:  soauth-dev-confidential-secret-2026');
}

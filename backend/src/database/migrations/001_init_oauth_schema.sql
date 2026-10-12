-- ============================================================================
-- soauth: OAuth 2.0 & OpenID Connect (OIDC) Core Relational Schema
-- Engine: PostgreSQL 16+
-- Security Constraints:
--   1. Passwords & Client Secrets stored strictly as Argon2id hashes
--   2. Refresh tokens & session tokens stored strictly as SHA-256 hashes
--   3. Redirect URIs stored as explicit TEXT[] for byte-exact matching
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. users: End-user identity accounts
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(320) NOT NULL UNIQUE,
    password_hash VARCHAR(512) NOT NULL, -- Argon2id encoded hash string
    is_mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret_encrypted TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

-- 2. registered_clients: OAuth 2.0 Relying Parties (RPs)
CREATE TABLE IF NOT EXISTS registered_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), -- Public client_id
    client_secret_hash VARCHAR(512),               -- Argon2id hash (NULL for public PKCE-only clients)
    app_name VARCHAR(255) NOT NULL,
    is_confidential BOOLEAN NOT NULL DEFAULT TRUE,
    -- Strict array of exact callback URLs (no wildcards allowed to prevent open redirectors)
    redirect_uris TEXT[] NOT NULL CHECK (array_length(redirect_uris, 1) >= 1),
    allowed_scopes TEXT[] NOT NULL DEFAULT ARRAY['openid', 'profile', 'email'],
    require_pkce BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. active_sessions: Tracks authenticated user sessions & binds authorization grants
-- Used to immediately revoke all downstream tokens if an Auth Code replay attack is detected
CREATE TABLE IF NOT EXISTS active_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id UUID NOT NULL REFERENCES registered_clients(id) ON DELETE CASCADE,
    session_token_hash VARCHAR(128) NOT NULL UNIQUE, -- SHA-256 hex digest
    ip_address INET,
    user_agent TEXT,
    auth_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_reason VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_active_sessions_user_client ON active_sessions (user_id, client_id);
CREATE INDEX IF NOT EXISTS idx_active_sessions_token_hash ON active_sessions (session_token_hash);

-- 4. refresh_tokens: Long-lived opaque tokens with rotation & family-based breach revocation
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hashed VARCHAR(128) NOT NULL UNIQUE, -- SHA-256 hex digest of the raw opaque token
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id UUID NOT NULL REFERENCES registered_clients(id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES active_sessions(id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    replaced_by_token_id UUID REFERENCES refresh_tokens(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hashed ON refresh_tokens (token_hashed);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session_id ON refresh_tokens (session_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_client ON refresh_tokens (user_id, client_id);

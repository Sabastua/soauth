import type { JWTPayload } from 'jose';

/**
 * Standard PKCE Code Challenge Method.
 * Plain is explicitly prohibited per RFC 9700 (OAuth 2.0 Security Best Current Practice).
 */
export type CodeChallengeMethod = 'S256';

/**
 * Standard OIDC & OAuth 2.0 Scopes
 */
export type OAuthScope = 'openid' | 'profile' | 'email' | 'offline_access' | string;

/**
 * OAuth 2.0 Access Token Claims (RFC 9068 Profile for JWT Access Tokens)
 */
export interface AccessTokenPayload extends JWTPayload {
  /** Issuer Identifier (e.g., https://auth.soauth.internal) */
  iss: string;
  /** Subject Identifier (User UUID) */
  sub: string;
  /** Audience (Resource Server URI or Client ID) */
  aud: string | string[];
  /** Client Identifier that requested the token */
  client_id: string;
  /** Expiration time (Unix epoch seconds) */
  exp: number;
  /** Issued at time (Unix epoch seconds) */
  iat: number;
  /** Unique Token Identifier (UUIDv4 for revocation/replay tracking) */
  jti: string;
  /** Session Identifier binding the token to an active_sessions row */
  sid: string;
  /** Space-delimited list of granted OAuth scopes */
  scope: string;
  /** Explicit token type header/claim */
  token_use: 'access';
  /** RBAC Role & Roles claims */
  role?: string;
  roles?: string[];
  /** Multi-Tenant Organization Claims */
  org_id?: string;
  org_slug?: string;
  org_role?: string;
  /** Custom JWT claims merged from client custom_claims_template */
  custom_claims?: Record<string, unknown>;
}

/**
 * OpenID Connect Core 1.0 ID Token Claims
 */
export interface IdTokenPayload extends JWTPayload {
  /** Issuer Identifier */
  iss: string;
  /** Subject Identifier (User UUID) */
  sub: string;
  /** Audience (MUST be the registered OAuth Client ID) */
  aud: string;
  /** Expiration time (Unix epoch seconds) */
  exp: number;
  /** Issued at time (Unix epoch seconds) */
  iat: number;
  /** Time when the End-User authentication occurred (Unix epoch seconds) */
  auth_time: number;
  /** String value used to associate a Client session with an ID Token (MITM/Replay mitigation) */
  nonce?: string;
  /** Access Token hash value (left-most half of SHA-256 of the octets of the ASCII access_token) */
  at_hash?: string;
  /** Session ID claim (OIDC Front/Back-Channel Logout) */
  sid: string;
  /** Optional profile/email scope claims */
  email?: string;
  email_verified?: boolean;
  /** RBAC Role & Roles claims */
  role?: string;
  roles?: string[];
  /** Multi-Tenant Organization Claims */
  org_id?: string;
  org_slug?: string;
  org_role?: string;
  /** Custom JWT claims merged from client custom_claims_template */
  custom_claims?: Record<string, unknown>;
}

/**
 * Opaque Refresh Token Metadata stored in PostgreSQL
 */
export interface RefreshTokenDescriptor {
  rawToken: string;
  tokenHash: string;
  userId: string;
  clientId: string;
  sessionId: string;
  scope: string;
  expiresAt: Date;
}

/**
 * Ephemeral Authorization Code Record stored in Redis (`oauth:code:<code_hash>`)
 * TTL: 300 seconds (5 minutes)
 */
export interface RedisAuthorizationCodeState {
  userId: string;
  clientId: string;
  sessionId: string;
  redirectUri: string;
  scope: string;
  codeChallenge: string;
  codeChallengeMethod: CodeChallengeMethod;
  nonce?: string;
  authTime: number;
  createdAt: number;
}

/**
 * GET /authorize Query Parameters (OAuth 2.1 + OIDC Core)
 */
export interface AuthorizeRequestQuery {
  response_type: 'code';
  client_id: string;
  redirect_uri: string;
  scope: string;
  state: string;
  code_challenge: string;
  code_challenge_method: CodeChallengeMethod;
  nonce?: string;
}

/**
 * POST /token Request Body (Authorization Code Exchange + Refresh Token Grant + Client Credentials Grant)
 */
export type TokenRequestBody =
  | {
      grant_type: 'authorization_code';
      code: string;
      redirect_uri: string;
      client_id: string;
      client_secret?: string;
      code_verifier: string;
    }
  | {
      grant_type: 'refresh_token';
      refresh_token: string;
      client_id: string;
      client_secret?: string;
      scope?: string;
    }
  | {
      grant_type: 'client_credentials';
      client_id: string;
      client_secret: string;
      scope?: string;
    };

/**
 * Standard RFC 6749 Section 5.1 Successful Token Response
 */
export interface TokenSuccessResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope: string;
}

/**
 * Standard RFC 6749 Section 5.2 Error Response
 */
export type OAuthErrorCode =
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'unauthorized_client'
  | 'unsupported_grant_type'
  | 'invalid_scope'
  | 'invalid_redirect_uri'
  | 'access_denied'
  | 'server_error';

export class OAuthProtocolError extends Error {
  public readonly errorCode: OAuthErrorCode;
  public readonly statusCode: number;
  public readonly errorDescription: string;

  constructor(errorCode: OAuthErrorCode, errorDescription: string, statusCode = 400) {
    super(errorDescription);
    this.name = 'OAuthProtocolError';
    this.errorCode = errorCode;
    this.errorDescription = errorDescription;
    this.statusCode = statusCode;
  }
}

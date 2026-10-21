/**
 * soauth Client SDK
 * Zero-dependency, isomorphic OAuth 2.0 & OpenID Connect client library
 * Works in modern browsers and Node.js v18+.
 */

export interface PKCEPair {
  codeVerifier: string;
  codeChallenge: string;
}

export interface AuthorizeOptions {
  issuerUrl: string;
  clientId: string;
  redirectUri: string;
  scope?: string;
  state?: string;
  nonce?: string;
  codeVerifier?: string;
}

export interface TokenExchangeOptions {
  issuerUrl: string;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  code: string;
  codeVerifier: string;
}

export interface RefreshTokenOptions {
  issuerUrl: string;
  clientId: string;
  clientSecret?: string;
  refreshToken: string;
  scope?: string;
}

export interface RevokeTokenOptions {
  issuerUrl: string;
  clientId: string;
  clientSecret?: string;
  token: string;
  tokenTypeHint?: 'access_token' | 'refresh_token';
}

export interface OAuthTokens {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

export interface UserInfo {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  updated_at?: number;
  [key: string]: unknown;
}

export interface LogoutOptions {
  issuerUrl: string;
  idTokenHint?: string;
  postLogoutRedirectUri?: string;
  state?: string;
}

function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Generates a cryptographically secure random URL-safe string.
 */
export function generateRandomString(length: number = 43): string {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  const randomValues = new Uint8Array(length);
  globalThis.crypto.getRandomValues(randomValues);
  let result = '';
  for (let i = 0; i < length; i++) {
    result += charset[randomValues[i] % charset.length];
  }
  return result;
}

/**
 * Generates an RFC 7636 compliant PKCE code_verifier and code_challenge (S256).
 */
export async function generatePKCE(): Promise<PKCEPair> {
  const codeVerifier = generateRandomString(64);
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', data);
  const codeChallenge = bufferToBase64Url(digest);
  return { codeVerifier, codeChallenge };
}

/**
 * Creates the standard OAuth 2.0 Authorization URL with PKCE parameters.
 */
export async function createAuthorizationUrl(options: AuthorizeOptions): Promise<{
  url: string;
  codeVerifier: string;
  state: string;
}> {
  const state = options.state ?? generateRandomString(32);
  let codeVerifier = options.codeVerifier;
  let codeChallenge: string;

  if (codeVerifier) {
    const encoder = new TextEncoder();
    const digest = await globalThis.crypto.subtle.digest('SHA-256', encoder.encode(codeVerifier));
    codeChallenge = bufferToBase64Url(digest);
  } else {
    const pkce = await generatePKCE();
    codeVerifier = pkce.codeVerifier;
    codeChallenge = pkce.codeChallenge;
  }

  const url = new URL(`${options.issuerUrl.replace(/\/$/, '')}/authorize`);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', options.clientId);
  url.searchParams.set('redirect_uri', options.redirectUri);
  url.searchParams.set('scope', options.scope ?? 'openid profile email');
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');

  if (options.nonce) {
    url.searchParams.set('nonce', options.nonce);
  }

  return { url: url.toString(), codeVerifier, state };
}

/**
 * Exchanges an Authorization Code for Access & ID Tokens at POST /token.
 */
export async function exchangeCodeForTokens(options: TokenExchangeOptions): Promise<OAuthTokens> {
  const tokenUrl = `${options.issuerUrl.replace(/\/$/, '')}/token`;
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: options.code,
    redirect_uri: options.redirectUri,
    client_id: options.clientId,
    code_verifier: options.codeVerifier,
  });

  if (options.clientSecret) {
    body.set('client_secret', options.clientSecret);
  }

  const res = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error_description ?? data.error ?? 'Token exchange failed');
  }

  return data as OAuthTokens;
}

/**
 * Retrieves the authenticated user profile from GET /userinfo.
 */
export async function fetchUserInfo(issuerUrl: string, accessToken: string): Promise<UserInfo> {
  const userinfoUrl = `${issuerUrl.replace(/\/$/, '')}/userinfo`;
  const res = await fetch(userinfoUrl, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error_description ?? data.error ?? 'Failed to fetch user info');
  }

  return data as UserInfo;
}

/**
 * Refreshes an expired access token using the refresh_token grant.
 */
export async function refreshAccessToken(options: RefreshTokenOptions): Promise<OAuthTokens> {
  const tokenUrl = `${options.issuerUrl.replace(/\/$/, '')}/token`;
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: options.refreshToken,
    client_id: options.clientId,
  });

  if (options.clientSecret) {
    body.set('client_secret', options.clientSecret);
  }

  if (options.scope) {
    body.set('scope', options.scope);
  }

  const res = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error_description ?? data.error ?? 'Token refresh failed');
  }

  return data as OAuthTokens;
}

/**
 * Revokes an access token or refresh token (RFC 7009).
 */
export async function revokeToken(options: RevokeTokenOptions): Promise<void> {
  const revokeUrl = `${options.issuerUrl.replace(/\/$/, '')}/revoke`;
  const body = new URLSearchParams({
    token: options.token,
    client_id: options.clientId,
  });

  if (options.clientSecret) {
    body.set('client_secret', options.clientSecret);
  }
  if (options.tokenTypeHint) {
    body.set('token_type_hint', options.tokenTypeHint);
  }

  const res = await fetch(revokeUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!res.ok) {
    const data = await res.json();
    throw new Error(data.error_description ?? data.error ?? 'Token revocation failed');
  }
}

/**
 * Builds the RFC RP-Initiated Logout URL.
 */
export function buildLogoutUrl(options: LogoutOptions): string {
  const url = new URL(`${options.issuerUrl.replace(/\/$/, '')}/logout`);
  if (options.idTokenHint) {
    url.searchParams.set('id_token_hint', options.idTokenHint);
  }
  if (options.postLogoutRedirectUri) {
    url.searchParams.set('post_logout_redirect_uri', options.postLogoutRedirectUri);
  }
  if (options.state) {
    url.searchParams.set('state', options.state);
  }
  return url.toString();
}

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
  role?: string;
  roles?: string[];
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

export interface SoAuthClientConfig {
  issuerUrl: string;
  clientId: string;
  clientSecret?: string;
  redirectUri?: string;
  scope?: string;
  storageKeyPrefix?: string;
}

export interface SoAuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: UserInfo | null;
  accessToken: string | null;
  idToken: string | null;
  error: string | null;
}

/**
 * Clerk-style Stateful Client Manager for SPAs, React, Vue, and Vanilla JS.
 * Automatically handles PKCE generation, redirect callback `?code=...`, token refresh, and session persistence.
 */
export class SoAuthClient {
  private readonly config: Required<Pick<SoAuthClientConfig, 'issuerUrl' | 'clientId' | 'scope' | 'storageKeyPrefix'>> &
    Omit<SoAuthClientConfig, 'issuerUrl' | 'clientId' | 'scope' | 'storageKeyPrefix'>;
  private state: SoAuthState = {
    isAuthenticated: false,
    isLoading: true,
    user: null,
    accessToken: null,
    idToken: null,
    error: null,
  };
  private listeners = new Set<(state: SoAuthState) => void>();

  constructor(config: SoAuthClientConfig) {
    this.config = {
      ...config,
      issuerUrl: config.issuerUrl.replace(/\/$/, ''),
      scope: config.scope ?? 'openid profile email offline_access',
      storageKeyPrefix: config.storageKeyPrefix ?? `soauth_${config.clientId}`,
    };
  }

  public getState(): SoAuthState {
    return this.state;
  }

  public subscribe(listener: (state: SoAuthState) => void): () => void {
    this.listeners.add(listener);
    listener(this.state);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private setState(partial: Partial<SoAuthState>): void {
    this.state = { ...this.state, ...partial };
    for (const listener of this.listeners) {
      listener(this.state);
    }
  }

  private getRedirectUri(): string {
    if (this.config.redirectUri) return this.config.redirectUri;
    if (typeof window !== 'undefined') {
      return window.location.origin + window.location.pathname;
    }
    throw new Error('redirectUri is required in non-browser environments');
  }

  /**
   * Initializes client state: checks URL for OAuth callback `?code=...` or restores cached session.
   */
  public async initialize(): Promise<SoAuthState> {
    if (typeof window === 'undefined') {
      this.setState({ isLoading: false });
      return this.state;
    }

    const prefix = this.config.storageKeyPrefix;
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const returnedState = params.get('state');
    const oauthError = params.get('error');

    if (oauthError) {
      const desc = params.get('error_description') ?? oauthError;
      this.cleanUrlParams();
      this.setState({ isLoading: false, isAuthenticated: false, error: desc });
      return this.state;
    }

    if (code && returnedState) {
      const expectedState = sessionStorage.getItem(`${prefix}_state`);
      const verifier = sessionStorage.getItem(`${prefix}_verifier`);

      if (verifier && (!expectedState || expectedState === returnedState)) {
        try {
          const tokens = await exchangeCodeForTokens({
            issuerUrl: this.config.issuerUrl,
            clientId: this.config.clientId,
            ...(this.config.clientSecret ? { clientSecret: this.config.clientSecret } : {}),
            redirectUri: this.getRedirectUri(),
            code,
            codeVerifier: verifier,
          });

          sessionStorage.removeItem(`${prefix}_state`);
          sessionStorage.removeItem(`${prefix}_verifier`);
          this.persistTokens(tokens);
          this.cleanUrlParams();

          const user = await fetchUserInfo(this.config.issuerUrl, tokens.access_token);
          sessionStorage.setItem(`${prefix}_user`, JSON.stringify(user));

          this.setState({
            isAuthenticated: true,
            isLoading: false,
            user,
            accessToken: tokens.access_token,
            idToken: tokens.id_token ?? null,
            error: null,
          });
          return this.state;
        } catch (err) {
          this.cleanUrlParams();
          this.setState({
            isAuthenticated: false,
            isLoading: false,
            error: err instanceof Error ? err.message : 'Token exchange failed',
          });
          return this.state;
        }
      }
    }

    // Restore from sessionStorage if valid
    const cachedAccess = sessionStorage.getItem(`${prefix}_access_token`);
    const cachedId = sessionStorage.getItem(`${prefix}_id_token`);
    const cachedUser = sessionStorage.getItem(`${prefix}_user`);

    if (cachedAccess) {
      try {
        const user = cachedUser
          ? (JSON.parse(cachedUser) as UserInfo)
          : await fetchUserInfo(this.config.issuerUrl, cachedAccess);
        sessionStorage.setItem(`${prefix}_user`, JSON.stringify(user));
        this.setState({
          isAuthenticated: true,
          isLoading: false,
          user,
          accessToken: cachedAccess,
          idToken: cachedId,
          error: null,
        });
        return this.state;
      } catch {
        // Attempt token refresh if refresh_token exists
        const cachedRefresh = sessionStorage.getItem(`${prefix}_refresh_token`);
        if (cachedRefresh) {
          try {
            const refreshed = await refreshAccessToken({
              issuerUrl: this.config.issuerUrl,
              clientId: this.config.clientId,
              ...(this.config.clientSecret ? { clientSecret: this.config.clientSecret } : {}),
              refreshToken: cachedRefresh,
            });
            this.persistTokens(refreshed);
            const user = await fetchUserInfo(this.config.issuerUrl, refreshed.access_token);
            sessionStorage.setItem(`${prefix}_user`, JSON.stringify(user));
            this.setState({
              isAuthenticated: true,
              isLoading: false,
              user,
              accessToken: refreshed.access_token,
              idToken: refreshed.id_token ?? cachedId,
              error: null,
            });
            return this.state;
          } catch {
            this.clearStorage();
          }
        } else {
          this.clearStorage();
        }
      }
    }

    this.setState({ isAuthenticated: false, isLoading: false, user: null, accessToken: null });
    return this.state;
  }

  /**
   * Starts the PKCE redirect flow to the hosted soauth login UI.
   */
  public async loginWithRedirect(customScope?: string): Promise<void> {
    const prefix = this.config.storageKeyPrefix;
    const { url, codeVerifier, state } = await createAuthorizationUrl({
      issuerUrl: this.config.issuerUrl,
      clientId: this.config.clientId,
      redirectUri: this.getRedirectUri(),
      scope: customScope ?? this.config.scope,
    });

    if (typeof window !== 'undefined') {
      sessionStorage.setItem(`${prefix}_verifier`, codeVerifier);
      sessionStorage.setItem(`${prefix}_state`, state);
      window.location.assign(url);
    }
  }

  /**
   * Returns a valid access token, refreshing automatically if needed.
   */
  public async getAccessToken(): Promise<string | null> {
    if (this.state.accessToken) return this.state.accessToken;
    const prefix = this.config.storageKeyPrefix;
    const refresh = typeof window !== 'undefined' ? sessionStorage.getItem(`${prefix}_refresh_token`) : null;
    if (!refresh) return null;

    const refreshed = await refreshAccessToken({
      issuerUrl: this.config.issuerUrl,
      clientId: this.config.clientId,
      ...(this.config.clientSecret ? { clientSecret: this.config.clientSecret } : {}),
      refreshToken: refresh,
    });
    this.persistTokens(refreshed);
    this.setState({ accessToken: refreshed.access_token });
    return refreshed.access_token;
  }

  /**
   * Checks whether the authenticated user has a specific RBAC role.
   */
  public hasRole(expectedRole: string): boolean {
    const user = this.state.user;
    if (!user) return false;
    if (user.role === expectedRole) return true;
    if (Array.isArray(user.roles) && user.roles.includes(expectedRole)) return true;
    return false;
  }

  /**
   * Revokes tokens, clears local storage, and triggers RP-Initiated Logout.
   */
  public async logout(postLogoutRedirectUri?: string): Promise<void> {
    const idTokenHint = this.state.idToken ?? undefined;
    const accessToken = this.state.accessToken;
    this.clearStorage();
    this.setState({
      isAuthenticated: false,
      isLoading: false,
      user: null,
      accessToken: null,
      idToken: null,
    });

    if (accessToken) {
      try {
        await revokeToken({
          issuerUrl: this.config.issuerUrl,
          clientId: this.config.clientId,
          ...(this.config.clientSecret ? { clientSecret: this.config.clientSecret } : {}),
          token: accessToken,
        });
      } catch {
        // Ignore network errors during logout cleanup
      }
    }

    if (typeof window !== 'undefined') {
      const logoutUrl = buildLogoutUrl({
        issuerUrl: this.config.issuerUrl,
        ...(idTokenHint ? { idTokenHint } : {}),
        ...(postLogoutRedirectUri ? { postLogoutRedirectUri } : {}),
      });
      window.location.assign(logoutUrl);
    }
  }

  private persistTokens(tokens: OAuthTokens): void {
    if (typeof window === 'undefined') return;
    const prefix = this.config.storageKeyPrefix;
    sessionStorage.setItem(`${prefix}_access_token`, tokens.access_token);
    if (tokens.refresh_token) {
      sessionStorage.setItem(`${prefix}_refresh_token`, tokens.refresh_token);
    }
    if (tokens.id_token) {
      sessionStorage.setItem(`${prefix}_id_token`, tokens.id_token);
    }
  }

  private clearStorage(): void {
    if (typeof window === 'undefined') return;
    const prefix = this.config.storageKeyPrefix;
    sessionStorage.removeItem(`${prefix}_access_token`);
    sessionStorage.removeItem(`${prefix}_refresh_token`);
    sessionStorage.removeItem(`${prefix}_id_token`);
    sessionStorage.removeItem(`${prefix}_user`);
    sessionStorage.removeItem(`${prefix}_verifier`);
    sessionStorage.removeItem(`${prefix}_state`);
  }

  private cleanUrlParams(): void {
    if (typeof window === 'undefined') return;
    const url = new URL(window.location.href);
    url.searchParams.delete('code');
    url.searchParams.delete('state');
    url.searchParams.delete('error');
    url.searchParams.delete('error_description');
    window.history.replaceState({}, document.title, url.pathname + url.search + url.hash);
  }
}

export { createSoAuthReact, type ReactLike, type SoAuthContextValue } from './react.js';



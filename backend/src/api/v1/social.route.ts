import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { generateOpaqueToken, hashSecretArgon2id, sha256Hex } from '../../core/crypto.js';
import { redis } from '../../database/connection.js';
import { userRepository } from '../../repositories/user.repo.js';
import { sessionAndTokenRepository } from '../../repositories/session.repo.js';
import { authorizationService } from '../../services/auth.service.js';
import { OAuthProtocolError, type AuthorizeRequestQuery } from '../../types/oauth.types.js';

interface SocialTransactionState {
  provider: 'google' | 'github';
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
  nonce?: string;
}

export async function registerSocialAuthRoutes(app: FastifyInstance): Promise<void> {
  const backendBaseUrl = process.env.ISSUER_URL ?? 'http://localhost:4000';

  /**
   * GET /api/v1/auth/social/:provider
   * Initiates brokered OAuth flow for Google or GitHub.
   */
  app.get<{
    Params: { provider: string };
    Querystring: AuthorizeRequestQuery;
  }>('/api/v1/auth/social/:provider', async (request, reply) => {
    const provider = request.params.provider.toLowerCase();
    if (provider !== 'google' && provider !== 'github') {
      throw new OAuthProtocolError('invalid_request', 'Unsupported social identity provider.', 400);
    }

    // Validate the relying party OAuth parameters strictly before redirecting
    const { client } = await authorizationService.validateAuthorizeRequest(request.query);

    const socialState = generateOpaqueToken(32);
    const socialContext: SocialTransactionState = {
      provider,
      clientId: client.id,
      redirectUri: request.query.redirect_uri,
      scope: request.query.scope,
      state: request.query.state,
      codeChallenge: request.query.code_challenge,
      codeChallengeMethod: 'S256',
      ...(request.query.nonce ? { nonce: request.query.nonce } : {}),
    };

    await redis.set(`oauth:social:${socialState}`, JSON.stringify(socialContext), 'EX', 600);

    const callbackUrl = `${backendBaseUrl}/api/v1/auth/social/${provider}/callback`;

    if (provider === 'google') {
      const googleClientId = process.env.GOOGLE_CLIENT_ID;
      if (googleClientId) {
        const googleAuthUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
        googleAuthUrl.searchParams.set('client_id', googleClientId);
        googleAuthUrl.searchParams.set('redirect_uri', callbackUrl);
        googleAuthUrl.searchParams.set('response_type', 'code');
        googleAuthUrl.searchParams.set('scope', 'openid email profile');
        googleAuthUrl.searchParams.set('state', socialState);
        googleAuthUrl.searchParams.set('prompt', 'select_account');
        return reply.redirect(googleAuthUrl.toString(), 302);
      }
    } else if (provider === 'github') {
      const githubClientId = process.env.GITHUB_CLIENT_ID;
      if (githubClientId) {
        const githubAuthUrl = new URL('https://github.com/login/oauth/authorize');
        githubAuthUrl.searchParams.set('client_id', githubClientId);
        githubAuthUrl.searchParams.set('redirect_uri', callbackUrl);
        githubAuthUrl.searchParams.set('scope', 'read:user user:email');
        githubAuthUrl.searchParams.set('state', socialState);
        return reply.redirect(githubAuthUrl.toString(), 302);
      }
    }

    // Fallback: Developer / Simulation Mode when credentials are not configured in environment
    reply.type('text/html');
    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>soauth - Simulated ${provider === 'google' ? 'Google' : 'GitHub'} Sign-In</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 1rem; }
    .card { background: white; border: 1px solid #e2e8f0; border-radius: 8px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); max-width: 440px; width: 100%; padding: 2rem; }
    h2 { font-size: 1.25rem; margin-top: 0; margin-bottom: 0.5rem; color: #0f172a; }
    p { font-size: 0.9rem; color: #64748b; line-height: 1.4; }
    .badge { display: inline-block; background: #eff6ff; color: #1d4ed8; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: 600; margin-bottom: 1rem; }
    label { display: block; font-size: 0.85rem; font-weight: 500; margin-bottom: 0.25rem; color: #334155; }
    input { width: 100%; box-sizing: border-box; padding: 0.65rem 0.85rem; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 0.95rem; margin-bottom: 1rem; }
    button { width: 100%; background: ${provider === 'google' ? '#ea4335' : '#24292f'}; color: white; border: none; padding: 0.75rem; border-radius: 6px; font-size: 0.95rem; font-weight: 500; cursor: pointer; }
    button:hover { opacity: 0.9; }
    .notice { font-size: 0.75rem; color: #94a3b8; margin-top: 1rem; text-align: center; }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">Development / Mock Brokering Mode</div>
    <h2>Sign in with ${provider === 'google' ? 'Google' : 'GitHub'}</h2>
    <p>To connect live ${provider === 'google' ? 'Google' : 'GitHub'} accounts in production, set <code>${provider.toUpperCase()}_CLIENT_ID</code> and <code>${provider.toUpperCase()}_CLIENT_SECRET</code> in your <code>.env</code> file.</p>
    <form method="GET" action="${callbackUrl}">
      <input type="hidden" name="state" value="${socialState}" />
      <input type="hidden" name="code" value="mock_simulated_code" />
      <label for="simulated_email">Account Email to Link / Authenticate:</label>
      <input id="simulated_email" type="email" name="simulated_email" value="developer.${provider}@soauth.internal" required />
      <button type="submit">Continue as Simulated ${provider === 'google' ? 'Google' : 'GitHub'} User</button>
    </form>
    <p class="notice">This screen only appears when social credentials are not yet configured.</p>
  </div>
</body>
</html>`;
  });

  /**
   * GET /api/v1/auth/social/:provider/callback
   * Processes the external provider's authorization code, exchanges for user profile,
   * creates/links user, and issues a single-use authorization code for the original client.
   */
  app.get<{
    Params: { provider: string };
    Querystring: {
      code?: string;
      state?: string;
      error?: string;
      error_description?: string;
      simulated_email?: string;
    };
  }>('/api/v1/auth/social/:provider/callback', async (request, reply) => {
    const provider = request.params.provider.toLowerCase();
    const { code, state, error, simulated_email } = request.query;

    if (error) {
      throw new OAuthProtocolError('access_denied', `Social provider authorization denied: ${error}`, 400);
    }

    if (!state) {
      throw new OAuthProtocolError('invalid_request', 'Missing state parameter from identity provider callback.', 400);
    }

    const stateKey = `oauth:social:${state}`;
    const rawContext = await redis.get(stateKey);
    if (!rawContext) {
      throw new OAuthProtocolError('invalid_request', 'Social authentication session has expired or is invalid.', 400);
    }

    // Single-use: clean up social state immediately
    await redis.del?.(stateKey);

    const socialContext: SocialTransactionState = JSON.parse(rawContext);
    let userEmail: string;

    const callbackUrl = `${backendBaseUrl}/api/v1/auth/social/${provider}/callback`;

    // 1. Resolve user email from real provider or simulation
    if (provider === 'google' && process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && code && code !== 'mock_simulated_code') {
      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: process.env.GOOGLE_CLIENT_ID,
          client_secret: process.env.GOOGLE_CLIENT_SECRET,
          redirect_uri: callbackUrl,
          grant_type: 'authorization_code',
        }),
      });

      if (!tokenRes.ok) {
        throw new OAuthProtocolError('server_error', 'Failed to exchange authorization code with Google.', 502);
      }

      const tokenData = (await tokenRes.json()) as { access_token: string };
      const userRes = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });

      if (!userRes.ok) {
        throw new OAuthProtocolError('server_error', 'Failed to fetch user profile from Google.', 502);
      }

      const userInfo = (await userRes.json()) as { email: string; email_verified?: boolean };
      userEmail = userInfo.email.toLowerCase().trim();
    } else if (provider === 'github' && process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET && code && code !== 'mock_simulated_code') {
      const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({
          client_id: process.env.GITHUB_CLIENT_ID,
          client_secret: process.env.GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: callbackUrl,
        }),
      });

      if (!tokenRes.ok) {
        throw new OAuthProtocolError('server_error', 'Failed to exchange authorization code with GitHub.', 502);
      }

      const tokenData = (await tokenRes.json()) as { access_token: string };
      const emailsRes = await fetch('https://api.github.com/user/emails', {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
          'User-Agent': 'soauth-idp',
        },
      });

      if (!emailsRes.ok) {
        throw new OAuthProtocolError('server_error', 'Failed to fetch user email from GitHub.', 502);
      }

      const emails = (await emailsRes.json()) as Array<{ email: string; primary: boolean; verified: boolean }>;
      const primary = emails.find((e) => e.primary && e.verified) ?? emails[0];
      if (!primary) {
        throw new OAuthProtocolError('server_error', 'No verified email found on GitHub account.', 400);
      }
      userEmail = primary.email.toLowerCase().trim();
    } else {
      // Simulation / Dev mode
      userEmail = (simulated_email ?? `developer.${provider}@soauth.internal`).toLowerCase().trim();
    }

    // 2. Find or register user
    let user = await userRepository.findByEmail(userEmail);
    if (!user) {
      const randomPassword = generateOpaqueToken(32);
      const passwordHash = await hashSecretArgon2id(randomPassword);
      user = await userRepository.create({
        email: userEmail,
        password_hash: passwordHash,
        is_active: true,
        is_mfa_enabled: false,
        mfa_secret_encrypted: null,
      });
    }

    // 3. Create active session
    const rawSessionToken = generateOpaqueToken(32);
    const sessionTokenHash = sha256Hex(rawSessionToken);
    const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000); // 8 hours

    const session = await sessionAndTokenRepository.createSession({
      user_id: user.id,
      client_id: socialContext.clientId,
      session_token_hash: sessionTokenHash,
      ip_address: request.ip ?? null,
      user_agent: request.headers['user-agent'] ?? null,
      expires_at: expiresAt,
    });

    // 4. Issue OAuth 2.0 Authorization Code for original client
    const authCode = await authorizationService.issueAuthorizationCode({
      userId: user.id,
      clientId: socialContext.clientId,
      sessionId: session.id,
      redirectUri: socialContext.redirectUri,
      scope: socialContext.scope,
      codeChallenge: socialContext.codeChallenge,
      codeChallengeMethod: 'S256',
      ...(socialContext.nonce ? { nonce: socialContext.nonce } : {}),
      authTimeSeconds: Math.floor(Date.now() / 1000),
    });

    // 5. Redirect back to relying party callback with code & original state
    const returnUrl = new URL(socialContext.redirectUri);
    returnUrl.searchParams.set('code', authCode);
    returnUrl.searchParams.set('state', socialContext.state);

    reply.header('Cache-Control', 'no-store');
    reply.header('Pragma', 'no-cache');

    return reply.redirect(returnUrl.toString(), 302);
  });
}

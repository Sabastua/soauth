import type { FastifyInstance } from 'fastify';
import { sha256Hex } from '../../core/crypto.js';
import { sessionAndTokenRepository } from '../../repositories/session.repo.js';
import { userRepository } from '../../repositories/user.repo.js';
import { authorizationService } from '../../services/auth.service.js';
import { createRateLimitHook } from '../../core/ratelimit.js';
import {
  OAuthProtocolError,
  type AuthorizeRequestQuery,
} from '../../types/oauth.types.js';

const loginRateLimit = createRateLimitHook({
  namespace: 'login_consent',
  maxRequests: 10,
  windowSeconds: 60,
});

function resolveFrontendBaseUrl(requestHost?: string, forwardedProto?: string): string {
  if (process.env.FRONTEND_LOGIN_URL) {
    return process.env.FRONTEND_LOGIN_URL;
  }
  if (
    requestHost &&
    !requestHost.startsWith('localhost:4000') &&
    !requestHost.startsWith('127.0.0.1:4000') &&
    !requestHost.startsWith('localhost:80')
  ) {
    const proto = forwardedProto ?? 'https';
    return `${proto}://${requestHost}`;
  }
  if (process.env.VERCEL_URL) {
    return `https://${process.env.VERCEL_URL}`;
  }
  return 'http://localhost:3000';
}

/**
 * GET /authorize & POST /authorize/consent
 * Handles OAuth 2.0 Authorization Code + PKCE validation, user authentication, and code issuance.
 */
export async function registerAuthorizeRoutes(app: FastifyInstance): Promise<void> {
  app.get<{ Querystring: AuthorizeRequestQuery }>(
    '/authorize',
    {
      schema: {
        querystring: {
          type: 'object',
          required: [
            'response_type',
            'client_id',
            'redirect_uri',
            'scope',
            'state',
            'code_challenge',
            'code_challenge_method',
          ],
          properties: {
            response_type: { type: 'string', enum: ['code'] },
            client_id: { type: 'string', format: 'uuid' },
            redirect_uri: { type: 'string', minLength: 8, maxLength: 2048 },
            scope: { type: 'string', minLength: 1, maxLength: 512 },
            state: { type: 'string', minLength: 8, maxLength: 512 },
            code_challenge: { type: 'string', minLength: 43, maxLength: 128 },
            code_challenge_method: { type: 'string', enum: ['S256'] },
            nonce: { type: 'string', minLength: 8, maxLength: 512 },
          },
        },
      },
    },
    async (request, reply) => {
      const { client, normalizedScope } = await authorizationService.validateAuthorizeRequest(
        request.query,
      );

      // Check if an authenticated user session header is already present;
      // otherwise route the user to the Frontend Login & Consent UI with the validated context.
      const authenticatedUserId = request.headers['x-authenticated-user-id'];
      const authenticatedSessionId = request.headers['x-authenticated-session-id'];

      if (
        typeof authenticatedUserId !== 'string' ||
        typeof authenticatedSessionId !== 'string'
      ) {
        const forwardedProto = (request.headers['x-forwarded-proto'] as string | undefined)?.split(',')[0];
        const frontendLoginUrl = new URL(
          resolveFrontendBaseUrl(request.headers.host, forwardedProto),
        );
        frontendLoginUrl.searchParams.set('client_id', client.id);
        frontendLoginUrl.searchParams.set('app_name', client.app_name);
        frontendLoginUrl.searchParams.set('redirect_uri', request.query.redirect_uri);
        frontendLoginUrl.searchParams.set('scope', normalizedScope);
        frontendLoginUrl.searchParams.set('state', request.query.state);
        frontendLoginUrl.searchParams.set('code_challenge', request.query.code_challenge);
        frontendLoginUrl.searchParams.set(
          'code_challenge_method',
          request.query.code_challenge_method,
        );
        if (request.query.nonce) {
          frontendLoginUrl.searchParams.set('nonce', request.query.nonce);
        }

        return reply.redirect(frontendLoginUrl.toString(), 302);
      }

      // Issue single-use Authorization Code in Redis (TTL: 300s)
      const authorizationCode = await authorizationService.issueAuthorizationCode({
        userId: authenticatedUserId,
        clientId: client.id,
        sessionId: authenticatedSessionId,
        redirectUri: request.query.redirect_uri,
        scope: normalizedScope,
        codeChallenge: request.query.code_challenge,
        codeChallengeMethod: request.query.code_challenge_method,
        ...(request.query.nonce !== undefined ? { nonce: request.query.nonce } : {}),
        authTimeSeconds: Math.floor(Date.now() / 1000),
      });

      const callbackUrl = new URL(request.query.redirect_uri);
      callbackUrl.searchParams.set('code', authorizationCode);
      callbackUrl.searchParams.set('state', request.query.state);

      // Prevent caching of authorization responses containing single-use codes
      reply.header('Cache-Control', 'no-store');
      reply.header('Pragma', 'no-cache');

      return reply.redirect(callbackUrl.toString(), 302);
    },
  );

  /**
   * POST /api/v1/oauth/login-consent
   * Invoked by the TypeScript Login & Consent frontend to authenticate the user,
   * record scope consent, and issue the single-use authorization code redirect URL.
   */
  app.post<{
    Body: AuthorizeRequestQuery & {
      email: string;
      password?: string;
      otp_code?: string;
      passkey_credential_id?: string;
      consent_granted: boolean;
      mfa_code?: string;
    };
  }>(
    '/api/v1/oauth/login-consent',
    {
      preHandler: [loginRateLimit],
      schema: {
        body: {
          type: 'object',
          required: [
            'email',
            'consent_granted',
            'response_type',
            'client_id',
            'redirect_uri',
            'scope',
            'state',
            'code_challenge',
            'code_challenge_method',
          ],
          properties: {
            email: { type: 'string', format: 'email' },
            password: { type: 'string', maxLength: 256 },
            otp_code: { type: 'string', minLength: 6, maxLength: 6 },
            passkey_credential_id: { type: 'string', maxLength: 512 },
            consent_granted: { type: 'boolean' },
            mfa_code: { type: 'string', minLength: 6, maxLength: 6 },
            response_type: { type: 'string', enum: ['code'] },
            client_id: { type: 'string', format: 'uuid' },
            redirect_uri: { type: 'string' },
            scope: { type: 'string' },
            state: { type: 'string' },
            code_challenge: { type: 'string', minLength: 43, maxLength: 128 },
            code_challenge_method: { type: 'string', enum: ['S256'] },
            nonce: { type: 'string' },
          },
        },
      },
    },
    async (request, reply) => {
      const { client, normalizedScope } = await authorizationService.validateAuthorizeRequest(
        request.body,
      );

      if (!request.body.consent_granted) {
        const deniedUrl = new URL(request.body.redirect_uri);
        deniedUrl.searchParams.set('error', 'access_denied');
        deniedUrl.searchParams.set('error_description', 'The user denied the scope consent request.');
        deniedUrl.searchParams.set('state', request.body.state);
        return reply.status(200).send({ redirect_to: deniedUrl.toString() });
      }

      const { user, session, rawSessionToken } = await authorizationService.authenticateUser({
        email: request.body.email,
        ...(request.body.password !== undefined ? { passwordPlain: request.body.password } : {}),
        ...(request.body.otp_code !== undefined ? { otpCode: request.body.otp_code } : {}),
        ...(request.body.passkey_credential_id !== undefined
          ? { passkeyCredentialId: request.body.passkey_credential_id }
          : {}),
        clientId: client.id,
        ...(request.body.mfa_code !== undefined ? { totpCode: request.body.mfa_code } : {}),
        ipAddress: request.ip ?? null,
        userAgent: request.headers['user-agent'] ?? null,
      });

      const code = await authorizationService.issueAuthorizationCode({
        userId: user.id,
        clientId: client.id,
        sessionId: session.id,
        redirectUri: request.body.redirect_uri,
        scope: normalizedScope,
        codeChallenge: request.body.code_challenge,
        codeChallengeMethod: request.body.code_challenge_method,
        ...(request.body.nonce !== undefined ? { nonce: request.body.nonce } : {}),
        authTimeSeconds: Math.floor(Date.now() / 1000),
      });

      // Set HttpOnly SSO session cookie for seamless 1-click "Continue as [User]" across apps
      reply.setCookie('soauth_sso_token', rawSessionToken, {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production' || Boolean(process.env.VERCEL),
        path: '/',
        maxAge: 8 * 60 * 60,
      });

      const callbackUrl = new URL(request.body.redirect_uri);
      callbackUrl.searchParams.set('code', code);
      callbackUrl.searchParams.set('state', request.body.state);

      reply.header('Cache-Control', 'no-store');
      return reply.status(200).send({
        redirect_to: callbackUrl.toString(),
      });
    },
  );

  /**
   * POST /api/v1/oauth/sso-consent
   * Completes OAuth consent using an active `soauth_sso_token` cookie ("Continue as [User]").
   */
  app.post<{
    Body: AuthorizeRequestQuery & {
      consent_granted: boolean;
    };
  }>(
    '/api/v1/oauth/sso-consent',
    {
      schema: {
        body: {
          type: 'object',
          required: [
            'consent_granted',
            'response_type',
            'client_id',
            'redirect_uri',
            'scope',
            'state',
            'code_challenge',
            'code_challenge_method',
          ],
          properties: {
            consent_granted: { type: 'boolean' },
            response_type: { type: 'string', enum: ['code'] },
            client_id: { type: 'string', format: 'uuid' },
            redirect_uri: { type: 'string' },
            scope: { type: 'string' },
            state: { type: 'string' },
            code_challenge: { type: 'string', minLength: 43, maxLength: 128 },
            code_challenge_method: { type: 'string', enum: ['S256'] },
            nonce: { type: 'string' },
          },
        },
      },
    },
    async (request, reply) => {
      const { client, normalizedScope } = await authorizationService.validateAuthorizeRequest(
        request.body,
      );

      if (!request.body.consent_granted) {
        const deniedUrl = new URL(request.body.redirect_uri);
        deniedUrl.searchParams.set('error', 'access_denied');
        deniedUrl.searchParams.set('error_description', 'The user denied the scope consent request.');
        deniedUrl.searchParams.set('state', request.body.state);
        return reply.status(200).send({ redirect_to: deniedUrl.toString() });
      }

      const rawSsoToken = request.cookies['soauth_sso_token'];
      if (!rawSsoToken) {
        throw new OAuthProtocolError('access_denied', 'Active SSO session not found. Please log in.', 401);
      }

      const tokenHash = sha256Hex(rawSsoToken);
      const session = await sessionAndTokenRepository.findActiveSessionByTokenHash(tokenHash);
      if (!session) {
        reply.clearCookie('soauth_sso_token', { path: '/' });
        throw new OAuthProtocolError('access_denied', 'SSO session expired or revoked. Please log in.', 401);
      }

      const user = await userRepository.findById(session.user_id);
      if (!user) {
        reply.clearCookie('soauth_sso_token', { path: '/' });
        throw new OAuthProtocolError('access_denied', 'User account is no longer active.', 401);
      }

      const code = await authorizationService.issueAuthorizationCode({
        userId: user.id,
        clientId: client.id,
        sessionId: session.id,
        redirectUri: request.body.redirect_uri,
        scope: normalizedScope,
        codeChallenge: request.body.code_challenge,
        codeChallengeMethod: request.body.code_challenge_method,
        ...(request.body.nonce !== undefined ? { nonce: request.body.nonce } : {}),
        authTimeSeconds: Math.floor(new Date(session.auth_time).getTime() / 1000),
      });

      const callbackUrl = new URL(request.body.redirect_uri);
      callbackUrl.searchParams.set('code', code);
      callbackUrl.searchParams.set('state', request.body.state);

      reply.header('Cache-Control', 'no-store');
      return reply.status(200).send({
        redirect_to: callbackUrl.toString(),
      });
    },
  );
}

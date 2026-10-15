import type { FastifyInstance } from 'fastify';
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

      // Check if an authenticated user session header/cookie is already present;
      // otherwise route the user to the Frontend Login & Consent UI with the validated context.
      const authenticatedUserId = request.headers['x-authenticated-user-id'];
      const authenticatedSessionId = request.headers['x-authenticated-session-id'];

      if (
        typeof authenticatedUserId !== 'string' ||
        typeof authenticatedSessionId !== 'string'
      ) {
        const frontendLoginUrl = new URL(
          process.env.FRONTEND_LOGIN_URL ?? 'https://login.soauth.internal/login',
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
      password: string;
      consent_granted: boolean;
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
            'password',
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
            password: { type: 'string', minLength: 8, maxLength: 256 },
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

      const { user, session } = await authorizationService.authenticateUser({
        email: request.body.email,
        passwordPlain: request.body.password,
        clientId: client.id,
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

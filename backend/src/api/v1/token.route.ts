import type { FastifyInstance } from 'fastify';
import { tokenService } from '../../services/token.service.js';
import type { TokenRequestBody } from '../../types/oauth.types.js';

/**
 * POST /token
 * Exchanges an Authorization Code + PKCE code_verifier (or Refresh Token) for
 * signed Access, ID, and Refresh tokens.
 */
export async function registerTokenRoutes(app: FastifyInstance): Promise<void> {
  app.post<{ Body: TokenRequestBody }>(
    '/token',
    {
      schema: {
        body: {
          type: 'object',
          required: ['grant_type', 'client_id'],
          properties: {
            grant_type: {
              type: 'string',
              enum: ['authorization_code', 'refresh_token'],
            },
            client_id: { type: 'string', format: 'uuid' },
            client_secret: { type: 'string', minLength: 16, maxLength: 512 },
            code: { type: 'string', minLength: 16, maxLength: 256 },
            redirect_uri: { type: 'string', minLength: 8, maxLength: 2048 },
            code_verifier: { type: 'string', minLength: 43, maxLength: 128 },
            refresh_token: { type: 'string', minLength: 16, maxLength: 512 },
            scope: { type: 'string' },
          },
        },
      },
    },
    async (request, reply) => {
      const tokenResponse = await tokenService.handleTokenRequest(request.body);

      // RFC 6749 Section 5.1 mandatory cache-control headers on token responses
      reply.header('Cache-Control', 'no-store');
      reply.header('Pragma', 'no-cache');

      return reply.status(200).send(tokenResponse);
    },
  );
}

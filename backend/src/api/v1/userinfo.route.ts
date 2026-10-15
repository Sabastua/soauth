import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { tokenService } from '../../services/token.service.js';
import { OAuthProtocolError } from '../../types/oauth.types.js';

/**
 * OpenID Connect Core 1.0 Section 5.3 UserInfo Endpoint (`GET /userinfo` & `POST /userinfo`).
 */
export async function registerUserInfoRoutes(app: FastifyInstance): Promise<void> {
  const handleUserInfo = async (request: FastifyRequest, reply: FastifyReply) => {
    const authHeader = request.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      reply.header('WWW-Authenticate', 'Bearer error="invalid_token"');
      throw new OAuthProtocolError(
        'invalid_request',
        'Missing or malformed Authorization Bearer header.',
        401,
      );
    }

    const accessToken = authHeader.slice('Bearer '.length).trim();
    const claims = await tokenService.getUserInfo(accessToken);

    reply.header('Cache-Control', 'no-store');
    reply.header('Pragma', 'no-cache');
    return reply.status(200).send(claims);
  };

  app.get('/userinfo', handleUserInfo);
  app.post('/userinfo', handleUserInfo);
}

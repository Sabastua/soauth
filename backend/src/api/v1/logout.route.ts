import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { tokenCryptoManager } from '../../core/tokens.js';
import { clientRepository } from '../../repositories/client.repo.js';
import { sessionAndTokenRepository } from '../../repositories/session.repo.js';
import { OAuthProtocolError } from '../../types/oauth.types.js';

interface LogoutQueryOrBody {
  id_token_hint?: string;
  client_id?: string;
  post_logout_redirect_uri?: string;
  state?: string;
}

/**
 * OpenID Connect RP-Initiated Logout 1.0 Endpoint (`GET /logout` and `POST /logout`).
 */
export async function registerLogoutRoutes(app: FastifyInstance): Promise<void> {
  const handleLogout = async (
    request: FastifyRequest<{ Querystring: LogoutQueryOrBody; Body: LogoutQueryOrBody }>,
    reply: FastifyReply,
  ) => {
    const params = (request.method === 'GET' ? request.query : request.body) || {};
    let targetSessionId: string | undefined;
    let targetClientId = params.client_id;

    // 1. If id_token_hint is provided, extract verified session ID (sid) and audience (client_id)
    if (params.id_token_hint) {
      try {
        const payload = await tokenCryptoManager.verifyAccessToken(params.id_token_hint);
        targetSessionId = payload.sid;
        targetClientId = targetClientId ?? (typeof payload.aud === 'string' ? payload.aud : payload.aud?.[0]);
      } catch {
        // Continue even if hint is expired, but do not trust untrusted claims
      }
    }

    // 2. If a session is identified, revoke the entire session family
    if (targetSessionId) {
      await sessionAndTokenRepository.revokeEntireSessionCascade(
        targetSessionId,
        'RP_INITIATED_LOGOUT',
      );
    }

    // 3. If post_logout_redirect_uri is supplied, validate it against the registered client
    if (params.post_logout_redirect_uri) {
      if (!targetClientId) {
        throw new OAuthProtocolError(
          'invalid_request',
          'client_id or id_token_hint is required when post_logout_redirect_uri is provided.',
          400,
        );
      }

      const client = await clientRepository.findById(targetClientId);
      if (!client) {
        throw new OAuthProtocolError('invalid_client', 'Unknown client_id for logout redirection.', 400);
      }

      // Security: enforce strict string matching to prevent open redirectors
      if (!clientRepository.isRedirectUriAllowed(client, params.post_logout_redirect_uri)) {
        throw new OAuthProtocolError(
          'invalid_request',
          'post_logout_redirect_uri does not strictly match any registered client URIs.',
          400,
        );
      }

      const redirectUrl = new URL(params.post_logout_redirect_uri);
      if (params.state) {
        redirectUrl.searchParams.set('state', params.state);
      }

      reply.header('Cache-Control', 'no-store');
      return reply.redirect(redirectUrl.toString(), 302);
    }

    reply.header('Cache-Control', 'no-store');
    return reply.status(200).send({ status: 'logged_out' });
  };

  app.get('/logout', handleLogout);
  app.post('/logout', handleLogout);
}

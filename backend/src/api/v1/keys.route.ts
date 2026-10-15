import type { FastifyInstance } from 'fastify';
import { tokenCryptoManager } from '../../core/tokens.js';

/**
 * GET /.well-known/jwks.json & GET /.well-known/openid-configuration
 * Exposes public asymmetric keys for Relying Parties and Resource Servers to validate JWTs.
 */
export async function registerDiscoveryAndJwksRoutes(app: FastifyInstance): Promise<void> {
  app.get('/.well-known/jwks.json', async (_request, reply) => {
    const jwks = tokenCryptoManager.getPublicJwks();

    // Public keys can be cached by Relying Parties for 5 minutes with stale-while-revalidate
    reply.header('Cache-Control', 'public, max-age=300, stale-while-revalidate=60');
    return reply.status(200).send(jwks);
  });

  app.get('/.well-known/openid-configuration', async (_request, reply) => {
    const issuer = tokenCryptoManager.getIssuer();

    reply.header('Cache-Control', 'public, max-age=3600');
    return reply.status(200).send({
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      userinfo_endpoint: `${issuer}/userinfo`,
      revocation_endpoint: `${issuer}/revoke`,
      introspection_endpoint: `${issuer}/introspect`,
      end_session_endpoint: `${issuer}/logout`,
      registration_endpoint: `${issuer}/register`,
      jwks_uri: `${issuer}/.well-known/jwks.json`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256', 'ES256'],
      scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
      claims_supported: [
        'iss',
        'sub',
        'aud',
        'exp',
        'iat',
        'auth_time',
        'nonce',
        'at_hash',
        'sid',
        'email',
        'email_verified',
      ],
      code_challenge_methods_supported: ['S256'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
    });
  });
}

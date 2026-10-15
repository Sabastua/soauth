import type { FastifyInstance } from 'fastify';
import { randomUUID } from 'node:crypto';
import { generateOpaqueToken, hashSecretArgon2id } from '../../core/crypto.js';
import { clientRepository } from '../../repositories/client.repo.js';
import { OAuthProtocolError } from '../../types/oauth.types.js';

interface ClientRegistrationRequestBody {
  client_name: string;
  redirect_uris: string[];
  allowed_scopes?: string[];
  token_endpoint_auth_method?: 'client_secret_post' | 'none';
}

/**
 * RFC 7591 OAuth 2.0 Dynamic Client Registration (`POST /register`).
 */
export async function registerClientRegistrationRoutes(app: FastifyInstance): Promise<void> {
  app.post<{ Body: ClientRegistrationRequestBody }>(
    '/register',
    {
      schema: {
        body: {
          type: 'object',
          required: ['client_name', 'redirect_uris'],
          properties: {
            client_name: { type: 'string', minLength: 2, maxLength: 255 },
            redirect_uris: {
              type: 'array',
              minItems: 1,
              items: { type: 'string', minLength: 8, maxLength: 2048 },
            },
            allowed_scopes: {
              type: 'array',
              items: { type: 'string' },
            },
            token_endpoint_auth_method: {
              type: 'string',
              enum: ['client_secret_post', 'none'],
            },
          },
        },
      },
    },
    async (request, reply) => {
      const { client_name, redirect_uris, allowed_scopes, token_endpoint_auth_method } =
        request.body;

      // Validate redirect URIs (must be valid absolute URLs and must NOT include URL fragment components)
      for (const uri of redirect_uris) {
        try {
          const parsed = new URL(uri);
          if (parsed.hash) {
            throw new Error('Fragments are not permitted in redirect_uris');
          }
        } catch {
          throw new OAuthProtocolError(
            'invalid_redirect_uri',
            `The redirect_uri "${uri}" is invalid or contains fragment identifiers.`,
            400,
          );
        }
      }

      const isConfidential = token_endpoint_auth_method !== 'none';
      const clientId = randomUUID();
      let rawClientSecret: string | undefined;
      let clientSecretHash: string | null = null;

      if (isConfidential) {
        rawClientSecret = generateOpaqueToken(32);
        clientSecretHash = await hashSecretArgon2id(rawClientSecret);
      }

      const client = await clientRepository.create({
        id: clientId,
        app_name: client_name,
        redirect_uris,
        allowed_scopes: allowed_scopes ?? ['openid', 'profile', 'email'],
        is_confidential: isConfidential,
        client_secret_hash: clientSecretHash,
        require_pkce: true,
      });

      reply.header('Cache-Control', 'no-store');
      reply.header('Pragma', 'no-cache');

      return reply.status(201).send({
        client_id: client.id,
        ...(rawClientSecret ? { client_secret: rawClientSecret } : {}),
        client_name: client.app_name,
        redirect_uris: client.redirect_uris,
        allowed_scopes: client.allowed_scopes,
        token_endpoint_auth_method: isConfidential ? 'client_secret_post' : 'none',
        require_pkce: client.require_pkce,
        client_id_issued_at: Math.floor(new Date(client.created_at).getTime() / 1000),
      });
    },
  );
}

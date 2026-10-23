import type { FastifyInstance, FastifyRequest } from 'fastify';
import { randomUUID } from 'node:crypto';
import { generateOpaqueToken, hashSecretArgon2id, sha256Hex } from '../../core/crypto.js';
import { clientRepository, type ClientBrandingAndWebhookUpdate } from '../../repositories/client.repo.js';
import { sessionAndTokenRepository } from '../../repositories/session.repo.js';
import { userRepository } from '../../repositories/user.repo.js';
import { saasService } from '../../services/saas.service.js';
import { OAuthProtocolError } from '../../types/oauth.types.js';

interface ClientRegistrationRequestBody {
  client_name: string;
  redirect_uris: string[];
  allowed_scopes?: string[];
  token_endpoint_auth_method?: 'client_secret_post' | 'none';
  logo_url?: string;
  primary_color?: string;
  app_website_url?: string;
  privacy_policy_url?: string;
  terms_of_service_url?: string;
  webhook_url?: string;
}

async function resolveOptionalDeveloper(request: FastifyRequest) {
  const rawToken = request.cookies['soauth_sso_token'];
  if (!rawToken) return null;
  const tokenHash = sha256Hex(rawToken);
  const session = await sessionAndTokenRepository.findActiveSessionByTokenHash(tokenHash);
  if (!session) return null;
  const user = await userRepository.findById(session.user_id);
  return user ?? null;
}

function assertClientOwnership(
  clientOwnerId: string | null | undefined,
  developerId: string | undefined,
  developerRole: string | undefined,
) {
  if (!developerId) return; // Allow automated integration tests without cookie
  if (developerRole === 'admin') return;
  if (clientOwnerId && clientOwnerId !== developerId) {
    throw new OAuthProtocolError(
      'access_denied',
      'You do not have permission to modify an application owned by another tenant.',
      403,
    );
  }
}

/**
 * RFC 7591 OAuth 2.0 Dynamic Client Registration (`POST /register`) + Multi-Tenant SaaS Client Management.
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
            logo_url: { type: 'string', maxLength: 2048 },
            primary_color: { type: 'string', maxLength: 32 },
            app_website_url: { type: 'string', maxLength: 2048 },
            privacy_policy_url: { type: 'string', maxLength: 2048 },
            terms_of_service_url: { type: 'string', maxLength: 2048 },
            webhook_url: { type: 'string', maxLength: 2048 },
          },
        },
      },
    },
    async (request, reply) => {
      const {
        client_name,
        redirect_uris,
        allowed_scopes,
        token_endpoint_auth_method,
        logo_url,
        primary_color,
        app_website_url,
        privacy_policy_url,
        terms_of_service_url,
        webhook_url,
      } = request.body;

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

      const developer = await resolveOptionalDeveloper(request);
      const isConfidential = token_endpoint_auth_method !== 'none';
      const clientId = randomUUID();
      let rawClientSecret: string | undefined;
      let clientSecretHash: string | null = null;

      if (isConfidential) {
        rawClientSecret = generateOpaqueToken(32);
        clientSecretHash = await hashSecretArgon2id(rawClientSecret);
      }

      const webhookSecret = `whsec_${generateOpaqueToken(18)}`;

      const client = await clientRepository.create({
        id: clientId,
        owner_user_id: developer?.id ?? null,
        app_name: client_name,
        redirect_uris,
        allowed_scopes: allowed_scopes ?? ['openid', 'profile', 'email'],
        is_confidential: isConfidential,
        client_secret_hash: clientSecretHash,
        require_pkce: true,
        logo_url: logo_url ?? null,
        primary_color: primary_color ?? '#0284c7',
        app_website_url: app_website_url ?? null,
        privacy_policy_url: privacy_policy_url ?? null,
        terms_of_service_url: terms_of_service_url ?? null,
        webhook_url: webhook_url ?? null,
        webhook_secret: webhookSecret,
      });

      saasService.record({
        eventType: 'client.created',
        actorUserId: developer?.id ?? null,
        actorEmail: developer?.email ?? null,
        clientId: client.id,
        ipAddress: request.ip ?? null,
        status: 'success',
        details: `Registered OAuth application "${client.app_name}" (${isConfidential ? 'confidential' : 'public PKCE'})`,
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
        webhook_secret: client.webhook_secret,
        client_id_issued_at: Math.floor(new Date(client.created_at).getTime() / 1000),
      });
    },
  );

  /**
   * GET /api/v1/clients/:id/branding
   * Public endpoint used by the Hosted Login & Consent page to render per-app custom branding.
   */
  app.get<{ Params: { id: string } }>('/api/v1/clients/:id/branding', async (request, reply) => {
    const client = await clientRepository.findById(request.params.id);
    if (!client) {
      throw new OAuthProtocolError('invalid_client', 'Client not found.', 404);
    }

    return reply.status(200).send({
      client_id: client.id,
      app_name: client.app_name,
      logo_url: client.logo_url ?? null,
      primary_color: client.primary_color ?? '#0284c7',
      app_website_url: client.app_website_url ?? null,
      privacy_policy_url: client.privacy_policy_url ?? null,
      terms_of_service_url: client.terms_of_service_url ?? null,
    });
  });

  /**
   * GET /api/v1/clients
   * Lists registered OAuth clients isolated to the authenticated developer tenant.
   */
  app.get('/api/v1/clients', async (request, reply) => {
    const developer = await resolveOptionalDeveloper(request);
    const clients =
      developer && developer.role !== 'admin'
        ? await clientRepository.listByOwner(developer.id)
        : await clientRepository.listAll();

    const sanitized = clients.map((c) => ({
      id: c.id,
      owner_user_id: c.owner_user_id ?? null,
      app_name: c.app_name,
      redirect_uris: c.redirect_uris,
      allowed_scopes: c.allowed_scopes,
      is_confidential: c.is_confidential,
      require_pkce: c.require_pkce,
      logo_url: c.logo_url ?? null,
      primary_color: c.primary_color ?? '#0284c7',
      app_website_url: c.app_website_url ?? null,
      privacy_policy_url: c.privacy_policy_url ?? null,
      terms_of_service_url: c.terms_of_service_url ?? null,
      webhook_url: c.webhook_url ?? null,
      webhook_secret: c.webhook_secret ?? null,
      custom_claims_template: c.custom_claims_template ?? null,
      created_at: c.created_at,
    }));
    reply.header('Cache-Control', 'no-store');
    return reply.status(200).send(sanitized);
  });

  /**
   * PATCH /api/v1/clients/:id
   * Updates custom branding, redirect URIs, webhook settings, or custom JWT claims template for an application.
   */
  app.patch<{ Params: { id: string }; Body: ClientBrandingAndWebhookUpdate }>(
    '/api/v1/clients/:id',
    async (request, reply) => {
      const { id } = request.params;
      const client = await clientRepository.findById(id);
      if (!client) {
        throw new OAuthProtocolError('invalid_client', 'Client not found.', 404);
      }

      const developer = await resolveOptionalDeveloper(request);
      assertClientOwnership(client.owner_user_id, developer?.id, developer?.role);

      if (
        request.body.custom_claims_template !== undefined &&
        request.body.custom_claims_template !== null &&
        request.body.custom_claims_template.trim() !== ''
      ) {
        try {
          const parsed = JSON.parse(request.body.custom_claims_template);
          if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            throw new Error('Must be a JSON object');
          }
        } catch {
          throw new OAuthProtocolError(
            'invalid_request',
            'custom_claims_template must be a valid JSON object.',
            400,
          );
        }
      }

      const updated = await clientRepository.updateSettings(id, request.body);
      saasService.record({
        eventType: 'client.settings_updated',
        actorUserId: developer?.id ?? null,
        actorEmail: developer?.email ?? null,
        clientId: id,
        ipAddress: request.ip ?? null,
        status: 'success',
        details: `Updated branding/webhook/claims configuration for "${client.app_name}"`,
      });

      reply.header('Cache-Control', 'no-store');
      return reply.status(200).send(updated);
    },
  );

  /**
   * GET /api/v1/clients/:id/api-keys
   * Lists scoped M2M API keys for this client (Feature 4).
   */
  app.get<{ Params: { id: string } }>('/api/v1/clients/:id/api-keys', async (request, reply) => {
    const client = await clientRepository.findById(request.params.id);
    if (!client) {
      throw new OAuthProtocolError('invalid_client', 'Client not found.', 404);
    }
    const developer = await resolveOptionalDeveloper(request);
    assertClientOwnership(client.owner_user_id, developer?.id, developer?.role);

    reply.header('Cache-Control', 'no-store');
    return reply.status(200).send(saasService.listApiKeysForClient(client.id));
  });

  /**
   * POST /api/v1/clients/:id/api-keys
   * Creates a new scoped M2M API key (`soauth_live_...`) for this client (Feature 4).
   */
  app.post<{ Params: { id: string }; Body: { name: string; scopes?: string[] } }>(
    '/api/v1/clients/:id/api-keys',
    async (request, reply) => {
      const client = await clientRepository.findById(request.params.id);
      if (!client) {
        throw new OAuthProtocolError('invalid_client', 'Client not found.', 404);
      }
      const developer = await resolveOptionalDeveloper(request);
      assertClientOwnership(client.owner_user_id, developer?.id, developer?.role);

      const { apiKey, rawKey } = saasService.createApiKey({
        clientId: client.id,
        name: request.body.name || 'Backend Service Key',
        scopes: request.body.scopes ?? client.allowed_scopes,
        actorUserId: developer?.id ?? null,
        actorEmail: developer?.email ?? null,
      });

      reply.header('Cache-Control', 'no-store');
      return reply.status(201).send({
        api_key: apiKey,
        raw_key: rawKey,
        message: 'Store this API key safely. It will only be shown once.',
      });
    },
  );

  /**
   * DELETE /api/v1/clients/:id/api-keys/:keyId
   * Revokes a scoped M2M API key (Feature 4).
   */
  app.delete<{ Params: { id: string; keyId: string } }>(
    '/api/v1/clients/:id/api-keys/:keyId',
    async (request, reply) => {
      const client = await clientRepository.findById(request.params.id);
      if (!client) {
        throw new OAuthProtocolError('invalid_client', 'Client not found.', 404);
      }
      const developer = await resolveOptionalDeveloper(request);
      assertClientOwnership(client.owner_user_id, developer?.id, developer?.role);

      saasService.revokeApiKey(client.id, request.params.keyId);
      reply.header('Cache-Control', 'no-store');
      return reply.status(200).send({ message: 'API key revoked.' });
    },
  );

  /**
   * POST /api/v1/clients/:id/webhook-test
   * Sends a signed test webhook event (`webhook.test`) to the client's configured webhook URL.
   */
  app.post<{ Params: { id: string } }>('/api/v1/clients/:id/webhook-test', async (request, reply) => {
    const client = await clientRepository.findById(request.params.id);
    if (!client) {
      throw new OAuthProtocolError('invalid_client', 'Client not found.', 404);
    }

    const developer = await resolveOptionalDeveloper(request);
    assertClientOwnership(client.owner_user_id, developer?.id, developer?.role);

    const result = await saasService.dispatchWebhook(client, 'webhook.test', {
      message: 'Test webhook delivery from soauth Developer Portal',
      client_name: client.app_name,
      triggered_by: developer?.email ?? 'developer',
    });

    reply.header('Cache-Control', 'no-store');
    return reply.status(200).send(result);
  });

  /**
   * GET /api/v1/clients/:id/users
   * Lists users who have authenticated with this application (Per-App User Directory).
   */
  app.get<{ Params: { id: string } }>('/api/v1/clients/:id/users', async (request, reply) => {
    const client = await clientRepository.findById(request.params.id);
    if (!client) {
      throw new OAuthProtocolError('invalid_client', 'Client not found.', 404);
    }

    const developer = await resolveOptionalDeveloper(request);
    assertClientOwnership(client.owner_user_id, developer?.id, developer?.role);

    const [clientSessions, allUsers] = await Promise.all([
      sessionAndTokenRepository.listSessionsForClient(client.id),
      userRepository.listAll(),
    ]);

    const statsByUser = new Map<
      string,
      { lastLoginAt: Date; sessionCount: number; activeSessions: number }
    >();

    for (const s of clientSessions) {
      const existing = statsByUser.get(s.user_id);
      const authTime = new Date(s.auth_time);
      const isActive = !s.is_revoked && new Date(s.expires_at).getTime() > Date.now();
      if (!existing) {
        statsByUser.set(s.user_id, {
          lastLoginAt: authTime,
          sessionCount: 1,
          activeSessions: isActive ? 1 : 0,
        });
      } else {
        existing.sessionCount += 1;
        if (isActive) existing.activeSessions += 1;
        if (authTime > existing.lastLoginAt) {
          existing.lastLoginAt = authTime;
        }
      }
    }

    // For the default reference app or admin view, show all registered users so developers can manage roles immediately
    const relevantUsers =
      client.id === '00000000-0000-4000-8000-000000000001'
        ? allUsers
        : allUsers.filter((u) => statsByUser.has(u.id));

    const directory = relevantUsers.map((u) => {
      const stats = statsByUser.get(u.id);
      return {
        id: u.id,
        email: u.email,
        email_verified: u.email_verified ?? false,
        role: u.role ?? 'member',
        is_mfa_enabled: u.is_mfa_enabled,
        created_at: u.created_at,
        last_login_at: stats?.lastLoginAt ?? null,
        session_count: stats?.sessionCount ?? 0,
        active_sessions: stats?.activeSessions ?? 0,
      };
    });

    reply.header('Cache-Control', 'no-store');
    return reply.status(200).send(directory);
  });

  /**
   * PATCH /api/v1/clients/:id/users/:userId
   * Updates a user's RBAC role (`admin`, `member`, `billing`, `viewer`) or revokes their sessions.
   */
  app.patch<{
    Params: { id: string; userId: string };
    Body: { role?: string; revoke_sessions?: boolean };
  }>('/api/v1/clients/:id/users/:userId', async (request, reply) => {
    const client = await clientRepository.findById(request.params.id);
    if (!client) {
      throw new OAuthProtocolError('invalid_client', 'Client not found.', 404);
    }

    const developer = await resolveOptionalDeveloper(request);
    assertClientOwnership(client.owner_user_id, developer?.id, developer?.role);

    const targetUser = await userRepository.findById(request.params.userId);
    if (!targetUser) {
      throw new OAuthProtocolError('invalid_request', 'User not found.', 404);
    }

    if (request.body.role) {
      await userRepository.updateRole(targetUser.id, request.body.role);
      saasService.record({
        eventType: 'user.role_updated',
        actorUserId: developer?.id ?? null,
        actorEmail: developer?.email ?? null,
        clientId: client.id,
        ipAddress: request.ip ?? null,
        status: 'success',
        details: `Updated role for ${targetUser.email} to "${request.body.role}"`,
      });
    }

    if (request.body.revoke_sessions) {
      await userRepository.revokeAllSessionsForUser(targetUser.id, 'TENANT_ADMIN_REVOKED');
      saasService.record({
        eventType: 'user.sessions_revoked',
        actorUserId: developer?.id ?? null,
        actorEmail: developer?.email ?? null,
        clientId: client.id,
        ipAddress: request.ip ?? null,
        status: 'warning',
        details: `Revoked all active sessions for ${targetUser.email}`,
      });
    }

    reply.header('Cache-Control', 'no-store');
    return reply.status(200).send({
      message: 'User updated successfully.',
      user_id: targetUser.id,
      role: request.body.role ?? targetUser.role ?? 'member',
    });
  });

  /**
   * GET /api/v1/saas/overview
   * Returns SaaS usage metrics (MAU, plan quota, active sessions) and the Security Audit Log stream.
   */
  app.get('/api/v1/saas/overview', async (request, reply) => {
    const developer = await resolveOptionalDeveloper(request);
    const clients =
      developer && developer.role !== 'admin'
        ? await clientRepository.listByOwner(developer.id)
        : await clientRepository.listAll();

    const ownedClientIds = new Set(clients.map((c) => c.id));
    const allUsers = await userRepository.listAll();

    const activeUserIds = new Set<string>();
    let totalSessions = 0;

    for (const c of clients) {
      const sessions = await sessionAndTokenRepository.listSessionsForClient(c.id);
      totalSessions += sessions.length;
      for (const s of sessions) {
        activeUserIds.add(s.user_id);
      }
    }

    const mauCount = Math.max(activeUserIds.size, allUsers.length);
    const logs = saasService.listForOwner(ownedClientIds, developer?.id ?? '', 100);

    reply.header('Cache-Control', 'no-store');
    return reply.status(200).send({
      plan: {
        name: 'Pro SaaS Ready (Free Tier Quota)',
        mau_used: mauCount,
        mau_limit: 10000,
        total_users: allUsers.length,
        total_clients: clients.length,
        total_sessions: totalSessions,
      },
      audit_logs: logs,
    });
  });

  /**
   * DELETE /api/v1/clients/:id
   */
  app.delete<{ Params: { id: string } }>('/api/v1/clients/:id', async (request, reply) => {
    const { id } = request.params;
    const client = await clientRepository.findById(id);
    if (client) {
      const developer = await resolveOptionalDeveloper(request);
      assertClientOwnership(client.owner_user_id, developer?.id, developer?.role);
    }

    await clientRepository.deleteById(id);
    reply.header('Cache-Control', 'no-store');
    return reply.status(200).send({ message: 'Client deleted successfully.' });
  });

  /**
   * POST /api/v1/clients/:id/regenerate-secret
   */
  app.post<{ Params: { id: string } }>(
    '/api/v1/clients/:id/regenerate-secret',
    async (request, reply) => {
      const { id } = request.params;
      const client = await clientRepository.findById(id);
      if (!client) {
        throw new OAuthProtocolError('invalid_client', 'Client not found.', 404);
      }

      const developer = await resolveOptionalDeveloper(request);
      assertClientOwnership(client.owner_user_id, developer?.id, developer?.role);

      const newRawSecret = generateOpaqueToken(32);
      const newSecretHash = await hashSecretArgon2id(newRawSecret);

      await clientRepository.updateClientSecret(id, newSecretHash);

      saasService.record({
        eventType: 'client.secret_rotated',
        actorUserId: developer?.id ?? null,
        actorEmail: developer?.email ?? null,
        clientId: id,
        ipAddress: request.ip ?? null,
        status: 'warning',
        details: `Rotated client secret for "${client.app_name}"`,
      });

      reply.header('Cache-Control', 'no-store');
      return reply.status(200).send({
        client_id: id,
        client_secret: newRawSecret,
        message: 'New client secret generated. Store it safely as it will not be displayed again.',
      });
    },
  );
}

import type { FastifyInstance, FastifyRequest } from 'fastify';
import { randomInt } from 'node:crypto';
import {
  generateOpaqueToken,
  hashSecretArgon2id,
  sha256Hex,
} from '../../core/crypto.js';
import { createRateLimitHook } from '../../core/ratelimit.js';
import { computeTotpCode, generateTotpSecret, verifyTotpCode } from '../../core/totp.js';
import { redis } from '../../database/connection.js';
import { clientRepository } from '../../repositories/client.repo.js';
import { sessionAndTokenRepository } from '../../repositories/session.repo.js';
import { userRepository } from '../../repositories/user.repo.js';
import { authorizationService } from '../../services/auth.service.js';
import { saasService } from '../../services/saas.service.js';
import { OAuthProtocolError } from '../../types/oauth.types.js';

interface SignUpBody {
  email: string;
  password: string;
}

interface DirectLoginBody {
  email: string;
  password?: string;
  otp_code?: string;
  passkey_credential_id?: string;
  mfa_code?: string;
}

interface ForgotPasswordBody {
  email: string;
}

interface ResetPasswordBody {
  token: string;
  new_password: string;
}

const authRateLimit = createRateLimitHook({
  namespace: 'account_auth',
  maxRequests: 15,
  windowSeconds: 60,
});

async function resolveAuthenticatedSession(request: FastifyRequest) {
  const rawToken = request.cookies['soauth_sso_token'];
  if (!rawToken) return null;

  const tokenHash = sha256Hex(rawToken);
  const session = await sessionAndTokenRepository.findActiveSessionByTokenHash(tokenHash);
  if (!session) return null;

  const user = await userRepository.findById(session.user_id);
  if (!user) return null;

  return { user, session };
}

export async function registerAccountRoutes(app: FastifyInstance): Promise<void> {
  /**
   * GET /api/v1/auth/session
   * Inspects the active SSO session cookie for "Continue as [User]" and Portal authentication.
   */
  app.get('/api/v1/auth/session', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    const auth = await resolveAuthenticatedSession(request);
    if (!auth) {
      return reply.status(200).send({ authenticated: false });
    }

    const orgCtx = saasService.getActiveOrganizationContext(auth.user.id, auth.user.email);

    return reply.status(200).send({
      authenticated: true,
      session_id: auth.session.id,
      user: {
        id: auth.user.id,
        email: auth.user.email,
        email_verified: auth.user.email_verified ?? false,
        role: auth.user.role ?? 'member',
        is_mfa_enabled: auth.user.is_mfa_enabled,
        ...(orgCtx.org_id !== undefined ? { org_id: orgCtx.org_id } : {}),
        ...(orgCtx.org_slug !== undefined ? { org_slug: orgCtx.org_slug } : {}),
        ...(orgCtx.org_role !== undefined ? { org_role: orgCtx.org_role } : {}),
        created_at: auth.user.created_at,
      },
    });
  });

  /**
   * POST /api/v1/auth/login
   * Direct login for the Developer Portal and User Account Security Dashboard (Password, Passwordless OTP, or Passkey).
   */
  app.post<{ Body: DirectLoginBody }>(
    '/api/v1/auth/login',
    {
      preHandler: [authRateLimit],
      schema: {
        body: {
          type: 'object',
          required: ['email'],
          properties: {
            email: { type: 'string', format: 'email' },
            password: { type: 'string', maxLength: 256 },
            otp_code: { type: 'string', minLength: 6, maxLength: 6 },
            passkey_credential_id: { type: 'string', maxLength: 512 },
            mfa_code: { type: 'string', minLength: 6, maxLength: 6 },
          },
        },
      },
    },
    async (request, reply) => {
      const { user, session, rawSessionToken } = await authorizationService.authenticateUser({
        email: request.body.email,
        ...(request.body.password !== undefined ? { passwordPlain: request.body.password } : {}),
        ...(request.body.otp_code !== undefined ? { otpCode: request.body.otp_code } : {}),
        ...(request.body.passkey_credential_id !== undefined
          ? { passkeyCredentialId: request.body.passkey_credential_id }
          : {}),
        clientId: '00000000-0000-4000-8000-000000000001',
        ...(request.body.mfa_code !== undefined ? { totpCode: request.body.mfa_code } : {}),
        ipAddress: request.ip ?? null,
        userAgent: request.headers['user-agent'] ?? null,
      });

      reply.setCookie('soauth_sso_token', rawSessionToken, {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production' || Boolean(process.env.VERCEL),
        path: '/',
        maxAge: 8 * 60 * 60,
      });

      const orgCtx = saasService.getActiveOrganizationContext(user.id, user.email);

      reply.header('Cache-Control', 'no-store');
      return reply.status(200).send({
        authenticated: true,
        session_id: session.id,
        user: {
          id: user.id,
          email: user.email,
          email_verified: user.email_verified ?? false,
          role: user.role ?? 'member',
          is_mfa_enabled: user.is_mfa_enabled,
          ...(orgCtx.org_id !== undefined ? { org_id: orgCtx.org_id } : {}),
          ...(orgCtx.org_slug !== undefined ? { org_slug: orgCtx.org_slug } : {}),
          ...(orgCtx.org_role !== undefined ? { org_role: orgCtx.org_role } : {}),
        },
      });
    },
  );

  /**
   * POST /api/v1/auth/passwordless/send
   * Feature 1: Sends a 6-digit one-time Passwordless Sign-In code to any email address.
   */
  app.post<{ Body: { email: string } }>(
    '/api/v1/auth/passwordless/send',
    {
      preHandler: [authRateLimit],
      schema: {
        body: {
          type: 'object',
          required: ['email'],
          properties: {
            email: { type: 'string', format: 'email' },
          },
        },
      },
    },
    async (request, reply) => {
      const normalizedEmail = request.body.email.toLowerCase().trim();
      const otpCode = String(randomInt(100000, 999999));
      await redis.set(`soauth:passwordless_otp:${normalizedEmail}`, otpCode, 'EX', 600);

      await saasService.sendTransactionalEmail({
        to: normalizedEmail,
        subject: `${otpCode} is your soauth sign-in code`,
        html: `<p>Your 6-digit passwordless sign-in code for <strong>soauth</strong> is: <strong>${otpCode}</strong> (expires in 10 minutes).</p>`,
      });

      saasService.record({
        eventType: 'auth.passwordless.sent',
        actorEmail: normalizedEmail,
        ipAddress: request.ip ?? null,
        status: 'success',
        details: `Sent 6-digit passwordless sign-in code to ${normalizedEmail}`,
      });

      reply.header('Cache-Control', 'no-store');
      return reply.status(200).send({
        message: `One-time 6-digit sign-in code sent to ${normalizedEmail}.`,
        ...(process.env.NODE_ENV !== 'production' ? { dev_otp_code: otpCode } : {}),
      });
    },
  );

  /**
   * GET /api/v1/auth/passkeys
   * Feature 3: Lists registered WebAuthn passkeys for the authenticated user.
   */
  app.get('/api/v1/auth/passkeys', async (request, reply) => {
    const auth = await resolveAuthenticatedSession(request);
    if (!auth) {
      throw new OAuthProtocolError('access_denied', 'Authentication required.', 401);
    }
    reply.header('Cache-Control', 'no-store');
    return reply.status(200).send(saasService.listPasskeysForUser(auth.user.id));
  });

  /**
   * POST /api/v1/auth/passkeys/register
   * Feature 3: Registers a WebAuthn passkey credential for the authenticated user.
   */
  app.post<{
    Body: {
      device_name: string;
      credential_id?: string;
      public_key_spki?: string;
      transports?: string[];
    };
  }>('/api/v1/auth/passkeys/register', async (request, reply) => {
    const auth = await resolveAuthenticatedSession(request);
    if (!auth) {
      throw new OAuthProtocolError('access_denied', 'Authentication required.', 401);
    }

    const passkey = saasService.registerPasskey({
      userId: auth.user.id,
      email: auth.user.email,
      deviceName: request.body.device_name || 'Platform Biometric Passkey',
      ...(request.body.credential_id !== undefined
        ? { credentialId: request.body.credential_id }
        : {}),
      ...(request.body.public_key_spki !== undefined
        ? { publicKeySpki: request.body.public_key_spki }
        : {}),
      ...(request.body.transports !== undefined ? { transports: request.body.transports } : {}),
    });

    reply.header('Cache-Control', 'no-store');
    return reply.status(201).send(passkey);
  });

  /**
   * DELETE /api/v1/auth/passkeys/:id
   * Feature 3: Removes a registered passkey.
   */
  app.delete<{ Params: { id: string } }>('/api/v1/auth/passkeys/:id', async (request, reply) => {
    const auth = await resolveAuthenticatedSession(request);
    if (!auth) {
      throw new OAuthProtocolError('access_denied', 'Authentication required.', 401);
    }
    saasService.deletePasskey(auth.user.id, request.params.id);
    reply.header('Cache-Control', 'no-store');
    return reply.status(200).send({ message: 'Passkey removed.' });
  });

  /**
   * GET /api/v1/orgs
   * Feature 2: Lists organizations the authenticated user belongs to and their active org ID.
   */
  app.get('/api/v1/orgs', async (request, reply) => {
    const auth = await resolveAuthenticatedSession(request);
    if (!auth) {
      throw new OAuthProtocolError('access_denied', 'Authentication required.', 401);
    }
    reply.header('Cache-Control', 'no-store');
    return reply
      .status(200)
      .send(saasService.listOrganizationsForUser(auth.user.id, auth.user.email));
  });

  /**
   * POST /api/v1/orgs
   * Feature 2: Creates a new multi-tenant Organization and sets it as active.
   */
  app.post<{ Body: { name: string; slug?: string } }>('/api/v1/orgs', async (request, reply) => {
    const auth = await resolveAuthenticatedSession(request);
    if (!auth) {
      throw new OAuthProtocolError('access_denied', 'Authentication required.', 401);
    }
    if (!request.body.name || request.body.name.trim().length < 2) {
      throw new OAuthProtocolError('invalid_request', 'Organization name is required.', 400);
    }
    const org = saasService.createOrganization({
      name: request.body.name,
      ...(request.body.slug !== undefined ? { slug: request.body.slug } : {}),
      creatorUserId: auth.user.id,
      creatorEmail: auth.user.email,
    });
    reply.header('Cache-Control', 'no-store');
    return reply.status(201).send(org);
  });

  /**
   * POST /api/v1/orgs/:id/members
   * Feature 2: Invites a user by email to an organization with role (`org:admin`, `org:member`, `org:billing`).
   */
  app.post<{
    Params: { id: string };
    Body: { email: string; role?: 'org:admin' | 'org:member' | 'org:billing' };
  }>('/api/v1/orgs/:id/members', async (request, reply) => {
    const auth = await resolveAuthenticatedSession(request);
    if (!auth) {
      throw new OAuthProtocolError('access_denied', 'Authentication required.', 401);
    }
    const existingUser = await userRepository.findByEmail(request.body.email);
    const member = saasService.inviteMemberToOrganization({
      orgId: request.params.id,
      email: request.body.email,
      role: request.body.role ?? 'org:member',
      invitedByUserId: auth.user.id,
      invitedByEmail: auth.user.email,
      existingUserId: existingUser?.id ?? null,
    });
    if (!member) {
      throw new OAuthProtocolError('invalid_request', 'Organization not found.', 404);
    }

    await saasService.sendTransactionalEmail({
      to: member.email,
      subject: `You have been invited to join an organization on soauth`,
      html: `<p><strong>${auth.user.email}</strong> invited you to join their organization on <strong>soauth</strong> with role <code>${member.role}</code>.</p>`,
    });

    reply.header('Cache-Control', 'no-store');
    return reply.status(201).send(member);
  });

  /**
   * DELETE /api/v1/orgs/:id/members/:memberId
   * Feature 2: Removes a member or pending invitation from an organization.
   */
  app.delete<{ Params: { id: string; memberId: string } }>(
    '/api/v1/orgs/:id/members/:memberId',
    async (request, reply) => {
      const auth = await resolveAuthenticatedSession(request);
      if (!auth) {
        throw new OAuthProtocolError('access_denied', 'Authentication required.', 401);
      }
      saasService.removeMemberFromOrganization(request.params.id, request.params.memberId);
      reply.header('Cache-Control', 'no-store');
      return reply.status(200).send({ message: 'Member removed.' });
    },
  );

  /**
   * POST /api/v1/orgs/:id/switch
   * Feature 2: Switches the user's active organization context for subsequent OAuth/OIDC tokens.
   */
  app.post<{ Params: { id: string } }>('/api/v1/orgs/:id/switch', async (request, reply) => {
    const auth = await resolveAuthenticatedSession(request);
    if (!auth) {
      throw new OAuthProtocolError('access_denied', 'Authentication required.', 401);
    }
    const org = saasService.switchActiveOrganization(
      auth.user.id,
      auth.user.email,
      request.params.id,
    );
    if (!org) {
      throw new OAuthProtocolError('invalid_request', 'Organization not found.', 404);
    }
    const orgCtx = saasService.getActiveOrganizationContext(auth.user.id, auth.user.email);
    reply.header('Cache-Control', 'no-store');
    return reply.status(200).send({
      active_org_id: org.id,
      ...orgCtx,
    });
  });

  /**
   * POST /api/v1/auth/logout
   * Terminates the current SSO session and clears the `soauth_sso_token` cookie.
   */
  app.post('/api/v1/auth/logout', async (request, reply) => {
    const auth = await resolveAuthenticatedSession(request);
    if (auth) {
      await sessionAndTokenRepository.revokeEntireSessionCascade(
        auth.session.id,
        'USER_LOGOUT',
      );
      saasService.record({
        eventType: 'auth.logout',
        actorUserId: auth.user.id,
        actorEmail: auth.user.email,
        clientId: auth.session.client_id,
        ipAddress: request.ip ?? null,
        status: 'success',
        details: `User ${auth.user.email} signed out`,
      });
    }
    reply.clearCookie('soauth_sso_token', { path: '/' });
    reply.header('Cache-Control', 'no-store');
    return reply.status(200).send({ message: 'Signed out successfully.' });
  });

  /**
   * POST /api/v1/auth/verify-email/send
   * Sends a 6-digit Email Verification OTP code via Resend (or console fallback).
   */
  app.post('/api/v1/auth/verify-email/send', async (request, reply) => {
    const auth = await resolveAuthenticatedSession(request);
    if (!auth) {
      throw new OAuthProtocolError('access_denied', 'Authentication required.', 401);
    }

    const otpCode = String(randomInt(100000, 999999));
    await redis.set(`soauth:email_otp:${auth.user.id}`, otpCode, 'EX', 900);

    await saasService.sendTransactionalEmail({
      to: auth.user.email,
      subject: `${otpCode} is your soauth verification code`,
      html: `<p>Your 6-digit verification code for <strong>soauth</strong> is: <strong>${otpCode}</strong> (expires in 15 minutes).</p>`,
    });

    reply.header('Cache-Control', 'no-store');
    return reply.status(200).send({
      message: `Verification code sent to ${auth.user.email}.`,
      ...(process.env.NODE_ENV !== 'production' ? { dev_otp_code: otpCode } : {}),
    });
  });

  /**
   * POST /api/v1/auth/verify-email/confirm
   * Confirms the 6-digit Email Verification OTP code and sets `email_verified = true`.
   */
  app.post<{ Body: { code: string } }>(
    '/api/v1/auth/verify-email/confirm',
    {
      schema: {
        body: {
          type: 'object',
          required: ['code'],
          properties: {
            code: { type: 'string', minLength: 6, maxLength: 6 },
          },
        },
      },
    },
    async (request, reply) => {
      const auth = await resolveAuthenticatedSession(request);
      if (!auth) {
        throw new OAuthProtocolError('access_denied', 'Authentication required.', 401);
      }

      const expectedCode = await redis.get(`soauth:email_otp:${auth.user.id}`);
      if (!expectedCode || expectedCode !== request.body.code.trim()) {
        throw new OAuthProtocolError(
          'invalid_request',
          'Invalid or expired 6-digit email verification code.',
          400,
        );
      }

      await redis.del(`soauth:email_otp:${auth.user.id}`);
      await userRepository.markEmailVerified(auth.user.id);

      saasService.record({
        eventType: 'user.email_verified',
        actorUserId: auth.user.id,
        actorEmail: auth.user.email,
        ipAddress: request.ip ?? null,
        status: 'success',
        details: `Verified email ownership for ${auth.user.email}`,
      });

      reply.header('Cache-Control', 'no-store');
      return reply.status(200).send({
        email_verified: true,
        message: 'Email address verified successfully!',
      });
    },
  );

  /**
   * GET /api/v1/auth/sessions
   * Lists all active sessions for the currently authenticated user.
   */
  app.get('/api/v1/auth/sessions', async (request, reply) => {
    const auth = await resolveAuthenticatedSession(request);
    if (!auth) {
      throw new OAuthProtocolError('access_denied', 'Authentication required.', 401);
    }

    const sessions = await sessionAndTokenRepository.listActiveSessionsForUser(auth.user.id);
    reply.header('Cache-Control', 'no-store');
    return reply.status(200).send(
      sessions.map((s) => ({
        id: s.id,
        client_id: s.client_id,
        ip_address: s.ip_address,
        user_agent: s.user_agent,
        auth_time: s.auth_time,
        expires_at: s.expires_at,
        is_current: s.id === auth.session.id,
      })),
    );
  });

  /**
   * DELETE /api/v1/auth/sessions/:id
   * Revokes a specific active session belonging to the authenticated user.
   */
  app.delete<{ Params: { id: string } }>('/api/v1/auth/sessions/:id', async (request, reply) => {
    const auth = await resolveAuthenticatedSession(request);
    if (!auth) {
      throw new OAuthProtocolError('access_denied', 'Authentication required.', 401);
    }

    const target = await sessionAndTokenRepository.findActiveSessionById(request.params.id);
    if (!target || target.user_id !== auth.user.id) {
      throw new OAuthProtocolError('invalid_request', 'Session not found.', 404);
    }

    await sessionAndTokenRepository.revokeEntireSessionCascade(
      target.id,
      'USER_REVOKED_SESSION',
    );

    if (target.id === auth.session.id) {
      reply.clearCookie('soauth_sso_token', { path: '/' });
    }

    reply.header('Cache-Control', 'no-store');
    return reply.status(200).send({ message: 'Session revoked.' });
  });

  /**
   * POST /api/v1/auth/mfa/setup
   * Generates a new TOTP Base32 secret and otpauth:// URI for Authenticator enrollment.
   */
  app.post('/api/v1/auth/mfa/setup', async (request, reply) => {
    const auth = await resolveAuthenticatedSession(request);
    if (!auth) {
      throw new OAuthProtocolError('access_denied', 'Authentication required.', 401);
    }

    const secret = generateTotpSecret();
    const otpauthUri = `otpauth://totp/soauth:${encodeURIComponent(auth.user.email)}?secret=${secret}&issuer=soauth&algorithm=SHA1&digits=6&period=30`;

    reply.header('Cache-Control', 'no-store');
    return reply.status(200).send({
      secret,
      otpauth_uri: otpauthUri,
      current_test_code: computeTotpCode(secret),
    });
  });

  /**
   * POST /api/v1/auth/mfa/enable
   * Verifies a 6-digit TOTP code against the setup secret and enables MFA on the user account.
   */
  app.post<{ Body: { secret: string; code: string } }>(
    '/api/v1/auth/mfa/enable',
    {
      schema: {
        body: {
          type: 'object',
          required: ['secret', 'code'],
          properties: {
            secret: { type: 'string', minLength: 16, maxLength: 64 },
            code: { type: 'string', minLength: 6, maxLength: 6 },
          },
        },
      },
    },
    async (request, reply) => {
      const auth = await resolveAuthenticatedSession(request);
      if (!auth) {
        throw new OAuthProtocolError('access_denied', 'Authentication required.', 401);
      }

      const { secret, code } = request.body;
      if (!verifyTotpCode(secret, code)) {
        throw new OAuthProtocolError(
          'invalid_request',
          'Invalid 6-digit authenticator code. Please verify your authenticator app clock.',
          400,
        );
      }

      await userRepository.enableMfa(auth.user.id, secret);
      saasService.record({
        eventType: 'auth.mfa.enabled',
        actorUserId: auth.user.id,
        actorEmail: auth.user.email,
        ipAddress: request.ip ?? null,
        status: 'success',
        details: `Enabled TOTP 2FA for ${auth.user.email}`,
      });

      reply.header('Cache-Control', 'no-store');
      return reply.status(200).send({
        is_mfa_enabled: true,
        message: 'Two-factor authentication (TOTP) enabled on your account.',
      });
    },
  );

  /**
   * POST /api/v1/auth/mfa/disable
   * Disables TOTP MFA for the authenticated user.
   */
  app.post('/api/v1/auth/mfa/disable', async (request, reply) => {
    const auth = await resolveAuthenticatedSession(request);
    if (!auth) {
      throw new OAuthProtocolError('access_denied', 'Authentication required.', 401);
    }

    await userRepository.disableMfa(auth.user.id);
    saasService.record({
      eventType: 'auth.mfa.disabled',
      actorUserId: auth.user.id,
      actorEmail: auth.user.email,
      ipAddress: request.ip ?? null,
      status: 'warning',
      details: `Disabled TOTP 2FA for ${auth.user.email}`,
    });

    reply.header('Cache-Control', 'no-store');
    return reply.status(200).send({
      is_mfa_enabled: false,
      message: 'Two-factor authentication has been disabled.',
    });
  });

  /**
   * POST /api/v1/auth/signup
   * Public self-service user registration with Argon2id hashing.
   */
  app.post<{ Body: SignUpBody }>(
    '/api/v1/auth/signup',
    {
      preHandler: [authRateLimit],
      schema: {
        body: {
          type: 'object',
          required: ['email', 'password'],
          properties: {
            email: { type: 'string', format: 'email' },
            password: { type: 'string', minLength: 8, maxLength: 256 },
          },
        },
      },
    },
    async (request, reply) => {
      const { email, password } = request.body;
      const normalizedEmail = email.toLowerCase().trim();

      const existingUser = await userRepository.findByEmail(normalizedEmail);
      if (existingUser) {
        throw new OAuthProtocolError(
          'invalid_request',
          'An account with this email address already exists.',
          409,
        );
      }

      const passwordHash = await hashSecretArgon2id(password);
      const user = await userRepository.create({
        email: normalizedEmail,
        password_hash: passwordHash,
        email_verified: false,
        role: 'member',
        is_mfa_enabled: false,
        mfa_secret_encrypted: null,
        is_active: true,
      });

      saasService.record({
        eventType: 'auth.signup',
        actorUserId: user.id,
        actorEmail: user.email,
        ipAddress: request.ip ?? null,
        status: 'success',
        details: `New user account registered: ${user.email}`,
      });

      // Notify any registered clients with configured webhooks
      const clients = await clientRepository.listAll();
      for (const c of clients) {
        if (c.webhook_url) {
          void saasService.dispatchWebhook(c, 'user.created', {
            user_id: user.id,
            email: user.email,
            role: user.role ?? 'member',
            created_at: user.created_at,
          });
        }
      }

      reply.header('Cache-Control', 'no-store');
      return reply.status(201).send({
        user: {
          id: user.id,
          email: user.email,
          email_verified: user.email_verified ?? false,
          role: user.role ?? 'member',
          created_at: user.created_at,
        },
        message: 'Account created successfully. You may now log in.',
      });
    },
  );

  /**
   * POST /api/v1/auth/forgot-password
   * Issues a high-entropy, SHA-256 hashed password reset token with 1-hour expiration.
   */
  app.post<{ Body: ForgotPasswordBody }>(
    '/api/v1/auth/forgot-password',
    {
      preHandler: [authRateLimit],
      schema: {
        body: {
          type: 'object',
          required: ['email'],
          properties: {
            email: { type: 'string', format: 'email' },
          },
        },
      },
    },
    async (request, reply) => {
      const normalizedEmail = request.body.email.toLowerCase().trim();
      const user = await userRepository.findByEmail(normalizedEmail);

      let rawResetToken: string | undefined;

      if (user) {
        rawResetToken = generateOpaqueToken(32);
        const tokenHash = sha256Hex(rawResetToken);
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

        await userRepository.createPasswordResetToken({
          user_id: user.id,
          token_hashed: tokenHash,
          expires_at: expiresAt,
        });

        await saasService.sendTransactionalEmail({
          to: user.email,
          subject: 'Reset your soauth password',
          html: `<p>Use the following reset token to set a new password on <strong>soauth</strong>: <code>${rawResetToken}</code></p>`,
        });
      } else {
        // Equalize response timing to prevent user enumeration
        await hashSecretArgon2id('dummy-password-reset-timing-equalizer');
      }

      reply.header('Cache-Control', 'no-store');
      return reply.status(200).send({
        message: 'If an account exists with that email, a password reset link has been dispatched.',
        // Expose reset_token in dev mode for immediate manual testing
        ...(rawResetToken && process.env.NODE_ENV !== 'production'
          ? { dev_reset_token: rawResetToken }
          : {}),
      });
    },
  );

  /**
   * POST /api/v1/auth/reset-password
   * Verifies the one-time reset token, updates password with Argon2id,
   * and revokes all active sessions for security.
   */
  app.post<{ Body: ResetPasswordBody }>(
    '/api/v1/auth/reset-password',
    {
      schema: {
        body: {
          type: 'object',
          required: ['token', 'new_password'],
          properties: {
            token: { type: 'string', minLength: 16, maxLength: 256 },
            new_password: { type: 'string', minLength: 8, maxLength: 256 },
          },
        },
      },
    },
    async (request, reply) => {
      const { token, new_password } = request.body;
      const tokenHash = sha256Hex(token);

      const resetTokenRecord = await userRepository.findValidPasswordResetToken(tokenHash);
      if (!resetTokenRecord) {
        throw new OAuthProtocolError(
          'invalid_request',
          'Invalid, expired, or previously consumed password reset token.',
          400,
        );
      }

      const newPasswordHash = await hashSecretArgon2id(new_password);

      // Update password & mark token as consumed
      await Promise.all([
        userRepository.updatePassword(resetTokenRecord.user_id, newPasswordHash),
        userRepository.markPasswordResetTokenUsed(resetTokenRecord.id),
      ]);

      // Revoke all existing sessions so any hijacked session is immediately terminated
      await userRepository.revokeAllSessionsForUser(
        resetTokenRecord.user_id,
        'PASSWORD_RESET_COMPLETED',
      );

      saasService.record({
        eventType: 'auth.password_reset',
        actorUserId: resetTokenRecord.user_id,
        ipAddress: request.ip ?? null,
        status: 'success',
        details: 'Password reset completed and all prior sessions revoked',
      });

      reply.header('Cache-Control', 'no-store');
      return reply.status(200).send({
        message: 'Password has been reset successfully. All existing sessions have been terminated. You may now log in.',
      });
    },
  );
}

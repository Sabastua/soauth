import type { FastifyInstance, FastifyRequest } from 'fastify';
import {
  generateOpaqueToken,
  hashSecretArgon2id,
  sha256Hex,
} from '../../core/crypto.js';
import { computeTotpCode, generateTotpSecret, verifyTotpCode } from '../../core/totp.js';
import { sessionAndTokenRepository } from '../../repositories/session.repo.js';
import { userRepository } from '../../repositories/user.repo.js';
import { authorizationService } from '../../services/auth.service.js';
import { OAuthProtocolError } from '../../types/oauth.types.js';

interface SignUpBody {
  email: string;
  password: string;
}

interface DirectLoginBody {
  email: string;
  password: string;
  mfa_code?: string;
}

interface ForgotPasswordBody {
  email: string;
}

interface ResetPasswordBody {
  token: string;
  new_password: string;
}

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

    return reply.status(200).send({
      authenticated: true,
      session_id: auth.session.id,
      user: {
        id: auth.user.id,
        email: auth.user.email,
        is_mfa_enabled: auth.user.is_mfa_enabled,
        created_at: auth.user.created_at,
      },
    });
  });

  /**
   * POST /api/v1/auth/login
   * Direct login for the Developer Portal and User Account Security Dashboard.
   */
  app.post<{ Body: DirectLoginBody }>(
    '/api/v1/auth/login',
    {
      schema: {
        body: {
          type: 'object',
          required: ['email', 'password'],
          properties: {
            email: { type: 'string', format: 'email' },
            password: { type: 'string', minLength: 8, maxLength: 256 },
            mfa_code: { type: 'string', minLength: 6, maxLength: 6 },
          },
        },
      },
    },
    async (request, reply) => {
      const { user, session, rawSessionToken } = await authorizationService.authenticateUser({
        email: request.body.email,
        passwordPlain: request.body.password,
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

      reply.header('Cache-Control', 'no-store');
      return reply.status(200).send({
        authenticated: true,
        session_id: session.id,
        user: {
          id: user.id,
          email: user.email,
          is_mfa_enabled: user.is_mfa_enabled,
        },
      });
    },
  );

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
    }
    reply.clearCookie('soauth_sso_token', { path: '/' });
    reply.header('Cache-Control', 'no-store');
    return reply.status(200).send({ message: 'Signed out successfully.' });
  });

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
        is_mfa_enabled: false,
        mfa_secret_encrypted: null,
        is_active: true,
      });

      reply.header('Cache-Control', 'no-store');
      return reply.status(201).send({
        user: {
          id: user.id,
          email: user.email,
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

      reply.header('Cache-Control', 'no-store');
      return reply.status(200).send({
        message: 'Password has been reset successfully. All existing sessions have been terminated. You may now log in.',
      });
    },
  );
}

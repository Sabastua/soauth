import type { FastifyInstance } from 'fastify';
import {
  generateOpaqueToken,
  hashSecretArgon2id,
  sha256Hex,
} from '../../core/crypto.js';
import { userRepository } from '../../repositories/user.repo.js';
import { OAuthProtocolError } from '../../types/oauth.types.js';

interface SignUpBody {
  email: string;
  password: string;
}

interface ForgotPasswordBody {
  email: string;
}

interface ResetPasswordBody {
  token: string;
  new_password: string;
}

export async function registerAccountRoutes(app: FastifyInstance): Promise<void> {
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

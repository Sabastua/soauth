import Fastify from 'fastify';
import cors from '@fastify/cors';
import formbody from '@fastify/formbody';
import cookie from '@fastify/cookie';
import { tokenCryptoManager } from './core/tokens.js';
import { registerAuthorizeRoutes } from './api/v1/authorize.route.js';
import { registerTokenRoutes } from './api/v1/token.route.js';
import { registerDiscoveryAndJwksRoutes } from './api/v1/keys.route.js';
import { OAuthProtocolError } from './types/oauth.types.js';

export async function buildOAuthServer() {
  const app = Fastify({
    logger: true,
    trustProxy: true,
  });

  // Support both application/json and application/x-www-form-urlencoded (RFC 6749 Section 4.1.3)
  await app.register(formbody);
  await app.register(cookie);
  await app.register(cors, {
    origin: process.env.FRONTEND_LOGIN_URL ?? 'https://login.soauth.internal',
    credentials: true,
  });

  // Initialize asymmetric RS256/ES256 keypair before accepting traffic
  await tokenCryptoManager.initializeKeys();

  // Global RFC 6749 compliant error handler
  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof OAuthProtocolError) {
      reply.header('Cache-Control', 'no-store');
      return reply.status(error.statusCode).send({
        error: error.errorCode,
        error_description: error.errorDescription,
      });
    }

    if (error.validation) {
      reply.header('Cache-Control', 'no-store');
      return reply.status(400).send({
        error: 'invalid_request',
        error_description: error.message,
      });
    }

    app.log.error(error);
    return reply.status(500).send({
      error: 'server_error',
      error_description: 'An unexpected internal error occurred.',
    });
  });

  await app.register(registerAuthorizeRoutes);
  await app.register(registerTokenRoutes);
  await app.register(registerDiscoveryAndJwksRoutes);

  return app;
}

async function start() {
  const app = await buildOAuthServer();
  const port = Number(process.env.PORT ?? 4000);
  const host = process.env.HOST ?? '0.0.0.0';

  await app.listen({ port, host });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  start().catch((err) => {
    console.error('Fatal error starting soauth server:', err);
    process.exit(1);
  });
}

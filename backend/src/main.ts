import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import Fastify, { type FastifyError } from 'fastify';
import cors from '@fastify/cors';
import formbody from '@fastify/formbody';
import cookie from '@fastify/cookie';
import { tokenCryptoManager } from './core/tokens.js';
import { registerAuthorizeRoutes } from './api/v1/authorize.route.js';
import { registerTokenRoutes } from './api/v1/token.route.js';
import { registerDiscoveryAndJwksRoutes } from './api/v1/keys.route.js';
import { registerUserInfoRoutes } from './api/v1/userinfo.route.js';
import { registerLogoutRoutes } from './api/v1/logout.route.js';
import { registerClientRegistrationRoutes } from './api/v1/register.route.js';
import { registerAccountRoutes } from './api/v1/account.route.js';
import { registerSocialAuthRoutes } from './api/v1/social.route.js';
import { initializeDevMemoryStore } from './database/dev-store.js';
import { OAuthProtocolError } from './types/oauth.types.js';

export async function buildOAuthServer() {
  // If running in development without live Postgres/Redis, enable in-memory dev store
  if (process.env.NODE_ENV !== 'test' && process.env.USE_DEV_MEMORY !== 'false') {
    await initializeDevMemoryStore();
  }

  const app = Fastify({
    logger: true,
    trustProxy: true,
  });

  // Support both application/json and application/x-www-form-urlencoded (RFC 6749 Section 4.1.3)
  await app.register(formbody);
  await app.register(cookie);
  await app.register(cors, {
    origin: process.env.FRONTEND_LOGIN_URL ?? 'http://localhost:3000',
    credentials: true,
  });

  // Initialize asymmetric RS256/ES256 keypair before accepting traffic
  await tokenCryptoManager.initializeKeys();

  // Global RFC 6749 compliant error handler
  app.setErrorHandler((error: FastifyError | Error, _request, reply) => {
    if (error instanceof OAuthProtocolError) {
      reply.header('Cache-Control', 'no-store');
      return reply.status(error.statusCode).send({
        error: error.errorCode,
        error_description: error.errorDescription,
      });
    }

    if ('validation' in error && error.validation) {
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
  await app.register(registerUserInfoRoutes);
  await app.register(registerLogoutRoutes);
  await app.register(registerClientRegistrationRoutes);
  await app.register(registerAccountRoutes);
  await app.register(registerSocialAuthRoutes);

  // Demo /callback inspector for interactive manual browser testing
  app.get('/callback', async (request, reply) => {
    const query = request.query as Record<string, string>;
    const code = query['code'] ?? 'None';
    const state = query['state'] ?? 'None';
    const error = query['error'];

    reply.type('text/html');
    return `<!DOCTYPE html>
<html>
<head>
  <title>soauth - Authorization Callback</title>
  <style>
    body { font-family: sans-serif; background: #f8fafc; padding: 2rem; display: flex; justify-content: center; }
    .card { background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 2rem; max-width: 600px; width: 100%; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
    h1 { color: #0f172a; font-size: 1.3rem; margin-bottom: 1rem; }
    .field { margin: 1rem 0; word-break: break-all; }
    label { font-weight: bold; font-size: 0.85rem; color: #64748b; display: block; margin-bottom: 0.25rem; }
    code { background: #f1f5f9; padding: 0.35rem 0.5rem; border-radius: 4px; display: block; font-size: 0.9rem; border: 1px solid #cbd5e1; }
    .success { color: #16a34a; font-weight: bold; }
    .error { color: #dc2626; font-weight: bold; }
  </style>
</head>
<body>
  <div class="card">
    <h1>${error ? '<span class="error">Authorization Denied</span>' : '<span class="success">Authorization Grant Successful</span>'}</h1>
    ${error ? `<p class="field"><label>Error:</label><code>${error}</code></p>` : `
      <div class="field"><label>Authorization Code (Single-Use, 300s TTL):</label><code>${code}</code></div>
      <div class="field"><label>State Parameter:</label><code>${state}</code></div>
      <p style="color: #64748b; font-size: 0.85rem; margin-top: 1rem;">You can now exchange this code at <code>POST /token</code> using your PKCE <code>code_verifier</code>!</p>
    `}
  </div>
</body>
</html>`;
  });

  return app;
}

async function start() {
  const app = await buildOAuthServer();
  const port = Number(process.env.PORT ?? 4000);
  const host = process.env.HOST ?? '0.0.0.0';

  await app.listen({ port, host });
}

const isMainModule =
  Boolean(process.env.START_SERVER) ||
  (process.argv[1] !== undefined &&
    (resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url)) ||
      process.argv[1].endsWith('main.ts') ||
      process.argv[1].endsWith('main.js')));

if (isMainModule) {
  start().catch((err) => {
    console.error('Fatal error starting soauth server:', err);
    process.exit(1);
  });
}

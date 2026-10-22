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
  // If running without live Postgres/Redis configured, enable in-memory store automatically
  const hasExternalDb = Boolean(process.env.DATABASE_URL && process.env.REDIS_URL);
  const shouldUseDevMemory =
    process.env.NODE_ENV !== 'test' &&
    (process.env.USE_DEV_MEMORY === 'true' || (!hasExternalDb && process.env.USE_DEV_MEMORY !== 'false'));

  if (shouldUseDevMemory) {
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
    origin: true,
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
    const code = query['code'];
    const state = query['state'] ?? 'None';
    const error = query['error'];

    reply.type('text/html');
    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>soauth - Authorization Grant Inspector</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; padding: 2rem 1rem; display: flex; justify-content: center; }
    .card { background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 2rem; max-width: 680px; width: 100%; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); }
    h1 { color: #0f172a; font-size: 1.35rem; margin-bottom: 0.5rem; }
    p { color: #64748b; font-size: 0.9rem; line-height: 1.4; margin-bottom: 1rem; }
    .field { margin: 1rem 0; word-break: break-all; }
    label { font-weight: 600; font-size: 0.85rem; color: #475569; display: block; margin-bottom: 0.25rem; }
    code { background: #f1f5f9; padding: 0.35rem 0.5rem; border-radius: 4px; display: block; font-size: 0.85rem; border: 1px solid #cbd5e1; font-family: monospace; }
    .success { color: #16a34a; font-weight: 600; }
    .error { color: #dc2626; font-weight: 600; }
    button { background: #0284c7; color: white; border: none; padding: 0.65rem 1.25rem; border-radius: 6px; font-weight: 500; cursor: pointer; font-size: 0.9rem; }
    button:hover { background: #0369a1; }
    button.secondary { background: #f1f5f9; color: #334155; border: 1px solid #cbd5e1; }
    pre { background: #0f172a; color: #f8fafc; padding: 1rem; border-radius: 6px; font-size: 0.85rem; overflow-x: auto; margin-top: 0.75rem; max-height: 300px; }
    input { width: 100%; box-sizing: border-box; padding: 0.5rem; border: 1px solid #cbd5e1; border-radius: 4px; font-family: monospace; font-size: 0.85rem; }
  </style>
</head>
<body>
  <div class="card">
    ${
      error
        ? `<h1><span class="error">Authorization Denied</span></h1>
           <div class="field"><label>Error Code:</label><code>${error}</code></div>
           <div class="field"><label>State:</label><code>${state}</code></div>`
        : code
        ? `<h1><span class="success">✓ Authorization Grant Received</span></h1>
           <p>The user approved access and soauth issued a single-use authorization code (300-second TTL).</p>
           <div class="field"><label>Authorization Code:</label><code id="authCode">${code}</code></div>
           <div class="field"><label>State Parameter:</label><code>${state}</code></div>
           
           <div style="margin-top: 1.5rem; border-top: 1px solid #e2e8f0; padding-top: 1rem;">
             <h3 style="font-size: 1rem; margin-bottom: 0.5rem;">Exchange Code for Tokens at <code>POST /token</code></h3>
             <div style="margin-bottom: 0.75rem;">
               <label>PKCE Code Verifier:</label>
               <input id="codeVerifier" type="text" placeholder="Retrieving from sessionStorage or enter verifier..." />
             </div>
             <div style="display:flex; gap: 0.5rem;">
               <button type="button" id="btnExchange" onclick="exchangeCode()">Exchange for Access & ID Tokens</button>
               <button type="button" class="secondary" id="btnUserInfo" style="display:none;" onclick="fetchUserInfo()">Call GET /userinfo</button>
             </div>
             <div id="resultBox" style="display:none; margin-top: 1rem;">
               <label>Token Endpoint Response:</label>
               <pre id="resultPre"></pre>
             </div>
           </div>`
        : `<h1>soauth Callback Tester</h1>
           <p>No authorization code detected in URL query parameters.</p>
           <button type="button" onclick="launchAuthorize()">Launch Authorization Flow with PKCE</button>`
    }
  </div>

  <script>
    // Auto-fill verifier from session storage if present
    const savedVerifier = sessionStorage.getItem('soauth_code_verifier');
    const verifierInput = document.getElementById('codeVerifier');
    if (verifierInput && savedVerifier) {
      verifierInput.value = savedVerifier;
    }

    async function exchangeCode() {
      const code = document.getElementById('authCode')?.innerText;
      const verifier = document.getElementById('codeVerifier')?.value?.trim();
      const clientId = sessionStorage.getItem('soauth_client_id') || '00000000-0000-4000-8000-000000000001';
      const clientSecret = sessionStorage.getItem('soauth_client_secret') || 'soauth-dev-confidential-secret-2026';

      const body = new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: window.location.origin + window.location.pathname,
        client_id: clientId,
        client_secret: clientSecret,
        code_verifier: verifier || 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      });

      const res = await fetch('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
      });

      const data = await res.json();
      document.getElementById('resultBox').style.display = 'block';
      document.getElementById('resultPre').innerText = JSON.stringify(data, null, 2);

      if (res.ok && data.access_token) {
        window.currentAccessToken = data.access_token;
        document.getElementById('btnUserInfo').style.display = 'inline-block';
      }
    }

    async function fetchUserInfo() {
      const res = await fetch('/userinfo', {
        headers: { Authorization: 'Bearer ' + window.currentAccessToken }
      });
      const data = await res.json();
      document.getElementById('resultPre').innerText = 'GET /userinfo Result:\n' + JSON.stringify(data, null, 2);
    }

    async function launchAuthorize() {
      // Generate PKCE
      const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
      const array = new Uint8Array(64);
      window.crypto.getRandomValues(array);
      let verifier = '';
      for (let i = 0; i < 64; i++) verifier += charset[array[i] % charset.length];

      const encoder = new TextEncoder();
      const digest = await window.crypto.subtle.digest('SHA-256', encoder.encode(verifier));
      const bytes = new Uint8Array(digest);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
      const challenge = btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');

      sessionStorage.setItem('soauth_code_verifier', verifier);
      sessionStorage.setItem('soauth_client_id', '00000000-0000-4000-8000-000000000001');

      const url = new URL('/authorize', window.location.origin);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('client_id', '00000000-0000-4000-8000-000000000001');
      url.searchParams.set('redirect_uri', window.location.origin + '/callback');
      url.searchParams.set('scope', 'openid profile email offline_access');
      url.searchParams.set('state', 'state_' + Math.random().toString(36).substring(2, 10));
      url.searchParams.set('code_challenge', challenge);
      url.searchParams.set('code_challenge_method', 'S256');

      window.location.assign(url.toString());
    }
  </script>
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

import type { IncomingMessage, ServerResponse } from 'node:http';
import { buildOAuthServer } from '../backend/src/main.js';

let serverPromise: ReturnType<typeof buildOAuthServer> | null = null;

/**
 * Vercel Serverless Function Entrypoint
 * Reuses the initialized Fastify instance and JWKS key material across warm invocations.
 */
export default async function handler(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!serverPromise) {
    serverPromise = buildOAuthServer().then(async (app) => {
      await app.ready();
      return app;
    });
  }

  const app = await serverPromise;
  app.server.emit('request', req, res);
}

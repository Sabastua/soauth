import type { FastifyReply, FastifyRequest } from 'fastify';
import { redis } from '../database/connection.js';
import { OAuthProtocolError } from '../types/oauth.types.js';

interface RateLimitOptions {
  namespace: string;
  maxRequests: number;
  windowSeconds: number;
}

const localFallbackCounters = new Map<string, { count: number; resetAtMs: number }>();

/**
 * Creates a Fastify `preHandler` hook enforcing fixed/sliding window rate limits per IP.
 * Uses Redis `INCR` + `EXPIRE` in production with an automatic in-memory fallback for local tests.
 */
export function createRateLimitHook(options: RateLimitOptions) {
  return async function rateLimitPreHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<void> {
    const clientIp = request.ip || '127.0.0.1';
    const key = `oauth:ratelimit:${options.namespace}:${clientIp}`;

    let currentCount = 1;
    try {
      if (redis.status === 'ready') {
        currentCount = await redis.incr(key);
        if (currentCount === 1) {
          await redis.expire(key, options.windowSeconds);
        }
      } else {
        const now = Date.now();
        const existing = localFallbackCounters.get(key);
        if (!existing || existing.resetAtMs <= now) {
          localFallbackCounters.set(key, {
            count: 1,
            resetAtMs: now + options.windowSeconds * 1000,
          });
          currentCount = 1;
        } else {
          existing.count += 1;
          currentCount = existing.count;
        }
      }
    } catch {
      // Fail open on transient cache connectivity issues while logging
      request.log.warn({ key }, 'Rate limit store unavailable; failing open');
      return;
    }

    reply.header('X-RateLimit-Limit', String(options.maxRequests));
    reply.header(
      'X-RateLimit-Remaining',
      String(Math.max(0, options.maxRequests - currentCount)),
    );

    if (currentCount > options.maxRequests) {
      reply.header('Retry-After', String(options.windowSeconds));
      throw new OAuthProtocolError(
        'invalid_request',
        'Rate limit exceeded. Please wait before retrying.',
        429,
      );
    }
  };
}

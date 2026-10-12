import { Kysely, PostgresDialect } from 'kysely';
import pg from 'pg';
import { Redis } from 'ioredis';
import type { Database } from './schema.js';

const { Pool } = pg;

/**
 * Type-safe Kysely PostgreSQL instance.
 * Enforces parameterized SQL queries across all repositories.
 */
export const db = new Kysely<Database>({
  dialect: new PostgresDialect({
    pool: new Pool({
      connectionString:
        process.env.DATABASE_URL ?? 'postgres://soauth_user:soauth_pass@localhost:5432/soauth_db',
      max: 20,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
    }),
  }),
});

/**
 * Redis client for ephemeral OAuth states, PKCE challenges, and single-use Auth Code tracking.
 */
export const redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379/0', {
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
  lazyConnect: true,
});

/**
 * Atomic Lua script enforcing RFC 6749 Section 10.5 Single-Use Authorization Codes.
 *
 * KEYS[1] -> active code key: `oauth:code:<code_hash>`
 * KEYS[2] -> tombstone key:   `oauth:code:used:<code_hash>`
 * ARGV[1] -> tombstone TTL in seconds (e.g. 3600)
 *
 * Returns:
 * - `['REPLAY_DETECTED', stateJson]` if the code was already consumed (triggers full session revocation)
 * - `['CONSUMED', stateJson]` on first valid consumption (atomically moves state to tombstone)
 * - `['NOT_FOUND', '']` if the code never existed or expired naturally
 */
export const CONSUME_AUTH_CODE_LUA = `
local usedState = redis.call('GET', KEYS[2])
if usedState then
  redis.call('DEL', KEYS[1])
  return {'REPLAY_DETECTED', usedState}
end

local activeState = redis.call('GET', KEYS[1])
if not activeState then
  return {'NOT_FOUND', ''}
end

redis.call('DEL', KEYS[1])
redis.call('SET', KEYS[2], activeState, 'EX', tonumber(ARGV[1]))
return {'CONSUMED', activeState}
`;

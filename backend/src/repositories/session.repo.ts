import { db } from '../database/connection.js';
import type {
  ActiveSessionRow,
  NewActiveSessionRow,
  NewRefreshTokenRow,
  RefreshTokenRow,
} from '../database/schema.js';

export class SessionAndTokenRepository {
  public async createSession(session: NewActiveSessionRow): Promise<ActiveSessionRow> {
    return db
      .insertInto('active_sessions')
      .values(session)
      .returningAll()
      .executeTakeFirstOrThrow();
  }

  public async findActiveSessionById(sessionId: string): Promise<ActiveSessionRow | undefined> {
    return db
      .selectFrom('active_sessions')
      .selectAll()
      .where('id', '=', sessionId)
      .where('is_revoked', '=', false)
      .where('expires_at', '>', new Date())
      .executeTakeFirst();
  }

  public async findActiveSessionByTokenHash(
    sessionTokenHash: string,
  ): Promise<ActiveSessionRow | undefined> {
    return db
      .selectFrom('active_sessions')
      .selectAll()
      .where('session_token_hash', '=', sessionTokenHash)
      .where('is_revoked', '=', false)
      .where('expires_at', '>', new Date())
      .executeTakeFirst();
  }

  public async listActiveSessionsForUser(userId: string): Promise<ActiveSessionRow[]> {
    return db
      .selectFrom('active_sessions')
      .selectAll()
      .where('user_id', '=', userId)
      .where('is_revoked', '=', false)
      .where('expires_at', '>', new Date())
      .orderBy('created_at', 'desc')
      .execute();
  }

  public async listSessionsForClient(clientId: string): Promise<ActiveSessionRow[]> {
    return db
      .selectFrom('active_sessions')
      .selectAll()
      .where('client_id', '=', clientId)
      .orderBy('created_at', 'desc')
      .execute();
  }

  public async createRefreshToken(token: NewRefreshTokenRow): Promise<RefreshTokenRow> {
    return db
      .insertInto('refresh_tokens')
      .values(token)
      .returningAll()
      .executeTakeFirstOrThrow();
  }

  public async findRefreshTokenByHash(tokenHash: string): Promise<RefreshTokenRow | undefined> {
    return db
      .selectFrom('refresh_tokens')
      .selectAll()
      .where('token_hashed', '=', tokenHash)
      .executeTakeFirst();
  }

  /**
   * Rotates a refresh token inside a single ACID transaction:
   * marks the current token as revoked and links it to the newly issued token.
   */
  public async rotateRefreshToken(
    oldTokenId: string,
    newTokenData: NewRefreshTokenRow,
  ): Promise<RefreshTokenRow> {
    return db.transaction().execute(async (trx) => {
      const inserted = await trx
        .insertInto('refresh_tokens')
        .values(newTokenData)
        .returningAll()
        .executeTakeFirstOrThrow();

      await trx
        .updateTable('refresh_tokens')
        .set({
          is_revoked: true,
          replaced_by_token_id: inserted.id,
        })
        .where('id', '=', oldTokenId)
        .execute();

      return inserted;
    });
  }

  /**
   * Security Constraint #4: Immediate revocation of all associated tokens for a session
   * when an Authorization Code or Refresh Token replay attack is detected.
   */
  public async revokeEntireSessionCascade(
    sessionId: string,
    reason: string,
  ): Promise<void> {
    await db.transaction().execute(async (trx) => {
      await trx
        .updateTable('active_sessions')
        .set({
          is_revoked: true,
          revoked_reason: reason,
        })
        .where('id', '=', sessionId)
        .execute();

      await trx
        .updateTable('refresh_tokens')
        .set({
          is_revoked: true,
        })
        .where('session_id', '=', sessionId)
        .execute();
    });
  }

  /**
   * RFC 7009 Explicit Refresh Token Revocation.
   */
  public async revokeRefreshTokenById(tokenId: string): Promise<void> {
    await db
      .updateTable('refresh_tokens')
      .set({ is_revoked: true })
      .where('id', '=', tokenId)
      .execute();
  }
}

export const sessionAndTokenRepository = new SessionAndTokenRepository();

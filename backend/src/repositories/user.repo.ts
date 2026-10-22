import { db } from '../database/connection.js';
import type {
  NewPasswordResetTokenRow,
  NewUserRow,
  PasswordResetTokenRow,
  UserRow,
} from '../database/schema.js';

export class UserRepository {
  public async findById(userId: string): Promise<UserRow | undefined> {
    return db
      .selectFrom('users')
      .selectAll()
      .where('id', '=', userId)
      .where('is_active', '=', true)
      .executeTakeFirst();
  }

  public async findByEmail(email: string): Promise<UserRow | undefined> {
    return db
      .selectFrom('users')
      .selectAll()
      .where('email', '=', email.toLowerCase().trim())
      .where('is_active', '=', true)
      .executeTakeFirst();
  }

  public async listAll(): Promise<UserRow[]> {
    return db
      .selectFrom('users')
      .selectAll()
      .orderBy('created_at', 'desc')
      .execute();
  }

  public async create(user: NewUserRow): Promise<UserRow> {
    return db
      .insertInto('users')
      .values({
        ...user,
        email: user.email.toLowerCase().trim(),
      })
      .returningAll()
      .executeTakeFirstOrThrow();
  }

  public async updatePassword(userId: string, newPasswordHash: string): Promise<void> {
    await db
      .updateTable('users')
      .set({
        password_hash: newPasswordHash,
        updated_at: new Date(),
      })
      .where('id', '=', userId)
      .execute();
  }

  public async markEmailVerified(userId: string): Promise<void> {
    await db
      .updateTable('users')
      .set({
        email_verified: true,
        updated_at: new Date(),
      })
      .where('id', '=', userId)
      .execute();
  }

  public async updateRole(userId: string, role: string): Promise<void> {
    await db
      .updateTable('users')
      .set({
        role,
        updated_at: new Date(),
      })
      .where('id', '=', userId)
      .execute();
  }

  public async enableMfa(userId: string, secretEncrypted: string): Promise<void> {
    await db
      .updateTable('users')
      .set({
        is_mfa_enabled: true,
        mfa_secret_encrypted: secretEncrypted,
        updated_at: new Date(),
      })
      .where('id', '=', userId)
      .execute();
  }

  public async disableMfa(userId: string): Promise<void> {
    await db
      .updateTable('users')
      .set({
        is_mfa_enabled: false,
        mfa_secret_encrypted: null,
        updated_at: new Date(),
      })
      .where('id', '=', userId)
      .execute();
  }

  public async createPasswordResetToken(
    tokenData: NewPasswordResetTokenRow,
  ): Promise<PasswordResetTokenRow> {
    return db
      .insertInto('password_reset_tokens')
      .values(tokenData)
      .returningAll()
      .executeTakeFirstOrThrow();
  }

  public async findValidPasswordResetToken(
    tokenHash: string,
  ): Promise<PasswordResetTokenRow | undefined> {
    return db
      .selectFrom('password_reset_tokens')
      .selectAll()
      .where('token_hashed', '=', tokenHash)
      .where('is_used', '=', false)
      .where('expires_at', '>', new Date())
      .executeTakeFirst();
  }

  public async markPasswordResetTokenUsed(tokenId: string): Promise<void> {
    await db
      .updateTable('password_reset_tokens')
      .set({ is_used: true })
      .where('id', '=', tokenId)
      .execute();
  }

  public async revokeAllSessionsForUser(userId: string, reason: string): Promise<void> {
    await db.transaction().execute(async (trx) => {
      await trx
        .updateTable('active_sessions')
        .set({
          is_revoked: true,
          revoked_reason: reason,
        })
        .where('user_id', '=', userId)
        .execute();

      await trx
        .updateTable('refresh_tokens')
        .set({ is_revoked: true })
        .where('user_id', '=', userId)
        .execute();
    });
  }
}

export const userRepository = new UserRepository();

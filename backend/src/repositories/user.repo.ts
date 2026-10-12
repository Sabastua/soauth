import { db } from '../database/connection.js';
import type { NewUserRow, UserRow } from '../database/schema.js';

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
}

export const userRepository = new UserRepository();

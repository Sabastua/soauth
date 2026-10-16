import type { ColumnType, Generated, Insertable, Selectable, Updateable } from 'kysely';

export interface UsersTable {
  id: Generated<string>;
  email: string;
  password_hash: string;
  is_mfa_enabled: Generated<boolean>;
  mfa_secret_encrypted: string | null;
  is_active: Generated<boolean>;
  created_at: ColumnType<Date, string | undefined, never>;
  updated_at: ColumnType<Date, string | undefined, Date | string>;
}

export interface RegisteredClientsTable {
  id: Generated<string>;
  client_secret_hash: string | null;
  app_name: string;
  is_confidential: Generated<boolean>;
  redirect_uris: string[];
  allowed_scopes: string[];
  require_pkce: Generated<boolean>;
  created_at: ColumnType<Date, string | undefined, never>;
  updated_at: ColumnType<Date, string | undefined, Date | string>;
}

export interface ActiveSessionsTable {
  id: Generated<string>;
  user_id: string;
  client_id: string;
  session_token_hash: string;
  ip_address: string | null;
  user_agent: string | null;
  auth_time: ColumnType<Date, Date | string | undefined, never>;
  expires_at: ColumnType<Date, Date | string, Date | string>;
  is_revoked: Generated<boolean>;
  revoked_reason: string | null;
  created_at: ColumnType<Date, string | undefined, never>;
}

export interface RefreshTokensTable {
  id: Generated<string>;
  token_hashed: string;
  user_id: string;
  client_id: string;
  session_id: string;
  scope: string;
  expires_at: ColumnType<Date, Date | string, Date | string>;
  is_revoked: Generated<boolean>;
  replaced_by_token_id: string | null;
  created_at: ColumnType<Date, string | undefined, never>;
}

export interface PasswordResetTokensTable {
  id: Generated<string>;
  user_id: string;
  token_hashed: string;
  expires_at: ColumnType<Date, Date | string, Date | string>;
  is_used: Generated<boolean>;
  created_at: ColumnType<Date, string | undefined, never>;
}

export interface Database {
  users: UsersTable;
  registered_clients: RegisteredClientsTable;
  active_sessions: ActiveSessionsTable;
  refresh_tokens: RefreshTokensTable;
  password_reset_tokens: PasswordResetTokensTable;
}

export type UserRow = Selectable<UsersTable>;
export type NewUserRow = Insertable<UsersTable>;

export type RegisteredClientRow = Selectable<RegisteredClientsTable>;
export type NewRegisteredClientRow = Insertable<RegisteredClientsTable>;

export type ActiveSessionRow = Selectable<ActiveSessionsTable>;
export type NewActiveSessionRow = Insertable<ActiveSessionsTable>;

export type RefreshTokenRow = Selectable<RefreshTokensTable>;
export type NewRefreshTokenRow = Insertable<RefreshTokensTable>;
export type RefreshTokenUpdate = Updateable<RefreshTokensTable>;

export type PasswordResetTokenRow = Selectable<PasswordResetTokensTable>;
export type NewPasswordResetTokenRow = Insertable<PasswordResetTokensTable>;

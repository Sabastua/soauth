import { db } from '../database/connection.js';
import type { NewRegisteredClientRow, RegisteredClientRow } from '../database/schema.js';
import { constantTimeStringEqual } from '../core/crypto.js';

export interface ClientBrandingAndWebhookUpdate {
  app_name?: string;
  redirect_uris?: string[];
  allowed_scopes?: string[];
  logo_url?: string | null;
  primary_color?: string | null;
  app_website_url?: string | null;
  privacy_policy_url?: string | null;
  terms_of_service_url?: string | null;
  webhook_url?: string | null;
  webhook_secret?: string | null;
  custom_claims_template?: string | null;
}

export class ClientRepository {
  public async findById(clientId: string): Promise<RegisteredClientRow | undefined> {
    return db
      .selectFrom('registered_clients')
      .selectAll()
      .where('id', '=', clientId)
      .executeTakeFirst();
  }

  public async create(client: NewRegisteredClientRow): Promise<RegisteredClientRow> {
    return db
      .insertInto('registered_clients')
      .values(client)
      .returningAll()
      .executeTakeFirstOrThrow();
  }

  /**
   * Security Constraint #3: Strict string-matching for Client Redirect URIs.
   * Rejects partial matches, regexes, or query parameter tampering to prevent Open Redirector attacks.
   * Iterates through all registered URIs using constant-time comparison.
   */
  public isRedirectUriAllowed(client: RegisteredClientRow, candidateRedirectUri: string): boolean {
    let matched = false;
    for (const allowedUri of client.redirect_uris) {
      if (constantTimeStringEqual(allowedUri, candidateRedirectUri)) {
        matched = true;
      }
    }
    return matched;
  }

  /**
   * Verifies that every requested scope is explicitly permitted for this client.
   */
  public areScopesAllowed(client: RegisteredClientRow, requestedScopes: string[]): boolean {
    if (requestedScopes.length === 0) return false;
    const allowedSet = new Set(client.allowed_scopes);
    return requestedScopes.every((scope) => allowedSet.has(scope));
  }

  /**
   * Lists all registered OAuth clients for the developer portal.
   */
  public async listAll(): Promise<RegisteredClientRow[]> {
    return db
      .selectFrom('registered_clients')
      .selectAll()
      .orderBy('created_at', 'desc')
      .execute();
  }

  /**
   * Multi-tenant query: lists only clients owned by the given developer user ID.
   */
  public async listByOwner(ownerUserId: string): Promise<RegisteredClientRow[]> {
    const all = await this.listAll();
    return all.filter((c) => !c.owner_user_id || c.owner_user_id === ownerUserId);
  }

  public async deleteById(clientId: string): Promise<void> {
    await db
      .deleteFrom('registered_clients')
      .where('id', '=', clientId)
      .execute();
  }

  public async updateClientSecret(clientId: string, newSecretHash: string): Promise<void> {
    await db
      .updateTable('registered_clients')
      .set({
        client_secret_hash: newSecretHash,
        updated_at: new Date(),
      })
      .where('id', '=', clientId)
      .execute();
  }

  public async updateSettings(
    clientId: string,
    patch: ClientBrandingAndWebhookUpdate,
  ): Promise<RegisteredClientRow | undefined> {
    await db
      .updateTable('registered_clients')
      .set({
        ...patch,
        updated_at: new Date(),
      })
      .where('id', '=', clientId)
      .execute();
    return this.findById(clientId);
  }
}

export const clientRepository = new ClientRepository();

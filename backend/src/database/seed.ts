import { db } from './connection.js';
import { hashSecretArgon2id } from '../core/crypto.js';
import { userRepository } from '../repositories/user.repo.js';
import { clientRepository } from '../repositories/client.repo.js';

const DEFAULT_CLIENT_ID = '00000000-0000-4000-8000-000000000001';
const DEFAULT_CLIENT_SECRET = 'soauth-dev-confidential-secret-2026';
const DEFAULT_USER_EMAIL = 'admin@soauth.internal';
const DEFAULT_USER_PASSWORD = 'SoAuthAdminPassword!2026';

/**
 * Seeds an initial test user and a registered OAuth 2.0 / OIDC Relying Party client.
 * Idempotent: skips insertion if records already exist.
 */
export async function seedDatabase(): Promise<void> {
  const existingUser = await userRepository.findByEmail(DEFAULT_USER_EMAIL);
  if (!existingUser) {
    const passwordHash = await hashSecretArgon2id(DEFAULT_USER_PASSWORD);
    const createdUser = await userRepository.create({
      email: DEFAULT_USER_EMAIL,
      password_hash: passwordHash,
      is_mfa_enabled: false,
      mfa_secret_encrypted: null,
      is_active: true,
    });
    console.log(`[seed] Created user: ${createdUser.email} (id: ${createdUser.id})`);
  } else {
    console.log(`[seed] User already exists: ${existingUser.email} (id: ${existingUser.id})`);
  }

  const existingClient = await clientRepository.findById(DEFAULT_CLIENT_ID);
  if (!existingClient) {
    const clientSecretHash = await hashSecretArgon2id(DEFAULT_CLIENT_SECRET);
    const createdClient = await clientRepository.create({
      id: DEFAULT_CLIENT_ID,
      client_secret_hash: clientSecretHash,
      app_name: 'soauth Reference Web App',
      is_confidential: true,
      redirect_uris: [
        'http://localhost:3000/oauth/callback',
        'https://app.soauth.internal/oauth/callback',
      ],
      allowed_scopes: ['openid', 'profile', 'email', 'offline_access'],
      require_pkce: true,
    });
    console.log(`[seed] Created OAuth Client: ${createdClient.app_name}`);
    console.log(`       client_id:     ${createdClient.id}`);
    console.log(`       client_secret: ${DEFAULT_CLIENT_SECRET}`);
    console.log(`       redirect_uris: ${createdClient.redirect_uris.join(', ')}`);
  } else {
    console.log(`[seed] OAuth Client already exists: ${existingClient.id}`);
  }
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('seed.ts')) {
  seedDatabase()
    .then(async () => {
      await db.destroy();
      process.exit(0);
    })
    .catch(async (err) => {
      console.error('[seed] Seeding failed:', err);
      await db.destroy();
      process.exit(1);
    });
}

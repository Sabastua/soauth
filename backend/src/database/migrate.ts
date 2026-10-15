import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sql } from 'kysely';
import { db } from './connection.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Executes the SQL schema migration (`001_init_oauth_schema.sql`) against PostgreSQL.
 * Safe to run multiple times (`IF NOT EXISTS` guards all DDL statements).
 */
export async function runMigrations(): Promise<void> {
  const migrationPath = join(__dirname, 'migrations', '001_init_oauth_schema.sql');
  const rawSql = await readFile(migrationPath, 'utf8');

  await sql.raw(rawSql).execute(db);
  console.log('[migrate] Successfully applied 001_init_oauth_schema.sql');
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('migrate.ts')) {
  runMigrations()
    .then(async () => {
      await db.destroy();
      process.exit(0);
    })
    .catch(async (err) => {
      console.error('[migrate] Migration failed:', err);
      await db.destroy();
      process.exit(1);
    });
}

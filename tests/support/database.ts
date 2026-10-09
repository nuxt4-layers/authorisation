import { randomBytes } from 'node:crypto'
import pg from 'pg'
import { expect, it } from 'vitest'

/**
 * Disposable PostgreSQL databases for integration tests (ADR-0002: never a
 * shared hosted database). Set AUTHORISATION_TEST_DATABASE_URL to an admin
 * connection, e.g. postgres://postgres@localhost:5432/postgres.
 */
export const adminUrl = process.env.AUTHORISATION_TEST_DATABASE_URL

/** True when integration suites can run. In CI the URL is mandatory. */
export const hasDatabase = Boolean(adminUrl)

/** Registers a test that fails in CI when the database is not configured, so suites cannot be skipped silently. */
export function requireDatabaseInCi(): void {
  it('has a test database configured when running in CI', () => {
    if (process.env.CI) expect(adminUrl, 'AUTHORISATION_TEST_DATABASE_URL must be set in CI').toBeTruthy()
  })
}

export async function createTestDatabase(): Promise<{ url: string, drop: () => Promise<void> }> {
  const name = `authorisation_test_${randomBytes(6).toString('hex')}`
  const admin = new pg.Client({ connectionString: adminUrl })
  await admin.connect()
  await admin.query(`create database "${name}"`)
  await admin.end()
  const url = new URL(adminUrl!)
  url.pathname = `/${name}`
  return {
    url: url.toString(),
    async drop() {
      const client = new pg.Client({ connectionString: adminUrl })
      await client.connect()
      await client.query(`drop database if exists "${name}" with (force)`)
      await client.end()
    },
  }
}

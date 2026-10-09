import type { PostgresPoolLike } from '../../contracts'

/**
 * PRIVATE. Versioned, append-only migrations for the capability-owned schema
 * (ADR-0002). `{{schema}}` is replaced with the validated, quoted schema
 * identifier. Never edit a released migration; add a new one.
 *
 * Authorisation stores roles, role assignments and grants only: no groups,
 * memberships or domain data, which belong to Identity and to the domain
 * capabilities. Identifiers are opaque text.
 */
export const AUTHORISATION_MIGRATIONS: readonly { id: string, sql: string }[] = [
  {
    id: '0001_roles_assignments_grants',
    sql: `
create table {{schema}}."custom_role" (
  "tenant_id" text not null,
  "role_id" text not null,
  "definition" jsonb not null,
  "created_at" timestamptz not null default now(),
  "updated_at" timestamptz not null default now(),
  primary key ("tenant_id", "role_id")
);

create table {{schema}}."role_assignment" (
  "principal_id" text not null,
  "group_id" text not null,
  "role_id" text not null,
  "scope" text not null check ("scope" in ('group', 'group-and-descendants')),
  "assigned_by" text,
  "created_at" timestamptz not null default now(),
  primary key ("principal_id", "group_id", "role_id")
);
create index "role_assignment_group_idx" on {{schema}}."role_assignment" ("group_id");

create table {{schema}}."grant" (
  "grant_id" uuid primary key,
  "resource_type" text not null,
  "resource_id" text not null,
  "subject_kind" text not null check ("subject_kind" in ('principal', 'group')),
  "subject_id" text not null,
  "permissions" text[] not null check (cardinality("permissions") between 1 and 100),
  "expires_at" timestamptz,
  "granted_by" text,
  "created_at" timestamptz not null default now()
);
create index "grant_resource_idx" on {{schema}}."grant" ("resource_type", "resource_id");
`,
  },
]

const SCHEMA_PATTERN = /^[a-z_][a-z0-9_]{0,62}$/

export function quoteSchema(schema: string): string {
  if (!SCHEMA_PATTERN.test(schema)) throw new TypeError(`Invalid authorisation schema name '${schema}'.`)
  return `"${schema}"`
}

interface PoolClientLike {
  query(text: string, values?: readonly unknown[]): Promise<{ rows: Record<string, unknown>[] }>
  release(): void
}

/**
 * Applies pending migrations inside one transaction, serialised across
 * instances with a transaction-scoped advisory lock. Returns the ids applied.
 */
export async function runAuthorisationMigrations(pool: PostgresPoolLike, schema: string): Promise<string[]> {
  const quoted = quoteSchema(schema)
  const client = await pool.connect() as PoolClientLike
  const applied: string[] = []
  try {
    await client.query('begin')
    await client.query('select pg_advisory_xact_lock(hashtext($1))', [`authorisation-migrations:${schema}`])
    const existing = await client.query('select 1 from pg_namespace where nspname = $1', [schema])
    if (existing.rows.length === 0) await client.query(`create schema ${quoted}`)
    await client.query(`create table if not exists ${quoted}."schema_migration" ("id" text primary key, "applied_at" timestamptz not null default now())`)
    const { rows } = await client.query(`select "id" from ${quoted}."schema_migration"`)
    const done = new Set(rows.map(row => row.id))
    for (const migration of AUTHORISATION_MIGRATIONS) {
      if (done.has(migration.id)) continue
      await client.query(migration.sql.replaceAll('{{schema}}', quoted))
      await client.query(`insert into ${quoted}."schema_migration" ("id") values ($1)`, [migration.id])
      applied.push(migration.id)
    }
    await client.query('commit')
    return applied
  }
  catch (error) {
    await client.query('rollback').catch(() => {})
    throw error
  }
  finally {
    client.release()
  }
}

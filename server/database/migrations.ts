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
  {
    // Contract 4: access administration. Every time is given by the
    // application from the host's clock; no column defaults to the
    // database's own time.
    id: '0002_administration',
    sql: `
-- Time-limited assignments and access reviews.
alter table {{schema}}."role_assignment"
  add column "expires_at" timestamptz,
  add column "confirmed_at" timestamptz,
  add column "confirmed_by" text,
  add column "overdue_announced_at" timestamptz;
create index "role_assignment_expiry_idx" on {{schema}}."role_assignment" ("expires_at") where "expires_at" is not null;

-- A grant made through a change is bound to the resource's owning group.
alter table {{schema}}."grant" add column "owning_group_id" text;
create index "grant_owning_group_idx" on {{schema}}."grant" ("owning_group_id") where "owning_group_id" is not null;

-- A group's default roles and review interval. No row: the defaults.
create table {{schema}}."group_access" (
  "group_id" text primary key,
  "tenant_id" text not null,
  "default_member_role" text,
  "default_guest_role" text,
  "review_interval_days" integer check ("review_interval_days" between 1 and 3650),
  "default_member_role_set" boolean not null default false,
  "default_guest_role_set" boolean not null default false,
  "updated_at" timestamptz not null,
  "updated_by" text,
  "version" integer not null default 1 check ("version" >= 1)
);

-- Pending changes (approvals).
create table {{schema}}."pending_change" (
  "change_id" uuid primary key,
  "type" text not null check ("type" in ('role.assign', 'role.unassign', 'grant.create', 'grant.revoke', 'role.define', 'role.delete',
    'group.change-default-roles', 'group.change-review-interval', 'assignment.confirm')),
  "tenant_id" text not null,
  "group_id" text not null,
  "requester_id" text not null,
  "beneficiary_id" text,
  "risk" text not null check ("risk" in ('low', 'medium', 'high', 'critical')),
  "justification" jsonb not null,
  "target" jsonb not null,
  -- What the digest also covers: the group's requirement and the owners' groups when requested.
  "basis" jsonb not null,
  "required_approvals" integer not null check ("required_approvals" between 0 and 2),
  "route" text not null check ("route" in ('approvers', 'parent-owner', 'tenant-owner', 'published-delay', 'none')),
  "approvals" jsonb not null default '[]'::jsonb check (jsonb_typeof("approvals") = 'array'),
  "change_digest" text not null check ("change_digest" ~ '^[0-9a-f]{64}$'),
  "delay_ends_at" timestamptz,
  "expires_at" timestamptz,
  "held_until" timestamptz,
  "state" text not null check ("state" in ('awaiting-approval', 'delayed', 'applied', 'rejected', 'expired', 'cancelled')),
  -- The rule that refused an application, as a code. Never shown beyond the change's own readers.
  "failure" text check ("failure" is null or "failure" ~ '^[a-z][a-z0-9-]{0,63}$'),
  "correlation_id" uuid not null,
  "created_at" timestamptz not null,
  "decided_at" timestamptz,
  "version" integer not null default 1 check ("version" >= 1),
  check (("state" in ('applied', 'rejected', 'expired', 'cancelled')) = ("decided_at" is not null))
);
create index "pending_change_group_idx" on {{schema}}."pending_change" ("group_id", "state");
create index "pending_change_open_idx" on {{schema}}."pending_change" ("state") where "state" in ('awaiting-approval', 'delayed');
create index "pending_change_requester_idx" on {{schema}}."pending_change" ("requester_id");
create index "pending_change_beneficiary_idx" on {{schema}}."pending_change" ("beneficiary_id");

-- The transactional outbox: written in the same transaction as each change.
create table {{schema}}."outbox" (
  "sequence" bigserial primary key,
  "event_id" uuid not null unique,
  "type" text not null,
  "payload" jsonb not null,
  "occurred_at" timestamptz not null,
  "published_at" timestamptz
);
create index "outbox_unpublished_idx" on {{schema}}."outbox" ("sequence") where "published_at" is null;

-- The relay claims unpublished events in order; concurrent relays skip what another holds.
create function {{schema}}.claim_outbox(p_limit integer)
returns table ("sequence" bigint, "payload" jsonb) language sql volatile as $$
  select o."sequence", o."payload" from {{schema}}."outbox" o
  where o."published_at" is null order by o."sequence" limit p_limit for update skip locked
$$;

create function {{schema}}.mark_outbox_published(p_sequences bigint[], p_at timestamptz)
returns integer language sql volatile as $$
  with done as (update {{schema}}."outbox" set "published_at" = p_at where "sequence" = any (p_sequences) and "published_at" is null returning 1)
  select count(*)::integer from done
$$;
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

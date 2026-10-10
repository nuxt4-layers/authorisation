import type { AuthorisationEvent } from './events'
import type { AuthorisationActorContext, AuthorisationGroup } from './resources'

/**
 * Structural shape of a PostgreSQL connection pool, as provided by the `pg`
 * driver's `Pool`. Declared structurally so the public contract does not
 * depend on a driver package.
 */
export interface PostgresPoolLike {
  query(text: string, values?: readonly unknown[]): Promise<unknown>
  connect(): Promise<unknown>
  end(): Promise<void>
}

/**
 * Persistence port (ADR-0002) for roles, role assignments and grants. The host
 * owns the pool's lifecycle, credentials, TLS and pooling mode; the layer owns
 * everything inside its schema.
 */
export interface AuthorisationDatabase {
  dialect: 'postgres'
  pool: PostgresPoolLike
  /** Schema owned by this capability. Defaults to `authorisation`. */
  schema?: string
}

/**
 * How fresh a directory answer must be. Ending a membership must end the
 * access derived from it (docs/contracts.md, "Revocation").
 *
 * - `strong` — read from the source of truth; no cache. Used for `high` and
 *   `critical` permissions.
 * - `bounded` — may come from a cache no older than
 *   `AUTHORISATION_MAX_STALENESS_SECONDS`. Used for `low` and `medium`.
 */
export type AuthorisationDirectoryConsistency = 'strong' | 'bounded'

/** Upper bound on the age of a `bounded` directory answer. */
export const AUTHORISATION_MAX_STALENESS_SECONDS = 30

export interface AuthorisationDirectoryReadOptions {
  consistency: AuthorisationDirectoryConsistency
}

/**
 * Directory port: groups, tenants and memberships, which Identity owns. The
 * host adapts Identity's public contract (or, until Identity exists, its own
 * store) to this shape.
 *
 * Both methods must honour `options.consistency`. A failure must reject (the
 * decision then fails closed); it must never answer with partial data, or
 * with data older than the requested consistency allows.
 */
export interface AuthorisationDirectory {
  /** The principal's personal group and memberships with their status, or null if unknown. */
  resolveActor(principalId: string, options: AuthorisationDirectoryReadOptions): Promise<AuthorisationActorContext | null>
  /** The group's lineage and tenant, or null if the group is unknown. */
  describeGroup(groupId: string, options: AuthorisationDirectoryReadOptions): Promise<AuthorisationGroup | null>
}

/**
 * Optional event port for audit and logging capabilities.
 *
 * Delivery is best effort: a sink failure is reported but never changes the
 * outcome of the operation that produced the event.
 */
export interface AuthorisationEventSink {
  emit(event: AuthorisationEvent): void | Promise<void>
}

/**
 * Clock port (docs/contracts.md, "Time"; iam-integration architecture §7):
 * the current time. Optional; without it Authorisation uses the system
 * clock. Every time Authorisation keeps or judges comes from it: grant
 * expiry, the age of an authentication for a permission that needs a recent
 * one, the times it records and events' `occurredAt`. Trusted like a key,
 * since it can keep an expired grant alive or make an old sign-in look
 * recent. An answer that is not a valid `Date`, or a failure, fails the
 * operation closed as `unavailable`: never a decision on another time.
 */
export interface AuthorisationClock {
  now(): Date
}

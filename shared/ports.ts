import type { AuthorisationEvent } from './events'
import type { AuthorisationActorContext, AuthorisationGroupLineage } from './resources'

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
 * Directory port: groups and memberships, which Identity owns. The host
 * adapts Identity's public contract (or, until Identity exists, its own
 * store) to this shape.
 *
 * Both methods answer from current data on every call. An adapter that
 * caches must expire entries quickly, because leaving a group must end
 * access promptly (docs/threat-model.md).
 */
export interface AuthorisationDirectory {
  /** The principal's personal group and current memberships, or null if unknown. */
  resolveActor(principalId: string): Promise<AuthorisationActorContext | null>
  /** The group's lineage from its tenant root, or null if the group is unknown. */
  getGroupLineage(groupId: string): Promise<AuthorisationGroupLineage | null>
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

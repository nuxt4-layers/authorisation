import type { AuthorisationRequiredApprovers } from './changes'
import type { AuthorisationDenialEvent, AuthorisationEvent } from './events'
import type { AuthorisationActorContext, AuthorisationGroup } from './resources'
import type { AuthorisationSubject } from './subject'

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
 * Optional port for refused decisions (`authorisation.denied`), for audit
 * and logging. Delivery is best effort: a sink failure is reported but never
 * changes the decision. Every other event goes through the transactional
 * outbox (`relayAuthorisationOutbox`) instead (contract 4).
 */
export interface AuthorisationEventSink {
  emit(event: AuthorisationDenialEvent): void | Promise<void>
}

/**
 * Where `relayAuthorisationOutbox` publishes the outbox's events. An event
 * is marked relayed only when `publish` resolves; a rejection stops the
 * relay, and the event is published again on the next run (at least once).
 */
export interface AuthorisationEventPublisher {
  publish(event: AuthorisationEvent): Promise<void>
}

/** The safety periods in force for a group, from Identity (iam-integration `approvals.md`). */
export interface AuthorisationSafetyPeriods {
  publishedDelayHighHours: number
  publishedDelayCriticalHours: number
  approvalExpiryDays: number
  recoveryHoldHours: number
}

/** A group as Identity's access governance describes it to Authorisation, for one requester. */
export interface AuthorisationGovernedGroup {
  groupId: string
  tenantId: string
  kind: 'standard' | 'personal'
  state: 'active' | 'orphaned' | 'archived'
  parentGroupId: string | null
  rootGroupId: string
  /** For a personal group: whose it is. */
  personalOfPrincipalId: string | null
  approvals: { required: AuthorisationRequiredApprovers, referenceRequired: boolean }
  safetyPeriods: AuthorisationSafetyPeriods
  requester: {
    /** The end of the requester's recovery hold, if one is running (ISO 8601). */
    recoveryHoldUntil: string | null
    /** Identities the requester controls (service identities they created), which never approve for them. */
    controls: readonly string[]
  }
}

/**
 * Governance port (contract 4; iam-integration architecture §3): Identity's
 * facts that Authorisation's approvals need and does not hold, read from
 * Identity's own record at `strong` consistency. Supplied by the host from
 * iam-integration's `authorisationGovernanceFromIdentity`. Required for
 * change requests and decisions: missing, a change fails closed. A failure
 * must reject; `describeGroup` answers null for a group Identity does not
 * know.
 */
export interface AuthorisationGovernance {
  describeGroup(input: { groupId: string, principalId: string, correlationId: string }): Promise<AuthorisationGovernedGroup | null>
  isOwner(input: { principalId: string, groupId: string }): Promise<boolean>
  countOwners(input: { groupId: string, excluding: readonly string[] }): Promise<number>
}

/**
 * Subject-resolver port, supplied by the host from Authentication
 * (`getAuthenticatedPrincipal(event)`), for the layer's endpoints.
 * `request` is the server's request event, passed through untouched: the
 * contract names no HTTP framework. Resolves null when nobody is signed in;
 * rejects on failure.
 */
export interface AuthorisationSubjectResolver {
  resolve(request: unknown): Promise<AuthorisationSubject | null>
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

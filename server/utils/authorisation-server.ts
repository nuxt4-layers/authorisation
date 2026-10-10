import type {
  AuthorisationDataExport,
  AuthorisationDecision,
  AuthorisationErrorBody,
  AuthorisationEventPublisher,
  AuthorisationErrorCode,
  AuthorisationGrant,
  AuthorisationResource,
  AuthorisationRoleAssignment,
  AuthorisationRoleAssignmentScope,
  AuthorisationRoleDefinition,
} from '../../contracts'
import { AUTHORISATION_ERROR_STATUS, AuthorisationFailure } from '../../contracts'
import { runAuthorisationMigrations } from '../database/migrations'
import { timeFrom } from '../internal/clock'
import { createDatabase } from '../internal/database'
import type { RelayResult } from '../internal/outbox'
import { relayOutbox } from '../internal/outbox'
import type { AuthoriseInput } from '../internal/service'
import { createService } from '../internal/service'
import {
  emitAuthorisationDenial,
  useAuthorisationCatalogue,
  useAuthorisationClock,
  useAuthorisationDatabase,
  useAuthorisationDirectory,
  useAuthorisationPolicy,
} from './authorisation-composition'

/**
 * PUBLIC server functions (auto-imported for the host's server code). Every
 * one fails closed: a directory or database failure throws
 * `AuthorisationFailure('unavailable')`, as does a clock that answers an
 * invalid time. Every time they keep or judge comes from the host's clock
 * (`provideAuthorisationClock`), or the system clock when none is supplied.
 *
 * The functions that change roles, assignments and grants decide nothing:
 * the caller has already authorised the change (the layer's own endpoints in
 * phase 3, or the host applying Identity's events through iam-integration).
 */

let migration: Promise<string[]> | null = null

/**
 * Applies pending migrations to the capability schema. Call once from the
 * host's Nitro plugin after `provideAuthorisationDatabase`; operations wait for
 * it. Safe to run concurrently from several instances.
 */
export function migrateAuthorisationDatabase(): Promise<string[]> {
  const database = useAuthorisationDatabase()
  migration = runAuthorisationMigrations(database.pool, database.schema)
  migration.catch((error) => {
    console.error('[authorisation] database migrations failed:', error instanceof Error ? error.message : error)
  })
  return migration
}

async function service() {
  if (migration) await migration.catch(() => { throw new AuthorisationFailure('unavailable', 'migrations failed') })
  const database = useAuthorisationDatabase()
  return createService({
    db: createDatabase(database.pool, database.schema),
    schemaName: database.schema,
    directory: useAuthorisationDirectory(),
    catalogue: useAuthorisationCatalogue(),
    policy: useAuthorisationPolicy(),
    emitDenial: emitAuthorisationDenial,
    // Read at each use, so every time comes from the host's clock (or the system clock).
    now: () => useAuthorisationClock().now(),
  })
}

/** May this subject perform this permission on this resource, now? Refusals are announced as `authorisation.denied`. */
export async function authorise(input: AuthoriseInput): Promise<AuthorisationDecision> {
  return (await service()).authorise(input)
}

function httpError(code: AuthorisationErrorCode) {
  const data: AuthorisationErrorBody = { code, messageKey: `authorisation.error.${code}` }
  return createError({ statusCode: AUTHORISATION_ERROR_STATUS[code], statusMessage: code, data })
}

/**
 * As `authorise`, but throws a coarse HTTP error unless allowed: `forbidden`
 * (never saying why), `insufficient-assurance`, or `unavailable`.
 */
export async function requireAuthorisation(input: AuthoriseInput): Promise<void> {
  let decision: AuthorisationDecision
  try {
    decision = await authorise(input)
  }
  catch (error) {
    throw httpError(error instanceof AuthorisationFailure ? error.code : 'unavailable')
  }
  if (!decision.allowed) throw httpError(decision.reason === 'insufficient-assurance' ? 'insufficient-assurance' : 'forbidden')
}

/** Whether the principal holds the permission on the resource now, whatever their session (for approvals). */
export async function authorisationQualifies(input: { principalId: string, permission: string, resource: AuthorisationResource }): Promise<boolean> {
  return (await service()).qualifies(input)
}

/** How many principals, other than those excluded, hold the permission on the resource now, up to `limit` (at most 100). */
export async function countAuthorisationQualifying(input: { permission: string, resource: AuthorisationResource, excludingPrincipalIds: readonly string[], limit: number }): Promise<number> {
  return (await service()).countQualifying(input)
}

export async function listAuthorisationRoleAssignments(input: { principalId?: string, groupId?: string }): Promise<AuthorisationRoleAssignment[]> {
  return (await service()).listAssignments(input)
}

/**
 * Gives a principal a role in a group, optionally until `expiresAt`. Returns
 * whether anything changed. Decides nothing: for the host's own server code
 * (owners and default roles from Identity's events). Written with its
 * `authorisation.role-assigned` event through the outbox.
 */
export async function assignAuthorisationRole(input: { principalId: string, groupId: string, roleId: string, scope?: AuthorisationRoleAssignmentScope, expiresAt?: string | null, actorPrincipalId: string, correlationId?: string }): Promise<boolean> {
  return (await service()).assign(input)
}

/** Takes a role, or with `roleId: null` every role, from a principal in a group. Returns the roles removed. Decides nothing. */
export async function unassignAuthorisationRole(input: { principalId: string, groupId: string, roleId: string | null, actorPrincipalId: string, correlationId?: string }): Promise<string[]> {
  return (await service()).unassign(input)
}

export async function defineAuthorisationRole(input: { tenantId: string, role: AuthorisationRoleDefinition, actorPrincipalId: string, correlationId?: string }): Promise<'defined' | 'changed'> {
  return (await service()).defineRole(input)
}

export async function deleteAuthorisationRole(input: { tenantId: string, roleId: string, actorPrincipalId: string, correlationId?: string }): Promise<boolean> {
  return (await service()).deleteRole(input)
}

/** Shares a resource; returns the grant's identifier. Decides nothing. */
export async function createAuthorisationGrant(input: { grant: AuthorisationGrant, actorPrincipalId: string, correlationId?: string }): Promise<string> {
  return (await service()).createGrant(input)
}

export async function revokeAuthorisationGrant(input: { grantId: string, actorPrincipalId: string, correlationId?: string }): Promise<boolean> {
  return (await service()).revokeGrant(input)
}

/**
 * Authorisation's part of a data-subject access request: the role
 * assignments and grants the principal holds. Server-only: the host calls it
 * through iam-integration's coordination adapter, for Profile. Answers null
 * when the principal holds nothing.
 */
export async function exportAuthorisationData(input: { principalId: string, correlationId: string }): Promise<AuthorisationDataExport | null> {
  const exported = await (await service()).exportPrincipal(input)
  return exported.roleAssignments.length === 0 && exported.grants.length === 0 ? null : exported
}

/**
 * Removes every role assignment and grant the principal holds, on Identity's
 * `identity.closed` (account closure), unless a legal hold covers
 * Authorisation's part. Decides nothing; idempotent. Announced as
 * `authorisation.principal-erased`. Returns how many were removed.
 */
export async function eraseAuthorisationPrincipal(input: { principalId: string, actorPrincipalId: string, correlationId?: string }): Promise<{ assignments: number, grants: number }> {
  return (await service()).erasePrincipal(input)
}

/**
 * Publishes up to `limit` (1 to 1000) of the outbox's events, in order,
 * through `publish`; each is marked relayed only when `publish` resolves. A
 * failure stops the run, and the event is published again next time (at
 * least once). The host runs it on a schedule, or after each request.
 */
export async function relayAuthorisationOutbox(input: { publish: AuthorisationEventPublisher['publish'], limit?: number }): Promise<RelayResult> {
  if (migration) await migration.catch(() => { throw new AuthorisationFailure('unavailable', 'migrations failed') })
  const database = useAuthorisationDatabase()
  const clock = useAuthorisationClock()
  try {
    return await relayOutbox(createDatabase(database.pool, database.schema), { publish: input.publish }, input.limit ?? 100, () => timeFrom(clock))
  }
  catch (error) {
    if (error instanceof AuthorisationFailure) throw error
    throw new AuthorisationFailure('unavailable', 'outbox relay failed')
  }
}

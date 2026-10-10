import { z } from 'zod'
import { AUTHORISATION_APPROVAL_ROUTES, AUTHORISATION_CHANGE_TYPES } from './changes'
import type { AuthorisationChangeType } from './changes'
import type { AuthorisationDenialReason } from './decision'
import { correlationIdSchema, identifierSchema, instantSchema, sha256DigestSchema, uuidSchema } from './identifiers'
import { AUTHORISATION_RISK_LEVELS } from './permissions'
import type { AuthorisationResourceRef } from './resources'
import { ROLE_ASSIGNMENT_SCOPES } from './roles'

/**
 * Authorisation's events (docs/contracts.md §8; iam-integration
 * architecture §4).
 *
 * Every change to roles, assignments, grants, group access and pending
 * changes writes its event to Authorisation's transactional outbox in the
 * same transaction as the change, so the event exists if and only if the
 * change committed. The host relays them (`relayAuthorisationOutbox`).
 * Delivery is at least once: consumers are idempotent by `eventId`.
 *
 * Decisions change nothing, so a refusal (`authorisation.denied`) is not an
 * outbox event: it goes to the optional best-effort event sink.
 *
 * Every event carries opaque identifiers, codes, role and permission names,
 * instants and the correlation identifier only: never a name, an address,
 * a resource attribute or free text.
 */

const id = identifierSchema
const changeType = z.enum(AUTHORISATION_CHANGE_TYPES as [AuthorisationChangeType, ...AuthorisationChangeType[]])
const risk = z.enum(AUTHORISATION_RISK_LEVELS)
const roleId = z.string().regex(/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/).max(64)
const permission = z.string().max(128)

const changeFacts = {
  changeId: uuidSchema,
  changeType,
  tenantId: id,
  groupId: id,
  requesterId: id,
  beneficiaryId: id.nullable(),
  risk,
  route: z.enum(AUTHORISATION_APPROVAL_ROUTES),
}

const assignmentFacts = {
  principalId: id,
  groupId: id,
  roleId,
  scope: z.enum(ROLE_ASSIGNMENT_SCOPES),
  expiresAt: instantSchema.nullable(),
  /** The change that made it, or null when the host's own server code did (Identity's events). */
  changeId: uuidSchema.nullable(),
}

const grantFacts = {
  grantId: uuidSchema,
  resourceType: z.string().max(100),
  resourceId: id,
  owningGroupId: id.nullable(),
  holder: z.discriminatedUnion('kind', [
    z.strictObject({ kind: z.literal('principal'), principalId: id }),
    z.strictObject({ kind: z.literal('group'), groupId: id }),
  ]),
  permissions: z.array(permission).min(1).max(100),
  expiresAt: instantSchema.nullable(),
  changeId: uuidSchema.nullable(),
}

const roleFacts = {
  tenantId: id,
  roleId,
  /** SHA-256 of the role's canonical JSON; null for a deletion. */
  digest: sha256DigestSchema.nullable(),
  changeId: uuidSchema.nullable(),
}

const payloads = {
  'authorisation.change-requested': z.strictObject({
    ...changeFacts,
    state: z.enum(['awaiting-approval', 'delayed', 'applied', 'rejected']),
    requiredApprovals: z.number().int().min(0).max(2),
    delayEndsAt: instantSchema.nullable(),
    expiresAt: instantSchema.nullable(),
  }),
  'authorisation.change-decided': z.strictObject({ ...changeFacts, state: z.enum(['applied', 'rejected', 'expired', 'cancelled']) }),
  'authorisation.change-held': z.strictObject({ ...changeFacts, state: z.enum(['awaiting-approval', 'delayed']), heldUntil: instantSchema }),
  'authorisation.role-assigned': z.strictObject(assignmentFacts),
  'authorisation.role-unassigned': z.strictObject(assignmentFacts),
  'authorisation.role-expired': z.strictObject(assignmentFacts),
  'authorisation.assignment-confirmed': z.strictObject({ principalId: id, groupId: id, roleId, confirmedAt: instantSchema, changeId: uuidSchema }),
  'authorisation.grant-created': z.strictObject(grantFacts),
  'authorisation.grant-revoked': z.strictObject(grantFacts),
  'authorisation.role-defined': z.strictObject(roleFacts),
  'authorisation.role-changed': z.strictObject(roleFacts),
  'authorisation.role-deleted': z.strictObject(roleFacts),
  'authorisation.roles-imported': z.strictObject({
    tenantId: id,
    /** The imported document's digest. */
    digest: sha256DigestSchema,
    defined: z.array(roleId).max(500),
    changed: z.array(roleId).max(500),
    deleted: z.array(roleId).max(500),
  }),
  'authorisation.group-access-changed': z.strictObject({
    groupId: id,
    tenantId: id,
    changed: z.array(z.enum(['default-roles', 'review-interval'])).min(1),
    changeId: uuidSchema,
  }),
  /** Announced once per assignment and confirmation: it keeps working until someone removes it. */
  'authorisation.review-overdue': z.strictObject({
    principalId: id,
    groupId: id,
    roleId,
    /** When it was last confirmed, or made when never confirmed. */
    lastConfirmedAt: instantSchema,
    reviewDueAt: instantSchema,
  }),
  'authorisation.principal-erased': z.strictObject({ principalId: id, assignments: z.number().int().min(0), grants: z.number().int().min(0) }),
  /**
   * Authorisation's part of a deleted group is gone (iam-integration group
   * deletion): its assignments, the grants on what it owned or to it, its
   * access settings and its changes. Identity counts it as confirmed.
   */
  'authorisation.group-disposed': z.strictObject({
    groupId: id,
    assignments: z.number().int().min(0),
    grants: z.number().int().min(0),
    changes: z.number().int().min(0),
  }),
  /** Authorisation's part of a closed tenant is gone: its custom roles and their changes. */
  'authorisation.tenant-disposed': z.strictObject({ tenantId: id, roles: z.number().int().min(0), changes: z.number().int().min(0) }),
  /** One maintenance run's deletions under the retention schedules (iam-integration retention): counts only. */
  'authorisation.retention-applied': z.strictObject({ outboxEvents: z.number().int().min(0), changes: z.number().int().min(0) }),
} as const

export type AuthorisationEventType = keyof typeof payloads
export const AUTHORISATION_EVENT_TYPES = Object.freeze(Object.keys(payloads) as AuthorisationEventType[])

const envelope = {
  /** Consumers are idempotent by it. */
  eventId: uuidSchema,
  occurredAt: instantSchema,
  correlationId: correlationIdSchema,
  /** The principal who caused the change, or null for the system (maintenance, an import, an expiry). */
  actorPrincipalId: id.nullable(),
}

function eventSchema<T extends AuthorisationEventType>(type: T) {
  return z.strictObject({ ...envelope, type: z.literal(type), data: payloads[type] })
}

export const authorisationEventSchema = z.discriminatedUnion(
  'type',
  AUTHORISATION_EVENT_TYPES.map(type => eventSchema(type)) as unknown as [ReturnType<typeof eventSchema>, ...ReturnType<typeof eventSchema>[]],
)

/** An outbox event, as `relayAuthorisationOutbox` publishes it. */
export type AuthorisationEvent = {
  [T in AuthorisationEventType]: { eventId: string, occurredAt: string, correlationId: string, actorPrincipalId: string | null, type: T, data: z.infer<(typeof payloads)[T]> }
}[AuthorisationEventType]

/** Per-type payload schemas, for consumers that validate one type. */
export const AUTHORISATION_EVENT_PAYLOADS: Readonly<Record<AuthorisationEventType, z.ZodType>> = Object.freeze(payloads)

/**
 * A refused decision, for audit: delivered best effort to the host's
 * `AuthorisationEventSink`, never through the outbox, since a decision
 * changes nothing. Opaque identifiers only.
 */
export interface AuthorisationDenialEvent {
  type: 'authorisation.denied'
  /** ISO 8601 timestamp. */
  occurredAt: string
  /** The principal who asked. */
  actorPrincipalId: string
  groupId: string
  resource: AuthorisationResourceRef
  permission: string
  reason: AuthorisationDenialReason
}

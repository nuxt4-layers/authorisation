import type { AuthorisationDenialReason } from './decision'
import type { AuthorisationResourceRef } from './resources'

/**
 * Facts Authorisation emits for audit and logging. Events carry opaque
 * identifiers only: never names, email addresses, resource attributes or
 * other personal data.
 */
export const AUTHORISATION_EVENT_TYPES = [
  'authorisation.denied',
  'authorisation.role-defined',
  'authorisation.role-changed',
  'authorisation.role-deleted',
  'authorisation.role-assigned',
  'authorisation.role-unassigned',
  'authorisation.grant-created',
  'authorisation.grant-revoked',
] as const

export type AuthorisationEventType = typeof AUTHORISATION_EVENT_TYPES[number]

export interface AuthorisationEvent {
  type: AuthorisationEventType
  /** ISO 8601 timestamp. */
  occurredAt: string
  /** The principal who asked (for `denied`) or who made the change. */
  actorPrincipalId: string
  /** The principal a role assignment or grant is about, when different from the actor. */
  subjectPrincipalId: string | null
  groupId: string | null
  resource: AuthorisationResourceRef | null
  permission: string | null
  roleId: string | null
  /** For `authorisation.denied`. */
  reason: AuthorisationDenialReason | null
}

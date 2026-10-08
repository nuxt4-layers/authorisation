/**
 * Public contract for the `@nuxt4-layers/authorisation` capability.
 *
 * This module is the only supported cross-layer import path for the layer's
 * types and pure helpers. Everything else in the repository is private.
 *
 * The contract uses the language of authorisation: subjects, permissions,
 * resources, groups, roles, grants and decisions. It stores and exposes no
 * domain data, and nothing from a database driver. It is plain TypeScript: it
 * imports nothing from Nuxt, Vue, h3 or the server.
 */

// ---------------------------------------------------------------------------
// Subject (who is asking)
// ---------------------------------------------------------------------------

export type {
  AuthorisationAssuranceLevel,
  AuthorisationAssuranceRequirement,
  AuthorisationSubject,
  AuthorisationSubjectAssurance,
} from '../shared/subject'

// ---------------------------------------------------------------------------
// Permissions (what may be done)
// ---------------------------------------------------------------------------

export type {
  AuthorisationPermissionCatalogue,
  AuthorisationPermissionDefinition,
  AuthorisationRiskLevel,
} from '../shared/permissions'
export {
  AUTHORISATION_PERMISSIONS,
  AUTHORISATION_RISK_LEVELS,
  isPermissionName,
  isPermissionPattern,
  permissionDefinitionSchema,
  permissionPatternMatches,
} from '../shared/permissions'

// ---------------------------------------------------------------------------
// Resources and groups (to what, and whose)
// ---------------------------------------------------------------------------

export type {
  AuthorisationActorContext,
  AuthorisationAttributeValue,
  AuthorisationGroupLineage,
  AuthorisationMembership,
  AuthorisationResource,
  AuthorisationResourceRef,
} from '../shared/resources'

// ---------------------------------------------------------------------------
// Roles, assignments, grants and conditions
// ---------------------------------------------------------------------------

export type {
  AuthorisationCondition,
  AuthorisationConditionOperator,
  AuthorisationGrant,
  AuthorisationGrantSubject,
  AuthorisationRoleAssignment,
  AuthorisationRoleDefinition,
  AuthorisationRolePermission,
  BuiltInRoleId,
} from '../shared/roles'
export {
  BUILT_IN_ROLE_IDS,
  CONDITION_OPERATORS,
  conditionSchema,
  roleDefinitionSchema,
  rolePermissionSchema,
} from '../shared/roles'

// ---------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------

export type {
  AuthorisationDecision,
  AuthorisationDenialReason,
  AuthorisationGrantSource,
} from '../shared/decision'

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export type { AuthorisationErrorBody, AuthorisationErrorCode } from '../shared/errors'
export {
  AUTHORISATION_ERROR_CODES,
  AUTHORISATION_ERROR_STATUS,
  AuthorisationCompositionError,
  isAuthorisationErrorCode,
} from '../shared/errors'

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

export type { AuthorisationEvent, AuthorisationEventType } from '../shared/events'
export { AUTHORISATION_EVENT_TYPES } from '../shared/events'

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

export type { AuthorisationPolicy, AuthorisationPolicyInput } from '../shared/policy'
export { DEFAULT_AUTHORISATION_POLICY, resolveAuthorisationPolicy } from '../shared/policy'

// ---------------------------------------------------------------------------
// Composition ports (supplied by the host application)
// ---------------------------------------------------------------------------

export type {
  AuthorisationDatabase,
  AuthorisationDirectory,
  AuthorisationEventSink,
  PostgresPoolLike,
} from '../shared/ports'

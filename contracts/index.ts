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
  AuthorisationPermissionDefinitionInput,
  AuthorisationPermissionEffect,
  AuthorisationRiskLevel,
} from '../shared/permissions'
export {
  AUTHORISATION_PERMISSION_EFFECTS,
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
  AuthorisationGroup,
  AuthorisationGroupLineage,
  AuthorisationMembership,
  AuthorisationMembershipStatus,
  AuthorisationPrincipalStatus,
  AuthorisationResource,
  AuthorisationResourceRef,
} from '../shared/resources'
export { AUTHORISATION_MEMBERSHIP_STATUSES, AUTHORISATION_PRINCIPAL_STATUSES } from '../shared/resources'

// ---------------------------------------------------------------------------
// Roles, assignments, grants and conditions
// ---------------------------------------------------------------------------

export type {
  AuthorisationCondition,
  AuthorisationConditionOperator,
  AuthorisationDataExport,
  AuthorisationGrant,
  AuthorisationGrantSubject,
  AuthorisationRoleAssignment,
  AuthorisationRoleAssignmentScope,
  AuthorisationRoleDefinition,
  AuthorisationRolePermission,
  BuiltInRoleId,
} from '../shared/roles'
export {
  BUILT_IN_ROLE_IDS,
  CONDITION_OPERATORS,
  conditionSchema,
  ROLE_ASSIGNMENT_SCOPES,
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
  AuthorisationFailure,
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
  AuthorisationDirectoryConsistency,
  AuthorisationDirectoryReadOptions,
  AuthorisationEventSink,
  PostgresPoolLike,
} from '../shared/ports'
export { AUTHORISATION_MAX_STALENESS_SECONDS } from '../shared/ports'

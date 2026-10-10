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
// Identifiers, codes, instants and digests
// ---------------------------------------------------------------------------

export {
  canonicalJson,
  correlationIdSchema,
  IDENTIFIER_PATTERN,
  identifierSchema,
  instantSchema,
  justificationReferenceSchema,
  REASON_CODE_PATTERN,
  reasonCodeSchema,
  sha256DigestSchema,
  UUID_PATTERN,
  uuidSchema,
  versionSchema,
} from '../shared/identifiers'

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
  AuthorisationAdministrationPermission,
  AuthorisationPermissionEffect,
  AuthorisationRiskLevel,
} from '../shared/permissions'
export {
  AUTHORISATION_PERMISSION_EFFECTS,
  AUTHORISATION_PERMISSIONS,
  AUTHORISATION_RISK_LEVELS,
  higherRisk,
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

export type { AuthorisationDenialEvent, AuthorisationEvent, AuthorisationEventType } from '../shared/events'
export { AUTHORISATION_EVENT_PAYLOADS, AUTHORISATION_EVENT_TYPES, authorisationEventSchema } from '../shared/events'

// ---------------------------------------------------------------------------
// Changes and approvals (access administration)
// ---------------------------------------------------------------------------

export type {
  AuthorisationApprovalRecord,
  AuthorisationApprovalRefusal,
  AuthorisationApprovalRequirement,
  AuthorisationApprovalRoute,
  AuthorisationAssuranceRecord,
  AuthorisationChangeRefusal,
  AuthorisationChangeRequest,
  AuthorisationChangeState,
  AuthorisationChangeTarget,
  AuthorisationChangeType,
  AuthorisationDefaultRoles,
  AuthorisationJustification,
  AuthorisationPendingChange,
  AuthorisationRequiredApprovers,
} from '../shared/changes'
export {
  APPROVAL_REFUSALS,
  approvalRecordSchema,
  approvalRequirement,
  assignmentRisk,
  assuranceRecordSchema,
  AUTHORISATION_APPROVAL_ROUTES,
  AUTHORISATION_CHANGE_STATES,
  AUTHORISATION_CHANGE_TARGETS,
  AUTHORISATION_CHANGE_TYPES,
  AUTHORISATION_CHANGES,
  CHANGE_REFUSALS,
  changeRequestSchema,
  chooseRoute,
  DEFAULT_GROUP_DEFAULT_ROLES,
  defaultRolesSchema,
  isSelfGrant,
  justificationSchema,
  meetsStepUp,
  OPEN_CHANGE_STATES,
  pendingChangeSchema,
  refuseApproval,
  REVIEW_INTERVAL_DAYS,
  roleRisk,
  STEP_UP_REQUIREMENTS,
} from '../shared/changes'

// ---------------------------------------------------------------------------
// Administration views and role documents
// ---------------------------------------------------------------------------

export type {
  AuthorisationAccessReview,
  AuthorisationAccessReviewEntry,
  AuthorisationAssignmentView,
  AuthorisationGrantView,
  AuthorisationGroupAccess,
  AuthorisationRoleDocument,
  AuthorisationRoleView,
  AuthorisationSelfView,
  AuthorisationTenantRoles,
} from '../shared/administration'
export {
  AUTHORISATION_API_PREFIX,
  AUTHORISATION_CORRELATION_HEADER,
  AUTHORISATION_ROLE_DOCUMENT_FORMAT,
  AUTHORISATION_ROLE_DOCUMENT_VERSION,
  roleDocumentSchema,
} from '../shared/administration'

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

export type { AuthorisationPolicy, AuthorisationPolicyInput } from '../shared/policy'
export { DEFAULT_AUTHORISATION_POLICY, resolveAuthorisationPolicy } from '../shared/policy'

// ---------------------------------------------------------------------------
// Composition ports (supplied by the host application)
// ---------------------------------------------------------------------------

export type {
  AuthorisationClock,
  AuthorisationDatabase,
  AuthorisationDirectory,
  AuthorisationDirectoryConsistency,
  AuthorisationDirectoryReadOptions,
  AuthorisationEventPublisher,
  AuthorisationEventSink,
  AuthorisationGovernance,
  AuthorisationGovernedGroup,
  AuthorisationSafetyPeriods,
  AuthorisationSubjectResolver,
  PostgresPoolLike,
} from '../shared/ports'
export { AUTHORISATION_MAX_STALENESS_SECONDS } from '../shared/ports'

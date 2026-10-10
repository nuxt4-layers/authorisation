import { z } from 'zod'
import {
  correlationIdSchema,
  identifierSchema,
  instantSchema,
  justificationReferenceSchema,
  reasonCodeSchema,
  sha256DigestSchema,
  uuidSchema,
  versionSchema,
} from './identifiers'
import { AUTHORISATION_RISK_LEVELS, higherRisk, permissionPatternMatches } from './permissions'
import type { AuthorisationAdministrationPermission, AuthorisationPermissionCatalogue, AuthorisationRiskLevel } from './permissions'
import { ROLE_ASSIGNMENT_SCOPES, roleDefinitionSchema } from './roles'
import type { AuthorisationRolePermission } from './roles'
import type { AuthorisationAssuranceRequirement } from './subject'

/**
 * Access administration (docs/contracts.md §15; iam-integration
 * `docs/processes/access-administration.md` and `approvals.md`).
 *
 * Every change to who may do what is requested as a pending change, whatever
 * its risk. A `low` or `medium` change applies at once once authorised; a
 * `high` or `critical` one waits for its approval route. Rules every change
 * obeys:
 *
 * 1. **No self-grant at any risk level.** Outside their own personal group,
 *    nobody assigns a role to themselves, confirms their own assignment, or
 *    grants themselves access.
 * 2. **Owners follow Identity.** The `owner` role is never assigned or
 *    removed through a change, nor chosen as a default role.
 * 3. **Nobody approves their own request**, a request of which they are the
 *    beneficiary, or through an identity the requester controls.
 * 4. The approval is bound to a digest of the exact change; a change that
 *    differs from what was approved needs a new approval.
 * 5. **Personal-group sovereignty.** In their own personal group a person
 *    needs no approver, but steps up to the assurance the risk sets.
 * 6. Every rule is checked again when a change applies.
 */

/** The changes Authorisation records, the permission each exercises and whether it can confer access on its beneficiary. */
export const AUTHORISATION_CHANGES = Object.freeze({
  'role.assign': { permission: 'authorisation.role-assignments:manage', confers: true },
  'role.unassign': { permission: 'authorisation.role-assignments:manage', confers: false },
  'grant.create': { permission: 'authorisation.grants:manage', confers: true },
  'grant.revoke': { permission: 'authorisation.grants:manage', confers: false },
  'role.define': { permission: 'authorisation.roles:manage', confers: false },
  'role.delete': { permission: 'authorisation.roles:manage', confers: false },
  'group.change-default-roles': { permission: 'authorisation.group-access:manage', confers: false },
  'group.change-review-interval': { permission: 'authorisation.group-access:manage', confers: false },
  'assignment.confirm': { permission: 'authorisation.role-assignments:manage', confers: true },
} as const satisfies Record<string, { permission: AuthorisationAdministrationPermission, confers: boolean }>)

export type AuthorisationChangeType = keyof typeof AUTHORISATION_CHANGES
export const AUTHORISATION_CHANGE_TYPES = Object.freeze(Object.keys(AUTHORISATION_CHANGES) as AuthorisationChangeType[])

/**
 * How the requirement is met:
 * - `approvers` — qualifying principals in the group (or covering it);
 * - `parent-owner`, `tenant-owner` — the single-owner fallbacks (owners from Identity);
 * - `published-delay` — no approver exists; the change applies when the delay ends unless cancelled;
 * - `none` — no approver needed (low or medium risk, or the requester's own personal group).
 */
export const AUTHORISATION_APPROVAL_ROUTES = ['approvers', 'parent-owner', 'tenant-owner', 'published-delay', 'none'] as const
export type AuthorisationApprovalRoute = typeof AUTHORISATION_APPROVAL_ROUTES[number]

export const AUTHORISATION_CHANGE_STATES = ['awaiting-approval', 'delayed', 'applied', 'rejected', 'expired', 'cancelled'] as const
export type AuthorisationChangeState = typeof AUTHORISATION_CHANGE_STATES[number]

/** States in which a change has not yet taken effect, and can still be decided or cancelled. */
export const OPEN_CHANGE_STATES: readonly AuthorisationChangeState[] = Object.freeze(['awaiting-approval', 'delayed'])

/** A review interval's bounds, in days. */
export const REVIEW_INTERVAL_DAYS = Object.freeze({ min: 1, max: 3650 })

// ---------------------------------------------------------------------------
// What each change acts on
// ---------------------------------------------------------------------------

const id = identifierSchema
const roleId = roleDefinitionSchema.shape.id

/** A role a group gives its new members or guests, or null for none. */
export const defaultRolesSchema = z.strictObject({ member: roleId.nullable(), guest: roleId.nullable() })
export type AuthorisationDefaultRoles = z.infer<typeof defaultRolesSchema>

/** The defaults when a group has set none: `member` for members, `viewer` for guests. */
export const DEFAULT_GROUP_DEFAULT_ROLES: AuthorisationDefaultRoles = Object.freeze({ member: 'member', guest: 'viewer' })

const grantSchema = z.strictObject({
  resource: z.strictObject({ type: z.string().regex(/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\.[a-z][a-z0-9]*(?:-[a-z0-9]+)*)*$/).max(100), id, owningGroupId: id }),
  subject: z.discriminatedUnion('kind', [
    z.strictObject({ kind: z.literal('principal'), principalId: id }),
    z.strictObject({ kind: z.literal('group'), groupId: id }),
  ]),
  permissions: z.array(z.string().max(128)).min(1).max(100),
  expiresAt: instantSchema.nullable(),
})

/** The target of each change: what a requester submits, and what approvers see and approve (its digest). */
export const AUTHORISATION_CHANGE_TARGETS = {
  /** Gives `principalId` the role in `groupId`; optionally to its descendants (always `critical`) and until `expiresAt`. */
  'role.assign': z.strictObject({ principalId: id, groupId: id, roleId, scope: z.enum(ROLE_ASSIGNMENT_SCOPES).optional(), expiresAt: instantSchema.nullable().optional() }),
  'role.unassign': z.strictObject({ principalId: id, groupId: id, roleId }),
  /** Shares a resource of `owningGroupId` with a principal or a group. */
  'grant.create': z.strictObject({ grant: grantSchema }),
  'grant.revoke': z.strictObject({ grantId: uuidSchema }),
  /** Defines or changes a custom role of the tenant. Requested on the tenant's root group. */
  'role.define': z.strictObject({ tenantId: id, role: roleDefinitionSchema }),
  'role.delete': z.strictObject({ tenantId: id, roleId }),
  'group.change-default-roles': z.strictObject({ groupId: id, defaultRoles: defaultRolesSchema }),
  /** Days within which every assignment must be confirmed, or null for no review interval. */
  'group.change-review-interval': z.strictObject({ groupId: id, intervalDays: z.number().int().min(REVIEW_INTERVAL_DAYS.min).max(REVIEW_INTERVAL_DAYS.max).nullable() }),
  /** Records that the assignment is still needed (an access review). */
  'assignment.confirm': z.strictObject({ principalId: id, groupId: id, roleId }),
} as const satisfies Record<AuthorisationChangeType, z.ZodType>

export type AuthorisationChangeTarget<T extends AuthorisationChangeType = AuthorisationChangeType> = z.infer<typeof AUTHORISATION_CHANGE_TARGETS[T]>

export const justificationSchema = z.strictObject({
  reasonCode: reasonCodeSchema,
  reference: justificationReferenceSchema.nullable(),
})
export type AuthorisationJustification = z.infer<typeof justificationSchema>

function requestSchema<T extends AuthorisationChangeType>(type: T) {
  return z.strictObject({ type: z.literal(type), target: AUTHORISATION_CHANGE_TARGETS[type], justification: justificationSchema })
}

/** A change as a requester submits it. */
export const changeRequestSchema = z.discriminatedUnion(
  'type',
  AUTHORISATION_CHANGE_TYPES.map(type => requestSchema(type)) as unknown as [ReturnType<typeof requestSchema>, ...ReturnType<typeof requestSchema>[]],
)

export type AuthorisationChangeRequest = {
  [T in AuthorisationChangeType]: { type: T, target: AuthorisationChangeTarget<T>, justification: AuthorisationJustification }
}[AuthorisationChangeType]

export const assuranceRecordSchema = z.strictObject({
  level: z.enum(['aal1', 'aal2']),
  phishingResistant: z.boolean(),
  authenticatedAt: instantSchema,
})
export type AuthorisationAssuranceRecord = z.infer<typeof assuranceRecordSchema>

export const approvalRecordSchema = z.strictObject({
  approverId: id,
  decision: z.enum(['approve', 'reject']),
  decidedAt: instantSchema,
  assurance: assuranceRecordSchema,
  /** The digest of the change as the approver saw it. */
  changeDigest: sha256DigestSchema,
})
export type AuthorisationApprovalRecord = z.infer<typeof approvalRecordSchema>

export const pendingChangeSchema = z.strictObject({
  changeId: uuidSchema,
  type: z.enum(AUTHORISATION_CHANGE_TYPES as [AuthorisationChangeType, ...AuthorisationChangeType[]]),
  tenantId: id,
  /** The group whose permission the change exercises and whose approvers decide it. */
  groupId: id,
  requesterId: id,
  /** The principal the change confers on or acts against; null when it concerns only a group, a role or a group's grant. */
  beneficiaryId: id.nullable(),
  risk: z.enum(AUTHORISATION_RISK_LEVELS),
  justification: justificationSchema,
  /** What the change acts on (`AUTHORISATION_CHANGE_TARGETS`). */
  target: z.record(z.string(), z.unknown()),
  requiredApprovals: z.number().int().min(0).max(2),
  route: z.enum(AUTHORISATION_APPROVAL_ROUTES),
  approvals: z.array(approvalRecordSchema).max(4),
  /**
   * SHA-256 of the canonical JSON of the change as recorded (type, tenant,
   * group, requester, beneficiary, risk, justification, target, required
   * approvals, route, and the group's requirement and owners' groups when
   * requested). Recomputed before every decision and application; an
   * approval must quote it.
   */
  changeDigest: sha256DigestSchema,
  /** For `published-delay`, or a change held after approval: when it applies. */
  delayEndsAt: instantSchema.nullable(),
  /** For `awaiting-approval`: when it expires unapplied. */
  expiresAt: instantSchema.nullable(),
  /** The end of a hold (the requester's recovery hold, or riskier default roles): the change cannot apply before it. */
  heldUntil: instantSchema.nullable(),
  state: z.enum(AUTHORISATION_CHANGE_STATES),
  correlationId: correlationIdSchema,
  createdAt: instantSchema,
  /** When it was applied, rejected, expired or cancelled. */
  decidedAt: instantSchema.nullable(),
  version: versionSchema,
}).superRefine((change, context) => {
  if (!AUTHORISATION_CHANGE_TARGETS[change.type].safeParse(change.target).success) {
    context.addIssue({ code: 'custom', path: ['target'], message: 'The target does not match the change type' })
  }
})

export type AuthorisationPendingChange = Omit<z.infer<typeof pendingChangeSchema>, 'target'> & { target: AuthorisationChangeTarget }

// ---------------------------------------------------------------------------
// Assurance by risk (step-up)
// ---------------------------------------------------------------------------

/** What each risk level demands of the session, for requesters and approvers alike (approvals.md). */
export const STEP_UP_REQUIREMENTS: Readonly<Record<AuthorisationRiskLevel, AuthorisationAssuranceRequirement>> = Object.freeze({
  low: { minimumLevel: 'aal1', phishingResistant: false, maxAuthenticationAgeSeconds: null },
  medium: { minimumLevel: 'aal1', phishingResistant: false, maxAuthenticationAgeSeconds: null },
  high: { minimumLevel: 'aal2', phishingResistant: false, maxAuthenticationAgeSeconds: null },
  critical: { minimumLevel: 'aal2', phishingResistant: true, maxAuthenticationAgeSeconds: 900 },
})

export function meetsStepUp(assurance: AuthorisationAssuranceRecord, requirement: AuthorisationAssuranceRequirement, now: Date): boolean {
  if (requirement.minimumLevel === 'aal2' && assurance.level !== 'aal2') return false
  if (requirement.phishingResistant && !assurance.phishingResistant) return false
  if (requirement.maxAuthenticationAgeSeconds !== null) {
    const age = (now.getTime() - Date.parse(assurance.authenticatedAt)) / 1000
    if (!(age >= 0 && age <= requirement.maxAuthenticationAgeSeconds)) return false
  }
  return true
}

// ---------------------------------------------------------------------------
// Risk
// ---------------------------------------------------------------------------

const WILDCARD_RISKS: readonly AuthorisationRiskLevel[] = ['low', 'medium']

/**
 * The highest risk among the permissions a role confers, resolved against
 * the catalogue: a wildcard covers only `low` and `medium` permissions, as
 * in decisions; an exact name its own risk. Conditions are ignored, since a
 * condition narrows where a permission applies, not what it is. A role
 * that confers nothing is `low`.
 */
export function roleRisk(permissions: readonly AuthorisationRolePermission[], catalogue: AuthorisationPermissionCatalogue): AuthorisationRiskLevel {
  let risk: AuthorisationRiskLevel = 'low'
  for (const { pattern } of permissions) {
    if (!pattern.includes('*')) {
      const definition = catalogue.get(pattern)
      // An exact permission missing from the catalogue confers nothing; treated as critical so it never lowers a risk.
      risk = higherRisk(risk, definition?.risk ?? 'critical')
      continue
    }
    for (const definition of catalogue.values()) {
      if (WILDCARD_RISKS.includes(definition.risk) && permissionPatternMatches(pattern, definition.name)) risk = higherRisk(risk, definition.risk)
    }
  }
  return risk
}

/** A role assignment's risk: the role's, at least `medium` (the permission's floor); `critical` for the descendants scope. */
export function assignmentRisk(role: AuthorisationRiskLevel, scope: 'group' | 'group-and-descendants'): AuthorisationRiskLevel {
  return scope === 'group-and-descendants' ? 'critical' : higherRisk('medium', role)
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

export type AuthorisationRequiredApprovers = { low: 0 | 1, medium: 0 | 1, high: 1 | 2, critical: 1 | 2 }

export interface AuthorisationApprovalRequirement {
  approvers: 0 | 1 | 2
  stepUp: AuthorisationAssuranceRequirement
}

/**
 * What a change at `risk` requires. In the requester's own personal group:
 * no approver, but the step-up still applies. Elsewhere: the group's
 * requirement, never below the default floor.
 */
export function approvalRequirement(input: {
  risk: AuthorisationRiskLevel
  inRequestersPersonalGroup: boolean
  groupRequirement: AuthorisationRequiredApprovers | null
}): AuthorisationApprovalRequirement {
  const stepUp = STEP_UP_REQUIREMENTS[input.risk]
  if (input.inRequestersPersonalGroup) return { approvers: 0, stepUp }
  const floor = ({ low: 0, medium: 0, high: 1, critical: 1 } as const)[input.risk]
  const required = Math.max(floor, input.groupRequirement?.[input.risk] ?? floor) as 0 | 1 | 2
  return { approvers: required, stepUp }
}

/**
 * The route for a change, given who could approve. The fallbacks apply in
 * order only when too few besides the requester qualify in the group itself.
 */
export function chooseRoute(input: { approvers: 0 | 1 | 2, qualifyingInGroup: number, parentOwners: number, tenantOwners: number }): AuthorisationApprovalRoute {
  if (input.approvers === 0) return 'none'
  if (input.qualifyingInGroup >= input.approvers) return 'approvers'
  if (input.parentOwners > 0) return 'parent-owner'
  if (input.tenantOwners > 0) return 'tenant-owner'
  return 'published-delay'
}

/**
 * Rule codes for a refused request or application, carried as `reason` of a
 * `conflict` (or `validation-failed` for `reference-missing`). Each is shown
 * only to a caller entitled to see the change.
 */
export const CHANGE_REFUSALS = [
  'self-grant',
  'owner-role',
  'reference-missing',
  'group-not-active',
  'not-a-member',
  'unknown-role',
  'not-assigned',
  'role-in-use',
  'built-in-role',
  'unknown-permission',
  'guest-role-too-risky',
  'expiry-in-the-past',
  'requirement-changed',
  'risk-changed',
  'requester-not-qualified',
  'change-differs',
  'grant-gone',
  'unknown-holder',
  'digest-mismatch',
  'tenant-mismatch',
] as const
export type AuthorisationChangeRefusal = typeof CHANGE_REFUSALS[number]

export const APPROVAL_REFUSALS = [
  'own-request',
  'beneficiary',
  'controlled-by-requester',
  'not-qualified',
  'insufficient-assurance',
  'change-differs',
  'not-pending',
  'already-decided',
] as const
export type AuthorisationApprovalRefusal = typeof APPROVAL_REFUSALS[number]

/** Whether a change confers on its requester outside their personal group (rule 1). */
export function isSelfGrant(input: { type: AuthorisationChangeType, requesterId: string, beneficiaryId: string | null, inRequestersPersonalGroup: boolean }): boolean {
  return AUTHORISATION_CHANGES[input.type].confers && input.beneficiaryId === input.requesterId && !input.inRequestersPersonalGroup
}

/**
 * Checks an approval at decision time. `qualifies` must be read at that
 * moment with `strong` consistency, so an approver whose role was removed
 * after the request is refused; `controls` are the identities the requester
 * controls, from Identity at that moment.
 */
export function refuseApproval(input: {
  change: Pick<AuthorisationPendingChange, 'requesterId' | 'beneficiaryId' | 'changeDigest' | 'state' | 'approvals' | 'risk'>
  approverId: string
  qualifies: boolean
  controls: readonly string[]
  assurance: AuthorisationAssuranceRecord
  changeDigest: string
  now: Date
}): AuthorisationApprovalRefusal | null {
  const { change } = input
  if (change.state !== 'awaiting-approval') return 'not-pending'
  if (input.approverId === change.requesterId) return 'own-request'
  if (input.approverId === change.beneficiaryId) return 'beneficiary'
  if (input.controls.includes(input.approverId)) return 'controlled-by-requester'
  if (change.approvals.some(approval => approval.approverId === input.approverId)) return 'already-decided'
  if (!input.qualifies) return 'not-qualified'
  if (input.changeDigest !== change.changeDigest) return 'change-differs'
  if (!meetsStepUp(input.assurance, STEP_UP_REQUIREMENTS[change.risk], input.now)) return 'insufficient-assurance'
  return null
}

import type {
  AuthorisationActorContext,
  AuthorisationAssuranceRequirement,
  AuthorisationCondition,
  AuthorisationDecision,
  AuthorisationDenialReason,
  AuthorisationGrant,
  AuthorisationGrantSource,
  AuthorisationGroup,
  AuthorisationPermissionCatalogue,
  AuthorisationPermissionDefinition,
  AuthorisationPolicy,
  AuthorisationResource,
  AuthorisationRoleAssignment,
  AuthorisationRoleDefinition,
  AuthorisationRolePermission,
  AuthorisationSubject,
  BuiltInRoleId,
} from '../../contracts'
import { BUILT_IN_ROLE_IDS, permissionPatternMatches } from '../../contracts'

/**
 * The decision engine: a pure function from facts to a decision. It performs
 * no I/O; the caller gathers the facts from the directory and the database.
 *
 * Rules, in order (docs/contracts.md, "How a decision is made"):
 *
 * 1. Deny by default. An unknown permission, principal or group is refused.
 * 2. Tenant isolation is its own check: a resource outside the request's
 *    tenant context is refused before any role or grant is considered.
 * 3. Only `active` memberships count in full. A role assignment counts only
 *    while the principal is a member of the group it was made in, and only in
 *    that group's tenant. A `paused` membership, or a paused principal,
 *    confers only `view` permissions at `low` or `medium` risk, whichever
 *    route (role, personal-group role or grant) reaches the resource.
 * 4. The hierarchy confers nothing by default. An assignment covers the
 *    resource's own group; it reaches descendants only with the explicit
 *    `group-and-descendants` scope.
 * 5. A principal holds the policy's personal-group role in their own personal
 *    group. Creator provenance never grants access by itself.
 * 6. A grant counts until it expires, only for the owning group it was made
 *    for (when bound to one), and stays inside the resource's tenant unless
 *    the policy allows external grants. A time-limited role assignment
 *    counts until its end.
 * 7. Wildcards never cover `high` or `critical` permissions.
 * 8. A permitted action still needs the session assurance its risk demands.
 */

export interface AuthorisationFacts {
  subject: AuthorisationSubject
  /** From the directory; null when it does not know the principal. */
  actor: AuthorisationActorContext | null
  permission: string
  resource: AuthorisationResource
  /** The resource's owning group, from the directory; null when unknown. */
  owningGroup: AuthorisationGroup | null
  /**
   * The tenant the request is made in, resolved on the server (e.g. from the
   * route the host serves). Never taken from client input. Null when the
   * operation is not tenant-scoped.
   */
  requestTenantId: string | null
  /** The subject's role assignments (others' are ignored). */
  assignments: readonly AuthorisationRoleAssignment[]
  /** Custom roles, keyed by tenant ID, then role ID. */
  customRoles: ReadonlyMap<string, ReadonlyMap<string, AuthorisationRoleDefinition>>
  /** Grants on the resource (grants on other resources are ignored). */
  grants: readonly AuthorisationGrant[]
  catalogue: AuthorisationPermissionCatalogue
  policy: AuthorisationPolicy
  now: Date
}

const WILDCARD_RISKS = new Set(['low', 'medium'])
const VIEWABLE_WHILE_PAUSED = new Set(['low', 'medium'])

/** What a route to the resource confers now: everything, views only, or nothing. */
type Standing = 'active' | 'paused' | null

const STANDING_RANK = { active: 2, paused: 1 } as const

/** A status as a standing: anything but `active` or `paused` confers nothing. */
function standingOf(status: unknown): Standing {
  return status === 'active' || status === 'paused' ? status : null
}

/** The more restrictive of two standings. */
function lower(a: Standing, b: Standing): Standing {
  if (!a || !b) return null
  return STANDING_RANK[a] <= STANDING_RANK[b] ? a : b
}

/** The less restrictive of two standings. */
function higher(a: Standing, b: Standing): Standing {
  if (!a) return b
  if (!b) return a
  return STANDING_RANK[a] >= STANDING_RANK[b] ? a : b
}

const LEVEL_RANK = { aal1: 1, aal2: 2 } as const

export function decideAuthorisation(facts: AuthorisationFacts): AuthorisationDecision {
  const { subject, actor, permission, resource, owningGroup: group } = facts
  const deny = (reason: AuthorisationDenialReason): AuthorisationDecision =>
    ({ allowed: false, permission, reason, requirement: null })

  const definition = facts.catalogue.get(permission)
  if (!definition || !permission.startsWith(`${resource.type}:`)) return deny('unknown-permission')
  if (!actor || actor.principalId !== subject.principalId) return deny('unknown-subject')
  if (!group || group.groupId !== resource.owningGroupId || group.lineage.at(-1) !== group.groupId || !group.tenantId) {
    return deny('unknown-group')
  }
  if (facts.requestTenantId !== null && facts.requestTenantId !== group.tenantId) return deny('tenant-mismatch')

  const found = findSource(facts, actor, group, definition)
  if (!found) return deny('not-permitted')
  if (found.standing === 'paused' && !(definition.effect === 'view' && VIEWABLE_WHILE_PAUSED.has(definition.risk))) return deny('paused')
  const via = found.via

  const requirement = facts.policy.assurance[definition.risk]
  if (!meetsRequirement(subject, requirement, facts.now)) {
    return { allowed: false, permission, reason: 'insufficient-assurance', requirement }
  }
  return { allowed: true, permission, via }
}

/**
 * The route that allows the permission, preferring one that confers it in
 * full: a paused membership never hides an active route to the same
 * resource. Null when no route covers it.
 */
function findSource(
  facts: AuthorisationFacts,
  actor: AuthorisationActorContext,
  group: AuthorisationGroup,
  definition: AuthorisationPermissionDefinition,
): { via: AuthorisationGrantSource, standing: 'active' | 'paused' } | null {
  const { subject, resource, policy } = facts
  const covers = (role: AuthorisationRoleDefinition | undefined) =>
    !!role && role.permissions.some(entry => entryCovers(entry, definition, facts))

  // The principal's own standing caps every membership.
  const own = standingOf(actor.status)

  // What each group the principal belongs to confers now, and its tenant.
  const standingIn = new Map<string, { standing: Standing, tenantId: string }>()
  for (const { group: member, status } of actor.memberships) {
    const standing = lower(standingOf(status), own)
    if (standing) standingIn.set(member.groupId, { standing, tenantId: member.tenantId })
  }
  if (actor.personalGroup && own) standingIn.set(actor.personalGroup.groupId, { standing: own, tenantId: actor.personalGroup.tenantId })
  const inResourceTenant = (groupId: string): Standing => {
    const entry = standingIn.get(groupId)
    return entry && entry.tenantId === group.tenantId ? entry.standing : null
  }

  let best: { via: AuthorisationGrantSource, standing: 'active' | 'paused' } | null = null
  const consider = (via: AuthorisationGrantSource, standing: Standing) => {
    if (standing && (!best || STANDING_RANK[standing] > STANDING_RANK[best.standing])) best = { via, standing }
  }

  const now = facts.now.getTime()

  // Roles held in the owning group, or in an ancestor when explicitly scoped to descendants.
  for (const a of facts.assignments) {
    if (a.principalId !== subject.principalId) continue
    // A time-limited assignment past its end confers nothing, whether or not maintenance has removed it.
    if (a.expiresAt != null && !(Date.parse(a.expiresAt) > now)) continue
    if (a.groupId !== group.groupId && !(a.scope === 'group-and-descendants' && group.lineage.includes(a.groupId))) continue
    const standing = inResourceTenant(a.groupId)
    if (standing && covers(findRole(a.roleId, group.tenantId, facts))) consider('role', standing)
  }

  // The principal's own personal group.
  if (actor.personalGroup?.groupId === group.groupId && policy.personalGroupRole) {
    if (covers(builtInRole(policy.personalGroupRole, policy))) consider('personal-group', own)
  }

  // Grants on this resource, inside its tenant unless external grants are allowed.
  for (const grant of facts.grants) {
    if (grant.resource.type !== resource.type || grant.resource.id !== resource.id) continue
    // A grant bound to an owning group counts only while that group owns the resource, as its capability describes it now.
    if (grant.resource.owningGroupId && grant.resource.owningGroupId !== resource.owningGroupId) continue
    if (!grant.permissions.includes(definition.name)) continue
    if (grant.expiresAt !== null && !(Date.parse(grant.expiresAt) > now)) continue
    if (grant.subject.kind === 'group') {
      const groupId = grant.subject.groupId
      consider('grant', policy.externalGrants ? standingIn.get(groupId)?.standing ?? null : inResourceTenant(groupId))
    }
    else if (grant.subject.principalId === subject.principalId) {
      // A direct share holds while the principal is a member in the resource's
      // tenant, as fully as their best membership there; external grants need
      // only the principal's own standing.
      let standing: Standing = policy.externalGrants ? own : null
      for (const groupId of standingIn.keys()) standing = higher(standing, inResourceTenant(groupId))
      consider('grant', standing)
    }
  }
  return best
}

function builtInRole(id: BuiltInRoleId, policy: AuthorisationPolicy): AuthorisationRoleDefinition {
  return { id, name: id, permissions: [...policy.roles[id]] }
}

function findRole(roleId: string, tenantId: string, facts: AuthorisationFacts): AuthorisationRoleDefinition | undefined {
  if ((BUILT_IN_ROLE_IDS as readonly string[]).includes(roleId)) return builtInRole(roleId as BuiltInRoleId, facts.policy)
  return facts.customRoles.get(tenantId)?.get(roleId)
}

function entryCovers(entry: AuthorisationRolePermission, definition: AuthorisationPermissionDefinition, facts: AuthorisationFacts): boolean {
  if (!permissionPatternMatches(entry.pattern, definition.name)) return false
  if (entry.pattern.includes('*') && !WILDCARD_RISKS.has(definition.risk)) return false
  return (entry.when ?? []).every(condition => conditionHolds(condition, facts))
}

function conditionHolds(condition: AuthorisationCondition, facts: AuthorisationFacts): boolean {
  const { resource, subject } = facts
  let actual: unknown
  if (condition.attribute === 'resource.creatorPrincipalId') {
    actual = resource.creatorPrincipalId
  }
  else {
    const key = condition.attribute.slice('resource.attributes.'.length)
    if (!resource.attributes || !Object.hasOwn(resource.attributes, key)) return false
    actual = resource.attributes[key]
  }
  if (actual === undefined) return false

  const resolve = (value: unknown) =>
    value !== null && typeof value === 'object' && 'ref' in value ? subject.principalId : value
  const expected = Array.isArray(condition.value) ? condition.value.map(resolve) : resolve(condition.value)

  switch (condition.operator) {
    case 'equals': return actual === expected
    case 'not-equals': return actual !== expected
    case 'in': return (expected as unknown[]).includes(actual)
    case 'not-in': return !(expected as unknown[]).includes(actual)
  }
}

function meetsRequirement(subject: AuthorisationSubject, requirement: AuthorisationAssuranceRequirement, now: Date): boolean {
  const level = LEVEL_RANK[subject.assurance?.level]
  if (!level || level < LEVEL_RANK[requirement.minimumLevel]) return false
  if (requirement.phishingResistant && subject.assurance.phishingResistant !== true) return false
  if (requirement.maxAuthenticationAgeSeconds !== null) {
    const authenticatedAt = Date.parse(subject.authenticatedAt)
    if (Number.isNaN(authenticatedAt)) return false
    const age = (now.getTime() - authenticatedAt) / 1000
    if (age > requirement.maxAuthenticationAgeSeconds) return false
  }
  return true
}

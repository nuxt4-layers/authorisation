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
 * 3. Only `active` memberships count. A role assignment counts only while the
 *    principal is an active member of the group it was made in, and only in
 *    that group's tenant.
 * 4. The hierarchy confers nothing by default. An assignment covers the
 *    resource's own group; it reaches descendants only with the explicit
 *    `group-and-descendants` scope.
 * 5. A principal holds the policy's personal-group role in their own personal
 *    group. Creator provenance never grants access by itself.
 * 6. A grant counts until it expires, and stays inside the resource's tenant
 *    unless the policy allows external grants.
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

  const via = findSource(facts, actor, group, definition)
  if (!via) return deny('not-permitted')

  const requirement = facts.policy.assurance[definition.risk]
  if (!meetsRequirement(subject, requirement, facts.now)) {
    return { allowed: false, permission, reason: 'insufficient-assurance', requirement }
  }
  return { allowed: true, permission, via }
}

function findSource(
  facts: AuthorisationFacts,
  actor: AuthorisationActorContext,
  group: AuthorisationGroup,
  definition: AuthorisationPermissionDefinition,
): AuthorisationGrantSource | null {
  const { subject, resource, policy } = facts
  const covers = (role: AuthorisationRoleDefinition | undefined) =>
    !!role && role.permissions.some(entry => entryCovers(entry, definition, facts))

  // Active memberships, and the tenant of each group the principal belongs to.
  const tenantOf = new Map<string, string>()
  for (const { group: member, status } of actor.memberships) {
    if (status === 'active') tenantOf.set(member.groupId, member.tenantId)
  }
  if (actor.personalGroup) tenantOf.set(actor.personalGroup.groupId, actor.personalGroup.tenantId)
  const inResourceTenant = (groupId: string) => tenantOf.get(groupId) === group.tenantId

  // Roles held in the owning group, or in an ancestor when explicitly scoped to descendants.
  const heldRoles = facts.assignments
    .filter(a => a.principalId === subject.principalId && inResourceTenant(a.groupId))
    .filter(a => a.groupId === group.groupId || (a.scope === 'group-and-descendants' && group.lineage.includes(a.groupId)))
    .map(a => findRole(a.roleId, group.tenantId, facts))
  if (heldRoles.some(covers)) return 'role'

  // The principal's own personal group.
  if (actor.personalGroup?.groupId === group.groupId && policy.personalGroupRole) {
    if (covers(builtInRole(policy.personalGroupRole, policy))) return 'personal-group'
  }

  // Grants on this resource, inside its tenant unless external grants are allowed.
  const now = facts.now.getTime()
  const granted = facts.grants.some((grant) => {
    if (grant.resource.type !== resource.type || grant.resource.id !== resource.id) return false
    if (!grant.permissions.includes(definition.name)) return false
    if (grant.expiresAt !== null && !(Date.parse(grant.expiresAt) > now)) return false
    if (grant.subject.kind === 'group') {
      const groupId = grant.subject.groupId
      return tenantOf.has(groupId) && (policy.externalGrants || inResourceTenant(groupId))
    }
    return grant.subject.principalId === subject.principalId
      && (policy.externalGrants || [...tenantOf.values()].includes(group.tenantId))
  })
  return granted ? 'grant' : null
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

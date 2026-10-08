import type {
  AuthorisationActorContext,
  AuthorisationAssuranceRequirement,
  AuthorisationCondition,
  AuthorisationDecision,
  AuthorisationDenialReason,
  AuthorisationGrant,
  AuthorisationGrantSource,
  AuthorisationGroupLineage,
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
 * 2. A role assignment counts only while the principal is a current member of
 *    the group it was made in, and only for resources owned by that group or
 *    its descendants. Tenants are therefore isolated by construction.
 * 3. Every principal is the owner of their personal group.
 * 4. A resource's owner holds the resource-owner role on it while they are a
 *    member of a group in the resource's lineage.
 * 5. A grant counts until it expires. A grant to a principal outside the
 *    resource's tenant, or to a group in another tenant (including someone's
 *    personal group), counts only if the policy allows external grants.
 * 6. Wildcards never cover `high` or `critical` permissions.
 * 7. A permitted action still needs the session assurance its risk demands.
 */

export interface AuthorisationFacts {
  subject: AuthorisationSubject
  /** From the directory; null when it does not know the principal. */
  actor: AuthorisationActorContext | null
  permission: string
  resource: AuthorisationResource
  /** From the directory; null when it does not know the owning group. */
  resourceLineage: AuthorisationGroupLineage | null
  /** The subject's role assignments (others' are ignored). */
  assignments: readonly AuthorisationRoleAssignment[]
  /** Custom roles, keyed by tenant root group, then role ID. */
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
  const { subject, actor, permission, resource, resourceLineage: lineage } = facts
  const deny = (reason: AuthorisationDenialReason): AuthorisationDecision =>
    ({ allowed: false, permission, reason, requirement: null })

  const definition = facts.catalogue.get(permission)
  if (!definition || !permission.startsWith(`${resource.type}:`)) return deny('unknown-permission')
  if (!actor || actor.principalId !== subject.principalId) return deny('unknown-subject')
  if (!lineage?.length || lineage.at(-1) !== resource.owningGroupId) return deny('unknown-group')

  const via = findSource(facts, actor, lineage, definition)
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
  lineage: AuthorisationGroupLineage,
  definition: AuthorisationPermissionDefinition,
): AuthorisationGrantSource | null {
  const { subject, resource, policy } = facts
  const tenantRoot = lineage[0]!
  const memberOf = new Set([actor.personalGroupId, ...actor.memberships.map(m => m.groupId)])
  const tenantOf = new Map<string, string | undefined>([
    [actor.personalGroupId, actor.personalGroupId],
    ...actor.memberships.map(m => [m.groupId, m.lineage[0]] as const),
  ])
  const inTenant = new Set(tenantOf.values()).has(tenantRoot)
  const covers = (role: AuthorisationRoleDefinition | undefined) =>
    !!role && role.permissions.some(entry => entryCovers(entry, definition, facts))

  // Roles held in a group on the resource's lineage, while still a member of it.
  const heldRoles = facts.assignments
    .filter(a => a.principalId === subject.principalId && lineage.includes(a.groupId) && memberOf.has(a.groupId))
    .map(a => findRole(a.roleId, tenantRoot, facts))
  if (lineage.length === 1 && tenantRoot === actor.personalGroupId) heldRoles.push(builtInRole('owner', policy))
  if (heldRoles.some(covers)) return 'role'

  // The resource's owner, while still a member somewhere on its lineage.
  if (resource.ownerPrincipalId === subject.principalId && lineage.some(group => memberOf.has(group))) {
    if (covers(builtInRole(policy.resourceOwnerRole, policy))) return 'resource-owner'
  }

  // Grants on this resource.
  const now = facts.now.getTime()
  const granted = facts.grants.some((grant) => {
    if (grant.resource.type !== resource.type || grant.resource.id !== resource.id) return false
    if (!grant.permissions.includes(definition.name)) return false
    if (grant.expiresAt !== null && !(Date.parse(grant.expiresAt) > now)) return false
    // Information stays in its tenant unless the host allows external grants.
    if (grant.subject.kind === 'group') {
      return memberOf.has(grant.subject.groupId)
        && (policy.externalGrants || tenantOf.get(grant.subject.groupId) === tenantRoot)
    }
    return grant.subject.principalId === subject.principalId && (policy.externalGrants || inTenant)
  })
  return granted ? 'grant' : null
}

function builtInRole(id: BuiltInRoleId, policy: AuthorisationPolicy): AuthorisationRoleDefinition {
  return { id, name: id, permissions: [...policy.roles[id]] }
}

function findRole(roleId: string, tenantRoot: string, facts: AuthorisationFacts): AuthorisationRoleDefinition | undefined {
  if ((BUILT_IN_ROLE_IDS as readonly string[]).includes(roleId)) return builtInRole(roleId as BuiltInRoleId, facts.policy)
  return facts.customRoles.get(tenantRoot)?.get(roleId)
}

function entryCovers(entry: AuthorisationRolePermission, definition: AuthorisationPermissionDefinition, facts: AuthorisationFacts): boolean {
  if (!permissionPatternMatches(entry.pattern, definition.name)) return false
  if (entry.pattern.includes('*') && !WILDCARD_RISKS.has(definition.risk)) return false
  return (entry.when ?? []).every(condition => conditionHolds(condition, facts))
}

function conditionHolds(condition: AuthorisationCondition, facts: AuthorisationFacts): boolean {
  const { resource, subject } = facts
  let actual: unknown
  if (condition.attribute === 'resource.ownerPrincipalId') {
    actual = resource.ownerPrincipalId
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

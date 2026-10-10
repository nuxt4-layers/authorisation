import type {
  AuthorisationDataExport,
  AuthorisationDecision,
  AuthorisationDirectory,
  AuthorisationEvent,
  AuthorisationGrant,
  AuthorisationGroup,
  AuthorisationPermissionCatalogue,
  AuthorisationPolicy,
  AuthorisationResource,
  AuthorisationRoleAssignment,
  AuthorisationRoleAssignmentScope,
  AuthorisationRoleDefinition,
  AuthorisationSubject,
} from '../../contracts'
import { AuthorisationFailure, BUILT_IN_ROLE_IDS, ROLE_ASSIGNMENT_SCOPES, isPermissionName, roleDefinitionSchema } from '../../contracts'
import { timeFrom } from './clock'
import { decideAuthorisation } from './decide'
import type { AuthorisationStore, StoredGrant } from './store'

/**
 * PRIVATE. Authorisation's server operations: gathering the facts for a
 * decision from the directory and the store, and changing roles, role
 * assignments and grants. Any directory or store failure fails closed
 * (`AuthorisationFailure('unavailable')`).
 */

export interface ServiceDependencies {
  store: AuthorisationStore
  directory: AuthorisationDirectory
  catalogue: AuthorisationPermissionCatalogue
  policy: AuthorisationPolicy
  emit: (event: AuthorisationEvent) => Promise<void>
  /** The host's clock (or the system clock); every time Authorisation keeps or judges comes from it. */
  now?: () => Date
}

export interface AuthoriseInput {
  subject: AuthorisationSubject
  permission: string
  resource: AuthorisationResource
  /** The tenant the request is made in, resolved on the server; null when the operation is not tenant-scoped. */
  requestTenantId?: string | null
}

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

function requireIdentifier(value: unknown, what: string): string {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) throw new AuthorisationFailure('validation-failed', `invalid ${what}`)
  return value
}

export function createService({ store, directory, catalogue, policy, emit, now: clockNow = () => new Date() }: ServiceDependencies) {
  /** The clock's time; an invalid answer fails closed as `unavailable`, so no decision is made on another time. */
  const clock = { now: clockNow }
  const now = (): Date => timeFrom(clock)

  async function io<T>(what: string, run: () => Promise<T>): Promise<T> {
    try {
      return await run()
    }
    catch (error) {
      if (error instanceof AuthorisationFailure) throw error
      throw new AuthorisationFailure('unavailable', `${what} failed`)
    }
  }

  /** High and critical permissions read the directory from the source of truth. */
  const consistencyFor = (permission: string) => {
    const risk = catalogue.get(permission)?.risk
    return { consistency: risk === 'high' || risk === 'critical' || risk === undefined ? 'strong' as const : 'bounded' as const }
  }

  async function decide(input: AuthoriseInput): Promise<AuthorisationDecision> {
    const { subject, permission, resource } = input
    // The time of the decision, read first: a clock that fails refuses before anything is read.
    const at = now()
    const options = consistencyFor(permission)
    const [actor, owningGroup] = await io('directory', () => Promise.all([
      directory.resolveActor(subject.principalId, options),
      directory.describeGroup(resource.owningGroupId, options),
    ]))
    const tenants = [...new Set([owningGroup?.tenantId].filter((t): t is string => !!t))]
    const [assignments, customRoles, grants] = await io('store', () => Promise.all([
      store.assignmentsOf(subject.principalId),
      store.customRoles(tenants),
      store.grantsOn(resource),
    ]))
    return decideAuthorisation({
      subject,
      actor,
      permission,
      resource,
      owningGroup,
      requestTenantId: input.requestTenantId ?? null,
      assignments,
      customRoles,
      grants,
      catalogue,
      policy,
      now: at,
    })
  }

  /** A subject that meets every assurance requirement: qualification ignores the session, which the approver brings later. */
  const fullAssurance = (principalId: string): AuthorisationSubject =>
    ({ principalId, authenticatedAt: now().toISOString(), assurance: { level: 'aal2', phishingResistant: true } })

  async function qualifies(principalId: string, permission: string, resource: AuthorisationResource): Promise<boolean> {
    const decision = await decide({ subject: fullAssurance(principalId), permission, resource })
    return decision.allowed
  }

  async function knownGroup(groupId: string): Promise<AuthorisationGroup> {
    const group = await io('directory', () => directory.describeGroup(groupId, { consistency: 'strong' }))
    if (!group || group.groupId !== groupId || group.lineage.at(-1) !== groupId) throw new AuthorisationFailure('validation-failed', 'unknown group')
    return group
  }

  const event = (type: AuthorisationEvent['type'], fields: Partial<AuthorisationEvent> & { actorPrincipalId: string }): AuthorisationEvent => ({
    type,
    occurredAt: now().toISOString(),
    subjectPrincipalId: null,
    groupId: null,
    resource: null,
    permission: null,
    roleId: null,
    reason: null,
    ...fields,
  })

  return {
    /** The decision, with the facts gathered at `strong` consistency for high and critical permissions. A refusal is announced. */
    async authorise(input: AuthoriseInput): Promise<AuthorisationDecision> {
      const decision = await decide(input)
      if (!decision.allowed) {
        await emit(event('authorisation.denied', {
          actorPrincipalId: input.subject.principalId,
          groupId: input.resource.owningGroupId,
          resource: { type: input.resource.type, id: input.resource.id },
          permission: input.permission,
          reason: decision.reason,
        }))
      }
      return decision
    },

    /**
     * Whether the principal holds the permission on the resource now,
     * whatever their session: for approvals, where the approver steps up when
     * they decide. Read at `strong` consistency.
     */
    async qualifies(input: { principalId: string, permission: string, resource: AuthorisationResource }): Promise<boolean> {
      return qualifies(requireIdentifier(input.principalId, 'principal'), input.permission, input.resource)
    },

    /**
     * How many principals, other than those excluded, hold the permission on
     * the resource now, up to `limit`. Candidates are the holders of role
     * assignments that can reach the resource's group and of grants on the
     * resource to a principal; grants to a group are not counted, since
     * Authorisation cannot list a group's members. Each is checked as
     * `qualifies` would.
     */
    async countQualifying(input: { permission: string, resource: AuthorisationResource, excludingPrincipalIds: readonly string[], limit: number }): Promise<number> {
      const limit = Math.max(0, Math.min(Math.trunc(input.limit), 100))
      if (limit === 0) return 0
      const group = await io('directory', () => directory.describeGroup(input.resource.owningGroupId, { consistency: 'strong' }))
      if (!group) return 0
      const [assignments, grants] = await io('store', () => Promise.all([store.assignmentsIn(group.lineage), store.grantsOn(input.resource)]))
      const candidates = new Set<string>()
      for (const a of assignments) {
        if (a.groupId === group.groupId || a.scope === 'group-and-descendants') candidates.add(a.principalId)
      }
      for (const grant of grants) {
        if (grant.subject.kind === 'principal') candidates.add(grant.subject.principalId)
      }
      for (const excluded of input.excludingPrincipalIds) candidates.delete(excluded)
      let count = 0
      for (const principalId of [...candidates].sort()) {
        if (await qualifies(principalId, input.permission, input.resource)) count += 1
        if (count >= limit) break
      }
      return count
    },

    /** The principal's role assignments, or those made in a group. */
    async listAssignments(input: { principalId?: string, groupId?: string }): Promise<AuthorisationRoleAssignment[]> {
      if (input.principalId) {
        const principalId = requireIdentifier(input.principalId, 'principal')
        const all = await io('store', () => store.assignmentsOf(principalId))
        return input.groupId ? all.filter(a => a.groupId === input.groupId) : all
      }
      if (input.groupId) return io('store', () => store.assignmentsIn([requireIdentifier(input.groupId, 'group')]))
      throw new AuthorisationFailure('validation-failed', 'name a principal or a group')
    },

    /**
     * Gives a principal a role in a group (a built-in role, or a custom role of
     * the group's tenant). Decides nothing: the caller has authorised it.
     */
    async assign(input: { principalId: string, groupId: string, roleId: string, scope?: AuthorisationRoleAssignmentScope, actorPrincipalId: string }): Promise<boolean> {
      const principalId = requireIdentifier(input.principalId, 'principal')
      const actor = requireIdentifier(input.actorPrincipalId, 'actor')
      const scope = input.scope ?? 'group'
      if (!(ROLE_ASSIGNMENT_SCOPES as readonly string[]).includes(scope)) throw new AuthorisationFailure('validation-failed', 'invalid scope')
      const group = await knownGroup(requireIdentifier(input.groupId, 'group'))
      if (!(BUILT_IN_ROLE_IDS as readonly string[]).includes(input.roleId)) {
        const roles = await io('store', () => store.customRoles([group.tenantId]))
        if (!roles.get(group.tenantId)?.has(input.roleId)) throw new AuthorisationFailure('validation-failed', 'unknown role')
      }
      const at = now()
      const changed = await io('store', () => store.assign({ principalId, groupId: group.groupId, roleId: input.roleId, scope }, actor, at))
      if (changed) await emit(event('authorisation.role-assigned', { actorPrincipalId: actor, subjectPrincipalId: principalId, groupId: group.groupId, roleId: input.roleId }))
      return changed
    },

    /** Takes a role (or, with `roleId` null, every role) from a principal in a group. Returns the roles removed. */
    async unassign(input: { principalId: string, groupId: string, roleId: string | null, actorPrincipalId: string }): Promise<string[]> {
      const principalId = requireIdentifier(input.principalId, 'principal')
      const groupId = requireIdentifier(input.groupId, 'group')
      const actor = requireIdentifier(input.actorPrincipalId, 'actor')
      const removed = await io('store', () => store.unassign({ principalId, groupId, roleId: input.roleId }))
      for (const roleId of removed) await emit(event('authorisation.role-unassigned', { actorPrincipalId: actor, subjectPrincipalId: principalId, groupId, roleId }))
      return removed
    },

    /** Defines or changes a tenant's custom role. Built-in IDs are refused, as are exact permissions missing from the catalogue. */
    async defineRole(input: { tenantId: string, role: AuthorisationRoleDefinition, actorPrincipalId: string }): Promise<'defined' | 'changed'> {
      const tenantId = requireIdentifier(input.tenantId, 'tenant')
      const actor = requireIdentifier(input.actorPrincipalId, 'actor')
      const parsed = roleDefinitionSchema.safeParse(input.role)
      if (!parsed.success || (BUILT_IN_ROLE_IDS as readonly string[]).includes(parsed.data.id)) throw new AuthorisationFailure('validation-failed', 'invalid role')
      for (const { pattern } of parsed.data.permissions) {
        if (!pattern.includes('*') && !catalogue.has(pattern)) throw new AuthorisationFailure('validation-failed', 'unknown permission')
      }
      const at = now()
      const outcome = await io('store', () => store.defineRole(tenantId, parsed.data, at))
      await emit(event(outcome === 'defined' ? 'authorisation.role-defined' : 'authorisation.role-changed', { actorPrincipalId: actor, roleId: parsed.data.id }))
      return outcome
    },

    async deleteRole(input: { tenantId: string, roleId: string, actorPrincipalId: string }): Promise<boolean> {
      const deleted = await io('store', () => store.deleteRole(requireIdentifier(input.tenantId, 'tenant'), requireIdentifier(input.roleId, 'role')))
      if (deleted) await emit(event('authorisation.role-deleted', { actorPrincipalId: requireIdentifier(input.actorPrincipalId, 'actor'), roleId: input.roleId }))
      return deleted
    },

    /** Shares a resource: exact, catalogued permissions of the resource's type only. */
    async createGrant(input: { grant: AuthorisationGrant, actorPrincipalId: string }): Promise<string> {
      const { grant } = input
      const actor = requireIdentifier(input.actorPrincipalId, 'actor')
      requireIdentifier(grant.resource?.id, 'resource')
      if (!Array.isArray(grant.permissions) || grant.permissions.length === 0
        || grant.permissions.some(p => !isPermissionName(p) || !catalogue.has(p) || !p.startsWith(`${grant.resource.type}:`))) {
        throw new AuthorisationFailure('validation-failed', 'invalid permissions')
      }
      requireIdentifier(grant.subject?.kind === 'group' ? grant.subject.groupId : grant.subject?.principalId, 'grant subject')
      const at = now()
      if (grant.expiresAt !== null && !(Date.parse(grant.expiresAt) > at.getTime())) throw new AuthorisationFailure('validation-failed', 'expiry in the past')
      const grantId = await io('store', () => store.createGrant(grant, actor, at))
      await emit(event('authorisation.grant-created', {
        actorPrincipalId: actor,
        subjectPrincipalId: grant.subject.kind === 'principal' ? grant.subject.principalId : null,
        groupId: grant.subject.kind === 'group' ? grant.subject.groupId : null,
        resource: { type: grant.resource.type, id: grant.resource.id },
      }))
      return grantId
    },

    /** A principal's part of a data-subject access request: the assignments and grants it holds. */
    async exportPrincipal(input: { principalId: string, correlationId: string }): Promise<AuthorisationDataExport> {
      const principalId = requireIdentifier(input.principalId, 'principal')
      const correlationId = requireIdentifier(input.correlationId, 'correlation')
      const [assignments, grants] = await Promise.all([
        io('store', () => store.assignmentsOf(principalId)),
        io('store', () => store.grantsHeldBy(principalId)),
      ])
      return {
        principalId,
        exportedAt: now().toISOString(),
        correlationId,
        roleAssignments: [...assignments].sort((a, b) => `${a.groupId} ${a.roleId}`.localeCompare(`${b.groupId} ${b.roleId}`)),
        grants: grants.map(({ grantId, resource, permissions, expiresAt }) => ({ grantId, resource, permissions, expiresAt })),
      }
    },

    /**
     * Removes every assignment and grant the principal holds (account
     * closure; erasure). Decides nothing: the caller acts on Identity's
     * `identity.closed`. Idempotent; announced once something was removed.
     */
    async erasePrincipal(input: { principalId: string, actorPrincipalId: string }): Promise<{ assignments: number, grants: number }> {
      const principalId = requireIdentifier(input.principalId, 'principal')
      const actor = requireIdentifier(input.actorPrincipalId, 'actor')
      const removed = await io('store', () => store.erasePrincipal(principalId))
      if (removed.assignments + removed.grants > 0) await emit(event('authorisation.principal-erased', { actorPrincipalId: actor, subjectPrincipalId: principalId }))
      return removed
    },

    async revokeGrant(input: { grantId: string, actorPrincipalId: string }): Promise<boolean> {
      if (typeof input.grantId !== 'string' || !UUID.test(input.grantId)) throw new AuthorisationFailure('validation-failed', 'invalid grant')
      const actor = requireIdentifier(input.actorPrincipalId, 'actor')
      const revoked: StoredGrant | null = await io('store', () => store.revokeGrant(input.grantId))
      if (revoked) {
        await emit(event('authorisation.grant-revoked', {
          actorPrincipalId: actor,
          subjectPrincipalId: revoked.subject.kind === 'principal' ? revoked.subject.principalId : null,
          groupId: revoked.subject.kind === 'group' ? revoked.subject.groupId : null,
          resource: revoked.resource,
        }))
      }
      return revoked !== null
    },

  }
}

export type AuthorisationService = ReturnType<typeof createService>

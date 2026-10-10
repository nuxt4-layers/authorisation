import { randomUUID } from 'node:crypto'
import type {
  AuthorisationDataExport,
  AuthorisationDecision,
  AuthorisationDenialEvent,
  AuthorisationDirectory,
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
import {
  AuthorisationFailure,
  BUILT_IN_ROLE_IDS,
  IDENTIFIER_PATTERN,
  isPermissionName,
  ROLE_ASSIGNMENT_SCOPES,
  roleDefinitionSchema,
  UUID_PATTERN,
} from '../../contracts'
import { timeFrom } from './clock'
import type { Database, Queryable } from './database'
import { decideAuthorisation } from './decide'
import { digestOf } from './digest'
import type { EventInput } from './outbox'
import { enqueue } from './outbox'
import type { StoredGrant } from './store'
import { createStore } from './store'

/**
 * PRIVATE. Authorisation's server operations: gathering the facts for a
 * decision from the directory and the store, and changing roles, role
 * assignments and grants, each in one transaction with its outbox events.
 * Any directory, store or clock failure fails closed
 * (`AuthorisationFailure('unavailable')`).
 */

export interface ServiceDependencies {
  db: Database
  /** The schema's bare name (the store quotes it). */
  schemaName: string
  directory: AuthorisationDirectory
  catalogue: AuthorisationPermissionCatalogue
  policy: AuthorisationPolicy
  /** Best-effort delivery of refused decisions to the host's sink. Never throws. */
  emitDenial: (event: AuthorisationDenialEvent) => Promise<void>
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

export function requireIdentifier(value: unknown, what: string): string {
  if (typeof value !== 'string' || !IDENTIFIER_PATTERN.test(value)) throw new AuthorisationFailure('validation-failed', `invalid-${what}`)
  return value
}

/** A caller's correlation identifier, or a new one. */
export function correlationOrNew(value: unknown): string {
  if (value === undefined || value === null) return randomUUID()
  if (typeof value !== 'string' || !UUID_PATTERN.test(value)) throw new AuthorisationFailure('validation-failed', 'invalid-correlation')
  return value
}

export const isBuiltInRole = (roleId: string) => (BUILT_IN_ROLE_IDS as readonly string[]).includes(roleId)

/** Runs `run`, turning any failure that is not already a contract failure into `unavailable`. */
export async function io<T>(what: string, run: () => Promise<T>): Promise<T> {
  try {
    return await run()
  }
  catch (error) {
    if (error instanceof AuthorisationFailure) throw error
    throw new AuthorisationFailure('unavailable', `${what} failed`)
  }
}

const grantEventData = (grant: StoredGrant, changeId: string | null) => ({
  grantId: grant.grantId,
  resourceType: grant.resource.type,
  resourceId: grant.resource.id,
  owningGroupId: grant.resource.owningGroupId ?? null,
  holder: grant.subject.kind === 'group' ? { kind: 'group' as const, groupId: grant.subject.groupId } : { kind: 'principal' as const, principalId: grant.subject.principalId },
  permissions: [...grant.permissions],
  expiresAt: grant.expiresAt,
  changeId,
})

const assignmentEventData = (a: AuthorisationRoleAssignment, changeId: string | null) =>
  ({ principalId: a.principalId, groupId: a.groupId, roleId: a.roleId, scope: a.scope, expiresAt: a.expiresAt, changeId })

/** The writes a change makes, inside a transaction, with its events. Used by the server functions and by applied changes. */
export function createWriter(client: Queryable, schemaName: string, quotedSchema: string, context: { actorPrincipalId: string | null, correlationId: string, at: Date, changeId: string | null }) {
  const store = createStore(client, schemaName)
  const emit = (input: EventInput) => enqueue(client, quotedSchema, input, context)
  return {
    store,
    emit,
    async assign(assignment: AuthorisationRoleAssignment): Promise<boolean> {
      const changed = await store.assign(assignment, context.actorPrincipalId, context.at)
      if (changed) await emit({ type: 'authorisation.role-assigned', data: assignmentEventData(assignment, context.changeId) })
      return changed
    },
    async unassign(input: { principalId: string, groupId: string, roleId: string | null }): Promise<AuthorisationRoleAssignment[]> {
      const removed = await store.unassign(input)
      for (const assignment of removed) await emit({ type: 'authorisation.role-unassigned', data: assignmentEventData(assignment, context.changeId) })
      return removed
    },
    async expire(assignment: AuthorisationRoleAssignment): Promise<void> {
      await emit({ type: 'authorisation.role-expired', data: assignmentEventData(assignment, null) })
    },
    async defineRole(tenantId: string, role: AuthorisationRoleDefinition): Promise<'defined' | 'changed' | null> {
      const outcome = await store.defineRole(tenantId, role, context.at)
      if (outcome) await emit({ type: outcome === 'defined' ? 'authorisation.role-defined' : 'authorisation.role-changed', data: { tenantId, roleId: role.id, digest: digestOf(role), changeId: context.changeId } })
      return outcome
    },
    async deleteRole(tenantId: string, roleId: string): Promise<boolean> {
      const deleted = await store.deleteRole(tenantId, roleId)
      if (deleted) await emit({ type: 'authorisation.role-deleted', data: { tenantId, roleId, digest: null, changeId: context.changeId } })
      return deleted
    },
    async createGrant(grant: AuthorisationGrant): Promise<string> {
      const grantId = await store.createGrant(grant, context.actorPrincipalId, context.at)
      await emit({ type: 'authorisation.grant-created', data: grantEventData({ ...grant, grantId }, context.changeId) })
      return grantId
    },
    async revokeGrant(grantId: string): Promise<StoredGrant | null> {
      const revoked = await store.revokeGrant(grantId)
      if (revoked) await emit({ type: 'authorisation.grant-revoked', data: grantEventData(revoked, context.changeId) })
      return revoked
    },
  }
}

export function createService({ db, schemaName, directory, catalogue, policy, emitDenial, now: clockNow = () => new Date() }: ServiceDependencies) {
  /** The clock's time; an invalid answer fails closed as `unavailable`, so no decision is made on another time. */
  const clock = { now: clockNow }
  const now = (): Date => timeFrom(clock)
  const store = createStore(db, schemaName)

  /** High and critical permissions read the directory from the source of truth. */
  const consistencyFor = (permission: string) => {
    const risk = catalogue.get(permission)?.risk
    return { consistency: risk === 'high' || risk === 'critical' || risk === undefined ? 'strong' as const : 'bounded' as const }
  }

  async function decide(input: AuthoriseInput, options: { strong?: boolean } = {}): Promise<AuthorisationDecision> {
    const { subject, permission, resource } = input
    // The time of the decision, read first: a clock that fails refuses before anything is read.
    const at = now()
    const read = options.strong ? { consistency: 'strong' as const } : consistencyFor(permission)
    const [actor, owningGroup] = await io('directory', () => Promise.all([
      directory.resolveActor(subject.principalId, read),
      directory.describeGroup(resource.owningGroupId, read),
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
    const decision = await decide({ subject: fullAssurance(principalId), permission, resource }, { strong: true })
    return decision.allowed
  }

  async function knownGroup(groupId: string): Promise<AuthorisationGroup> {
    const group = await io('directory', () => directory.describeGroup(groupId, { consistency: 'strong' }))
    if (!group || group.groupId !== groupId || group.lineage.at(-1) !== groupId) throw new AuthorisationFailure('validation-failed', 'unknown-group')
    return group
  }

  /** Runs writes in one transaction with their outbox events. */
  function write<T>(context: { actorPrincipalId: string | null, correlationId: string, at: Date, changeId?: string | null }, run: (writer: ReturnType<typeof createWriter>) => Promise<T>): Promise<T> {
    return io('store', () => db.transaction(client => run(createWriter(client, schemaName, db.schema, { ...context, changeId: context.changeId ?? null }))))
  }

  function validRole(role: unknown): AuthorisationRoleDefinition {
    const parsed = roleDefinitionSchema.safeParse(role)
    if (!parsed.success) throw new AuthorisationFailure('validation-failed', 'invalid-role')
    if (isBuiltInRole(parsed.data.id)) throw new AuthorisationFailure('validation-failed', 'built-in-role')
    for (const { pattern } of parsed.data.permissions) {
      if (!pattern.includes('*') && !catalogue.has(pattern)) throw new AuthorisationFailure('validation-failed', 'unknown-permission')
    }
    return parsed.data
  }

  /** Validates a grant: exact, catalogued permissions of the resource's type, a known holder, an expiry in the future. */
  function validGrant(grant: AuthorisationGrant, at: Date): AuthorisationGrant {
    requireIdentifier(grant?.resource?.id, 'resource')
    if (typeof grant.resource.type !== 'string') throw new AuthorisationFailure('validation-failed', 'invalid-resource')
    if (grant.resource.owningGroupId != null) requireIdentifier(grant.resource.owningGroupId, 'group')
    if (!Array.isArray(grant.permissions) || grant.permissions.length === 0 || grant.permissions.length > 100
      || grant.permissions.some(p => !isPermissionName(p) || !catalogue.has(p) || !p.startsWith(`${grant.resource.type}:`))) {
      throw new AuthorisationFailure('validation-failed', 'unknown-permission')
    }
    requireIdentifier(grant.subject?.kind === 'group' ? grant.subject.groupId : grant.subject?.principalId, 'holder')
    if (grant.expiresAt !== null && !(Date.parse(grant.expiresAt) > at.getTime())) throw new AuthorisationFailure('validation-failed', 'expiry-in-the-past')
    return {
      resource: { type: grant.resource.type, id: grant.resource.id, owningGroupId: grant.resource.owningGroupId ?? null },
      subject: grant.subject.kind === 'group' ? { kind: 'group', groupId: grant.subject.groupId } : { kind: 'principal', principalId: grant.subject.principalId },
      permissions: [...new Set(grant.permissions)].sort(),
      expiresAt: grant.expiresAt === null ? null : new Date(grant.expiresAt).toISOString(),
    }
  }

  return {
    decide,
    qualifiesNow: qualifies,
    validRole,
    validGrant,
    store,

    /** The decision, with the facts gathered at `strong` consistency for high and critical permissions. A refusal is announced to the sink. */
    async authorise(input: AuthoriseInput): Promise<AuthorisationDecision> {
      const decision = await decide(input)
      if (!decision.allowed) {
        await emitDenial({
          type: 'authorisation.denied',
          occurredAt: now().toISOString(),
          actorPrincipalId: input.subject.principalId,
          groupId: input.resource.owningGroupId,
          resource: { type: input.resource.type, id: input.resource.id },
          permission: input.permission,
          reason: decision.reason,
        })
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
     * the group's tenant), optionally until `expiresAt`. Decides nothing: the
     * caller has authorised it.
     */
    async assign(input: { principalId: string, groupId: string, roleId: string, scope?: AuthorisationRoleAssignmentScope, expiresAt?: string | null, actorPrincipalId: string, correlationId?: string }): Promise<boolean> {
      const principalId = requireIdentifier(input.principalId, 'principal')
      const actor = requireIdentifier(input.actorPrincipalId, 'actor')
      const correlationId = correlationOrNew(input.correlationId)
      const scope = input.scope ?? 'group'
      if (!(ROLE_ASSIGNMENT_SCOPES as readonly string[]).includes(scope)) throw new AuthorisationFailure('validation-failed', 'invalid-scope')
      const at = now()
      const expiresAt = input.expiresAt == null ? null : new Date(input.expiresAt)
      if (expiresAt !== null && !(expiresAt.getTime() > at.getTime())) throw new AuthorisationFailure('validation-failed', 'expiry-in-the-past')
      const group = await knownGroup(requireIdentifier(input.groupId, 'group'))
      if (!isBuiltInRole(input.roleId)) {
        const roles = await io('store', () => store.customRoles([group.tenantId]))
        if (!roles.get(group.tenantId)?.has(input.roleId)) throw new AuthorisationFailure('validation-failed', 'unknown-role')
      }
      return write({ actorPrincipalId: actor, correlationId, at }, writer =>
        writer.assign({ principalId, groupId: group.groupId, roleId: input.roleId, scope, expiresAt: expiresAt?.toISOString() ?? null }))
    },

    /** Takes a role (or, with `roleId` null, every role) from a principal in a group. Returns the roles removed. */
    async unassign(input: { principalId: string, groupId: string, roleId: string | null, actorPrincipalId: string, correlationId?: string }): Promise<string[]> {
      const principalId = requireIdentifier(input.principalId, 'principal')
      const groupId = requireIdentifier(input.groupId, 'group')
      const actor = requireIdentifier(input.actorPrincipalId, 'actor')
      const correlationId = correlationOrNew(input.correlationId)
      const at = now()
      const removed = await write({ actorPrincipalId: actor, correlationId, at }, writer => writer.unassign({ principalId, groupId, roleId: input.roleId }))
      return removed.map(a => a.roleId)
    },

    /** Defines or changes a tenant's custom role. Built-in IDs are refused, as are exact permissions missing from the catalogue. */
    async defineRole(input: { tenantId: string, role: AuthorisationRoleDefinition, actorPrincipalId: string, correlationId?: string }): Promise<'defined' | 'changed'> {
      const tenantId = requireIdentifier(input.tenantId, 'tenant')
      const actor = requireIdentifier(input.actorPrincipalId, 'actor')
      const correlationId = correlationOrNew(input.correlationId)
      const role = validRole(input.role)
      const at = now()
      const outcome = await write({ actorPrincipalId: actor, correlationId, at }, writer => writer.defineRole(tenantId, role))
      return outcome ?? 'changed'
    },

    async deleteRole(input: { tenantId: string, roleId: string, actorPrincipalId: string, correlationId?: string }): Promise<boolean> {
      const tenantId = requireIdentifier(input.tenantId, 'tenant')
      const roleId = requireIdentifier(input.roleId, 'role')
      const actor = requireIdentifier(input.actorPrincipalId, 'actor')
      const correlationId = correlationOrNew(input.correlationId)
      const at = now()
      return write({ actorPrincipalId: actor, correlationId, at }, writer => writer.deleteRole(tenantId, roleId))
    },

    /** Shares a resource: exact, catalogued permissions of the resource's type only. */
    async createGrant(input: { grant: AuthorisationGrant, actorPrincipalId: string, correlationId?: string }): Promise<string> {
      const actor = requireIdentifier(input.actorPrincipalId, 'actor')
      const correlationId = correlationOrNew(input.correlationId)
      const at = now()
      const grant = validGrant(input.grant, at)
      return write({ actorPrincipalId: actor, correlationId, at }, writer => writer.createGrant(grant))
    },

    async revokeGrant(input: { grantId: string, actorPrincipalId: string, correlationId?: string }): Promise<boolean> {
      if (typeof input.grantId !== 'string' || !UUID_PATTERN.test(input.grantId)) throw new AuthorisationFailure('validation-failed', 'invalid-grant')
      const actor = requireIdentifier(input.actorPrincipalId, 'actor')
      const correlationId = correlationOrNew(input.correlationId)
      const at = now()
      return (await write({ actorPrincipalId: actor, correlationId, at }, writer => writer.revokeGrant(input.grantId))) !== null
    },

    /** A principal's part of a data-subject access request: the assignments and grants it holds, and the changes it is part of. */
    async exportPrincipal(input: { principalId: string, correlationId: string }): Promise<AuthorisationDataExport> {
      const principalId = requireIdentifier(input.principalId, 'principal')
      const correlationId = requireIdentifier(input.correlationId, 'correlation')
      const exportedAt = now().toISOString()
      const [assignments, grants, changes] = await Promise.all([
        io('store', () => store.assignmentsOf(principalId)),
        io('store', () => store.grantsHeldBy(principalId)),
        io('store', () => store.changesInvolving(principalId)),
      ])
      return {
        principalId,
        exportedAt,
        correlationId,
        roleAssignments: [...assignments].sort((a, b) => `${a.groupId} ${a.roleId}`.localeCompare(`${b.groupId} ${b.roleId}`)),
        grants: grants.map(({ grantId, resource, permissions, expiresAt }) => ({ grantId, resource: { type: resource.type, id: resource.id }, permissions, expiresAt })),
        changes: changes.map(change => ({
          changeId: change.changeId,
          type: change.type,
          involvement: change.requesterId === principalId ? 'requester' as const : change.beneficiaryId === principalId ? 'beneficiary' as const : 'approver' as const,
          state: change.state,
          createdAt: change.createdAt,
        })),
      }
    },

    /**
     * Removes every assignment and grant the principal holds (account
     * closure; erasure), and rejects the open changes it requested or would
     * benefit from. Decides nothing: the caller acts on Identity's
     * `identity.closed`. Idempotent; announced once something was removed.
     */
    async erasePrincipal(input: { principalId: string, actorPrincipalId: string, correlationId?: string }): Promise<{ assignments: number, grants: number }> {
      const principalId = requireIdentifier(input.principalId, 'principal')
      const actor = requireIdentifier(input.actorPrincipalId, 'actor')
      const correlationId = correlationOrNew(input.correlationId)
      const at = now()
      return write({ actorPrincipalId: actor, correlationId, at }, async (writer) => {
        const removed = await writer.store.erasePrincipal(principalId)
        for (const change of await writer.store.openChangesInvolving(principalId)) {
          await writer.store.updateChange(change.changeId, { state: 'rejected', decidedAt: at.toISOString(), failure: 'principal-erased' })
          await writer.emit({ type: 'authorisation.change-decided', data: { changeId: change.changeId, changeType: change.type, tenantId: change.tenantId, groupId: change.groupId, requesterId: change.requesterId, beneficiaryId: change.beneficiaryId, risk: change.risk, route: change.route, state: 'rejected' } })
        }
        if (removed.assignments + removed.grants > 0) await writer.emit({ type: 'authorisation.principal-erased', data: { principalId, ...removed } })
        return removed
      })
    },
  }
}

export type AuthorisationService = ReturnType<typeof createService>

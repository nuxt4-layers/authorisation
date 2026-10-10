import { randomUUID } from 'node:crypto'
import { z } from 'zod'
import type {
  AuthorisationApprovalRecord,
  AuthorisationAssuranceRecord,
  AuthorisationChangeRequest,
  AuthorisationChangeTarget,
  AuthorisationDirectory,
  AuthorisationGovernance,
  AuthorisationGovernedGroup,
  AuthorisationGroup,
  AuthorisationPendingChange,
  AuthorisationPermissionCatalogue,
  AuthorisationPolicy,
  AuthorisationResource,
  AuthorisationRiskLevel,
  AuthorisationRoleDefinition,
  AuthorisationSubject,
} from '../../contracts'
import {
  AUTHORISATION_CHANGES,
  AUTHORISATION_RISK_LEVELS,
  AuthorisationFailure,
  OPEN_CHANGE_STATES,
  STEP_UP_REQUIREMENTS,
  approvalRequirement,
  assignmentRisk,
  changeRequestSchema,
  chooseRoute,
  correlationIdSchema,
  higherRisk,
  identifierSchema,
  instantSchema,
  isSelfGrant,
  meetsStepUp,
  refuseApproval,
  roleRisk,
  sha256DigestSchema,
  uuidSchema,
} from '../../contracts'
import type { Database, Queryable } from './database'
import { digestOf } from './digest'
import { enqueue } from './outbox'
import type { AuthorisationService } from './service'
import { createWriter, io, isBuiltInRole } from './service'
import type { StoredChange } from './store'
import { createStore } from './store'

/**
 * PRIVATE. The approvals engine for access administration (docs/contracts.md
 * §15; iam-integration `docs/processes/access-administration.md` and
 * `approvals.md`).
 *
 * A change is requested, authorised through Authorisation's own decision at
 * `strong` consistency, checked against the rules with Identity's facts from
 * the governance port (no self-grant, owners follow Identity, the target
 * still holds, justification, step-up), routed (approvers in the group, an
 * owner of the parent group, an owner of the tenant's root group, or a
 * published delay) and recorded with its digest. With no approver needed it
 * applies at once; otherwise when enough qualifying approvers agree, or when
 * its published delay ends; it expires if nobody decides in time. A change
 * within the requester's recovery hold, or to riskier default roles, waits
 * as `delayed` until the hold ends. Every rule is checked again when a
 * change applies, in the same transaction as the decision and its outbox
 * events.
 *
 * Errors stay coarse: an unknown change, group, role or grant, or a caller
 * who may not see it, is `forbidden`; a rule is reported (`conflict`, with
 * its code) only to a caller entitled to see the change.
 */

export interface ChangesDependencies {
  db: Database
  schemaName: string
  service: AuthorisationService
  directory: AuthorisationDirectory
  catalogue: AuthorisationPermissionCatalogue
  policy: AuthorisationPolicy
  /** Required for every change; read at use, so a missing port fails closed. */
  governance: () => AuthorisationGovernance
  /** The validated clock time. */
  now: () => Date
}

const subjectSchema = z.object({
  principalId: identifierSchema,
  authenticatedAt: instantSchema,
  assurance: z.object({ level: z.enum(['aal1', 'aal2']), phishingResistant: z.boolean() }),
})

const governedGroupSchema = z.object({
  groupId: identifierSchema,
  tenantId: identifierSchema,
  kind: z.enum(['standard', 'personal']),
  state: z.enum(['active', 'orphaned', 'archived']),
  parentGroupId: identifierSchema.nullable(),
  rootGroupId: identifierSchema,
  personalOfPrincipalId: identifierSchema.nullable(),
  approvals: z.object({
    required: z.object({ low: z.union([z.literal(0), z.literal(1)]), medium: z.union([z.literal(0), z.literal(1)]), high: z.union([z.literal(1), z.literal(2)]), critical: z.union([z.literal(1), z.literal(2)]) }),
    referenceRequired: z.boolean(),
  }),
  safetyPeriods: z.object({
    publishedDelayHighHours: z.number().int().min(1),
    publishedDelayCriticalHours: z.number().int().min(1),
    approvalExpiryDays: z.number().int().min(1),
    recoveryHoldHours: z.number().int().min(1),
  }),
  requester: z.object({ recoveryHoldUntil: instantSchema.nullable(), controls: z.array(identifierSchema).max(1000) }),
})

function parse<T>(run: () => T): T {
  try {
    return run()
  }
  catch {
    throw new AuthorisationFailure('validation-failed')
  }
}

const conflict = (reason: string) => new AuthorisationFailure('conflict', reason)
const hours = (at: Date, n: number) => new Date(at.getTime() + n * 3_600_000).toISOString()
const later = (a: string | null, b: string | null) => (a === null ? b : b === null ? a : Date.parse(a) >= Date.parse(b) ? a : b)

/** The resource an administration permission is decided on: the group itself. */
export const groupResource = (permission: string, groupId: string): AuthorisationResource =>
  ({ type: permission.slice(0, permission.indexOf(':')), id: groupId, owningGroupId: groupId })

/** What the digest covers: the change as recorded. */
function digestInput(change: Pick<StoredChange, 'type' | 'tenantId' | 'groupId' | 'requesterId' | 'beneficiaryId' | 'risk' | 'justification' | 'target' | 'requiredApprovals' | 'route' | 'basis'>) {
  return {
    type: change.type,
    tenantId: change.tenantId,
    groupId: change.groupId,
    requesterId: change.requesterId,
    beneficiaryId: change.beneficiaryId,
    risk: change.risk,
    justification: change.justification,
    target: change.target,
    requiredApprovals: change.requiredApprovals,
    route: change.route,
    basis: change.basis,
  }
}

/** A pending change as callers see it: without the server's basis and failure code. */
export function publicChange(change: StoredChange): AuthorisationPendingChange {
  const { basis: _basis, failure: _failure, ...rest } = change
  return rest
}

interface Located {
  group: AuthorisationGroup
  beneficiaryId: string | null
  /** The target as recorded (normalised). */
  target: AuthorisationChangeTarget
}

export function createChanges(deps: ChangesDependencies) {
  const { db, schemaName, service, directory, catalogue, policy, now } = deps
  const store = createStore(db, schemaName)

  async function governed(groupId: string, principalId: string, correlationId: string): Promise<AuthorisationGovernedGroup | null> {
    const governance = deps.governance()
    const answer = await io('governance', () => governance.describeGroup({ groupId, principalId, correlationId }))
    if (answer === null) return null
    const parsed = governedGroupSchema.safeParse(answer)
    if (!parsed.success || parsed.data.groupId !== groupId) throw new AuthorisationFailure('unavailable', 'governance answered malformed facts')
    return parsed.data
  }

  const isOwner = (principalId: string, groupId: string) => io('governance', () => deps.governance().isOwner({ principalId, groupId }))
  const countOwners = (groupId: string, excluding: readonly string[]) => io('governance', () => deps.governance().countOwners({ groupId, excluding }))

  async function describe(groupId: string): Promise<AuthorisationGroup | null> {
    const group = await io('directory', () => directory.describeGroup(groupId, { consistency: 'strong' }))
    if (!group || group.groupId !== groupId || group.lineage.at(-1) !== groupId || !group.tenantId) return null
    return group
  }

  /** A role of the tenant: built-in from the policy, or the tenant's own. */
  async function findRole(q: Queryable, tenantId: string, roleId: string): Promise<AuthorisationRoleDefinition | null> {
    if (isBuiltInRole(roleId)) return { id: roleId, name: roleId, permissions: [...policy.roles[roleId as keyof typeof policy.roles]] }
    const roles = await createStore(q, schemaName).customRoles([tenantId])
    return roles.get(tenantId)?.get(roleId) ?? null
  }

  const riskOfRole = (role: AuthorisationRoleDefinition | null): AuthorisationRiskLevel => (role ? roleRisk(role.permissions, catalogue) : 'low')

  /** Whether the role is assigned in a group of the tenant, or is a default role of one. */
  async function roleInUse(q: Queryable, tenantId: string, roleId: string): Promise<boolean> {
    const s = createStore(q, schemaName)
    if ((await s.groupsDefaulting(tenantId, roleId)).length > 0) return true
    for (const groupId of await s.groupsAssigning(roleId)) {
      const group = await describe(groupId)
      if (group?.tenantId === tenantId) return true
    }
    return false
  }

  /** Whether the principal holds a membership in effect (active or paused) in the group, or it is their personal group. */
  async function memberOf(principalId: string, groupId: string): Promise<boolean> {
    const actor = await io('directory', () => directory.resolveActor(principalId, { consistency: 'strong' }))
    if (!actor || actor.principalId !== principalId || (actor.status !== 'active' && actor.status !== 'paused')) return false
    if (actor.personalGroup?.groupId === groupId) return true
    return actor.memberships.some(m => m.group.groupId === groupId && (m.status === 'active' || m.status === 'paused'))
  }

  /** Whether a grant's holder lies beyond the tenant: a group in another tenant, or a principal with no membership in it. Null when unknown. */
  async function beyondTenant(holder: { kind: 'principal', principalId: string } | { kind: 'group', groupId: string }, tenantId: string): Promise<boolean | null> {
    if (holder.kind === 'group') {
      const group = await describe(holder.groupId)
      return group ? group.tenantId !== tenantId : null
    }
    const actor = await io('directory', () => directory.resolveActor(holder.principalId, { consistency: 'strong' }))
    if (!actor || actor.principalId !== holder.principalId) return null
    return !actor.memberships.some(m => m.group.tenantId === tenantId && (m.status === 'active' || m.status === 'paused'))
  }

  /**
   * The change's risk and the rules that must hold for its target now
   * (docs/contracts.md §15). Throws `conflict` with the rule's code when one
   * does not; reads within `q` (a transaction when applying).
   */
  async function assess(q: Queryable, change: { type: AuthorisationChangeRequest['type'], target: AuthorisationChangeTarget, tenantId: string, groupId: string }, at: Date): Promise<{ risk: AuthorisationRiskLevel, riskier?: boolean }> {
    const s = createStore(q, schemaName)
    switch (change.type) {
      case 'role.assign': {
        const target = change.target as AuthorisationChangeTarget<'role.assign'>
        if (target.roleId === 'owner') throw conflict('owner-role')
        if (target.expiresAt && !(Date.parse(target.expiresAt) > at.getTime())) throw conflict('expiry-in-the-past')
        const role = await findRole(q, change.tenantId, target.roleId)
        if (!role) throw conflict('unknown-role')
        if (!(await memberOf(target.principalId, target.groupId))) throw conflict('not-a-member')
        return { risk: assignmentRisk(riskOfRole(role), target.scope ?? 'group') }
      }
      case 'role.unassign': {
        const target = change.target as AuthorisationChangeTarget<'role.unassign'>
        if (target.roleId === 'owner') throw conflict('owner-role')
        if (!(await s.assignment(target))) throw conflict('not-assigned')
        return { risk: 'medium' }
      }
      case 'assignment.confirm': {
        const target = change.target as AuthorisationChangeTarget<'assignment.confirm'>
        if (!(await s.assignment(target))) throw conflict('not-assigned')
        return { risk: 'low' }
      }
      case 'grant.create': {
        const { grant } = change.target as AuthorisationChangeTarget<'grant.create'>
        try {
          service.validGrant(grant, at)
        }
        catch (error) {
          throw conflict(error instanceof AuthorisationFailure && error.reason ? error.reason : 'unknown-permission')
        }
        const beyond = await beyondTenant(grant.subject, change.tenantId)
        if (beyond === null) throw conflict('unknown-holder')
        let risk: AuthorisationRiskLevel = 'high'
        for (const name of grant.permissions) risk = higherRisk(risk, catalogue.get(name)!.risk)
        return { risk: beyond ? 'critical' : risk }
      }
      case 'grant.revoke': {
        const { grantId } = change.target as AuthorisationChangeTarget<'grant.revoke'>
        const grant = await s.grant(grantId)
        if (!grant || grant.resource.owningGroupId !== change.groupId) throw conflict('grant-gone')
        return { risk: 'medium' }
      }
      case 'role.define': {
        const { role } = change.target as AuthorisationChangeTarget<'role.define'>
        let valid: AuthorisationRoleDefinition
        try {
          valid = service.validRole(role)
        }
        catch (error) {
          throw conflict(error instanceof AuthorisationFailure && error.reason ? error.reason : 'unknown-permission')
        }
        const risk = riskOfRole(valid)
        if (risk === 'high' || risk === 'critical') {
          const defaulting = await s.groupsDefaulting(change.tenantId, valid.id)
          if (defaulting.some(entry => entry.as.includes('guest'))) throw conflict('guest-role-too-risky')
        }
        return { risk: 'critical' }
      }
      case 'role.delete': {
        const { roleId } = change.target as AuthorisationChangeTarget<'role.delete'>
        if (isBuiltInRole(roleId)) throw conflict('built-in-role')
        if (!(await findRole(q, change.tenantId, roleId))) throw conflict('unknown-role')
        if (await roleInUse(q, change.tenantId, roleId)) throw conflict('role-in-use')
        return { risk: 'critical' }
      }
      case 'group.change-default-roles': {
        const { defaultRoles } = change.target as AuthorisationChangeTarget<'group.change-default-roles'>
        let risk: AuthorisationRiskLevel = 'high'
        for (const [kind, roleId] of Object.entries(defaultRoles) as ['member' | 'guest', string | null][]) {
          if (roleId === null) continue
          if (roleId === 'owner') throw conflict('owner-role')
          const role = await findRole(q, change.tenantId, roleId)
          if (!role) throw conflict('unknown-role')
          const roleRiskLevel = riskOfRole(role)
          if (kind === 'guest' && (roleRiskLevel === 'high' || roleRiskLevel === 'critical')) throw conflict('guest-role-too-risky')
          risk = higherRisk(risk, roleRiskLevel)
        }
        // Riskier than the roles new members receive now: held, so the group's owners can see it coming.
        const current = await s.groupAccess(change.groupId, change.tenantId)
        let currentRisk: AuthorisationRiskLevel = 'low'
        for (const roleId of [current.defaultRoles.member, current.defaultRoles.guest]) {
          if (roleId) currentRisk = higherRisk(currentRisk, riskOfRole(await findRole(q, change.tenantId, roleId)))
        }
        let newRisk: AuthorisationRiskLevel = 'low'
        for (const roleId of [defaultRoles.member, defaultRoles.guest]) {
          if (roleId) newRisk = higherRisk(newRisk, riskOfRole(await findRole(q, change.tenantId, roleId)))
        }
        return { risk, riskier: AUTHORISATION_RISK_LEVELS.indexOf(newRisk) > AUTHORISATION_RISK_LEVELS.indexOf(currentRisk) }
      }
      case 'group.change-review-interval':
        return { risk: 'high' }
    }
  }

  /** Finds the group a change is governed by, and its beneficiary. Anything unknown is `forbidden`. */
  async function locate(request: AuthorisationChangeRequest, subject: AuthorisationSubject): Promise<Located> {
    const known = async (groupId: string) => {
      const group = await describe(groupId)
      if (!group) throw new AuthorisationFailure('forbidden')
      return group
    }
    switch (request.type) {
      case 'role.assign': {
        const target = { ...request.target, scope: request.target.scope ?? 'group', expiresAt: request.target.expiresAt ? new Date(request.target.expiresAt).toISOString() : null }
        return { group: await known(target.groupId), beneficiaryId: target.principalId, target }
      }
      case 'role.unassign':
      case 'assignment.confirm':
        return { group: await known(request.target.groupId), beneficiaryId: request.target.principalId, target: request.target }
      case 'grant.create': {
        const { grant } = request.target
        const normalised = {
          grant: {
            resource: grant.resource,
            subject: grant.subject,
            permissions: [...new Set(grant.permissions)].sort(),
            expiresAt: grant.expiresAt === null ? null : new Date(grant.expiresAt).toISOString(),
          },
        }
        return { group: await known(grant.resource.owningGroupId), beneficiaryId: grant.subject.kind === 'principal' ? grant.subject.principalId : null, target: normalised }
      }
      case 'grant.revoke': {
        const grant = await io('store', () => store.grant(request.target.grantId))
        if (!grant?.resource.owningGroupId) throw new AuthorisationFailure('forbidden')
        return { group: await known(grant.resource.owningGroupId), beneficiaryId: grant.subject.kind === 'principal' ? grant.subject.principalId : null, target: request.target }
      }
      case 'group.change-default-roles':
      case 'group.change-review-interval':
        return { group: await known(request.target.groupId), beneficiaryId: null, target: request.target }
      case 'role.define':
      case 'role.delete': {
        // The tenant's root group: the root of a group of the tenant the requester belongs to, on which they hold the permission.
        const { tenantId } = request.target
        const actor = await io('directory', () => directory.resolveActor(subject.principalId, { consistency: 'strong' }))
        const roots = new Set<string>()
        for (const m of actor?.principalId === subject.principalId ? actor.memberships : []) {
          if (m.group.tenantId === tenantId && m.status === 'active' && m.group.lineage[0]) roots.add(m.group.lineage[0])
        }
        let stepUp = false
        for (const rootId of [...roots].sort()) {
          const decision = await service.decide({ subject, permission: AUTHORISATION_CHANGES[request.type].permission, resource: groupResource(AUTHORISATION_CHANGES[request.type].permission, rootId) }, { strong: true })
          if (decision.allowed) return { group: await known(rootId), beneficiaryId: null, target: request.target }
          if (decision.reason === 'insufficient-assurance') stepUp = true
        }
        throw new AuthorisationFailure(stepUp ? 'insufficient-assurance' : 'forbidden')
      }
    }
  }

  async function authoriseOn(subject: AuthorisationSubject, permission: string, groupId: string): Promise<void> {
    const decision = await service.decide({ subject, permission, resource: groupResource(permission, groupId) }, { strong: true })
    if (decision.allowed) return
    throw new AuthorisationFailure(decision.reason === 'insufficient-assurance' ? 'insufficient-assurance' : 'forbidden')
  }

  /** Whether the principal may decide the change now, by its route. Strong reads. */
  async function qualifiesFor(change: StoredChange, approverId: string): Promise<boolean> {
    const permission = AUTHORISATION_CHANGES[change.type].permission
    switch (change.route) {
      case 'approvers':
        return service.qualifiesNow(approverId, permission, groupResource(permission, change.groupId))
      case 'parent-owner':
      case 'tenant-owner': {
        const owners = change.route === 'parent-owner' ? change.basis.parentGroupId : change.basis.rootGroupId
        return typeof owners === 'string' && owners !== change.groupId ? isOwner(approverId, owners) : false
      }
      default:
        return false
    }
  }

  async function load(changeId: string): Promise<StoredChange | null> {
    return io('store', () => store.change(changeId))
  }

  const decidedData = (change: StoredChange, state: 'applied' | 'rejected' | 'expired' | 'cancelled') => ({
    changeId: change.changeId,
    changeType: change.type,
    tenantId: change.tenantId,
    groupId: change.groupId,
    requesterId: change.requesterId,
    beneficiaryId: change.beneficiaryId,
    risk: change.risk,
    route: change.route,
    state,
  })

  /**
   * Applies a change whose requirement is met, inside `client`'s
   * transaction, checking every rule again (docs/contracts.md §15). A rule
   * that no longer holds rejects the change; a port or database failure
   * rolls the whole transaction back (nothing is recorded, fail closed).
   * A change still held waits as `delayed` until its hold ends.
   */
  async function settle(client: Queryable, change: StoredChange, at: Date, deciderId: string | null): Promise<StoredChange> {
    const s = createStore(client, schemaName)
    if (change.heldUntil !== null && Date.parse(change.heldUntil) > at.getTime()) {
      return s.updateChange(change.changeId, { state: 'delayed', delayEndsAt: later(change.delayEndsAt, change.heldUntil) })
    }
    await client.query('savepoint authorisation_apply')
    let failure: string | null = null
    try {
      await apply(client, change, at)
    }
    catch (error) {
      if (!(error instanceof AuthorisationFailure) || error.code !== 'conflict') throw error
      failure = error.reason ?? 'rejected'
      await client.query('rollback to savepoint authorisation_apply')
    }
    await client.query('release savepoint authorisation_apply')
    const state = failure ? 'rejected' : 'applied'
    const settled = await s.updateChange(change.changeId, { state, decidedAt: at.toISOString(), failure })
    await enqueue(client, db.schema, { type: 'authorisation.change-decided', data: decidedData(settled, state) }, { actorPrincipalId: deciderId, correlationId: change.correlationId, at })
    return settled
  }

  async function apply(client: Queryable, change: StoredChange, at: Date): Promise<void> {
    if (digestOf(digestInput(change)) !== change.changeDigest) throw conflict('change-differs')
    const group = await describe(change.groupId)
    if (!group || group.tenantId !== change.tenantId) throw conflict('group-not-active')
    const facts = await governed(change.groupId, change.requesterId, change.correlationId)
    if (!facts || facts.state !== 'active' || facts.tenantId !== change.tenantId) throw conflict('group-not-active')
    const basis = change.basis as { approvals?: unknown }
    if (digestOf(facts.approvals) !== digestOf(basis.approvals)) throw conflict('requirement-changed')
    const inPersonal = facts.kind === 'personal' && facts.personalOfPrincipalId === change.requesterId
    if (isSelfGrant({ type: change.type, requesterId: change.requesterId, beneficiaryId: change.beneficiaryId, inRequestersPersonalGroup: inPersonal })) throw conflict('self-grant')
    const permission = AUTHORISATION_CHANGES[change.type].permission
    if (!(await service.qualifiesNow(change.requesterId, permission, groupResource(permission, change.groupId)))) throw conflict('requester-not-qualified')
    const { risk } = await assess(client, { type: change.type, target: change.target, tenantId: change.tenantId, groupId: change.groupId }, at)
    if (AUTHORISATION_RISK_LEVELS.indexOf(risk) > AUTHORISATION_RISK_LEVELS.indexOf(change.risk)) throw conflict('risk-changed')

    // The change's effects are the requester's; the decision is the approver's.
    const writer = createWriter(client, schemaName, db.schema, { actorPrincipalId: change.requesterId, correlationId: change.correlationId, at, changeId: change.changeId })
    switch (change.type) {
      case 'role.assign': {
        const target = change.target as AuthorisationChangeTarget<'role.assign'>
        await writer.assign({ principalId: target.principalId, groupId: target.groupId, roleId: target.roleId, scope: target.scope ?? 'group', expiresAt: target.expiresAt ?? null })
        return
      }
      case 'role.unassign': {
        const target = change.target as AuthorisationChangeTarget<'role.unassign'>
        if ((await writer.unassign(target)).length === 0) throw conflict('not-assigned')
        return
      }
      case 'assignment.confirm': {
        const target = change.target as AuthorisationChangeTarget<'assignment.confirm'>
        if (!(await writer.store.confirm(target, change.requesterId, at))) throw conflict('not-assigned')
        await writer.emit({ type: 'authorisation.assignment-confirmed', data: { ...target, confirmedAt: at.toISOString(), changeId: change.changeId } })
        return
      }
      case 'grant.create': {
        const { grant } = change.target as AuthorisationChangeTarget<'grant.create'>
        await writer.createGrant(service.validGrant(grant, at))
        return
      }
      case 'grant.revoke': {
        const { grantId } = change.target as AuthorisationChangeTarget<'grant.revoke'>
        if (!(await writer.revokeGrant(grantId))) throw conflict('grant-gone')
        return
      }
      case 'role.define': {
        const { tenantId, role } = change.target as AuthorisationChangeTarget<'role.define'>
        await writer.store.lockTenantRoles(tenantId)
        await writer.defineRole(tenantId, service.validRole(role))
        return
      }
      case 'role.delete': {
        const { tenantId, roleId } = change.target as AuthorisationChangeTarget<'role.delete'>
        await writer.store.lockTenantRoles(tenantId)
        if (!(await writer.deleteRole(tenantId, roleId))) throw conflict('unknown-role')
        return
      }
      case 'group.change-default-roles': {
        const { groupId, defaultRoles } = change.target as AuthorisationChangeTarget<'group.change-default-roles'>
        await writer.store.setDefaultRoles(groupId, change.tenantId, defaultRoles, change.requesterId, at)
        await writer.emit({ type: 'authorisation.group-access-changed', data: { groupId, tenantId: change.tenantId, changed: ['default-roles'], changeId: change.changeId } })
        return
      }
      case 'group.change-review-interval': {
        const { groupId, intervalDays } = change.target as AuthorisationChangeTarget<'group.change-review-interval'>
        await writer.store.setReviewInterval(groupId, change.tenantId, intervalDays, change.requesterId, at)
        await writer.emit({ type: 'authorisation.group-access-changed', data: { groupId, tenantId: change.tenantId, changed: ['review-interval'], changeId: change.changeId } })
      }
    }
  }

  async function expire(client: Queryable, change: StoredChange, at: Date): Promise<StoredChange> {
    const expired = await createStore(client, schemaName).updateChange(change.changeId, { state: 'expired', decidedAt: at.toISOString() })
    await enqueue(client, db.schema, { type: 'authorisation.change-decided', data: decidedData(expired, 'expired') }, { actorPrincipalId: null, correlationId: change.correlationId, at })
    return expired
  }

  return {
    /**
     * Requests a change. Returns it as recorded: `applied` when no approver
     * is needed (or `rejected` should a rule fail as it applies),
     * `awaiting-approval`, or `delayed` (a published delay, or a hold).
     */
    async request(input: { subject: AuthorisationSubject, request: unknown, correlationId: string }): Promise<AuthorisationPendingChange> {
      const subject = parse(() => subjectSchema.parse(input.subject)) as AuthorisationSubject
      const correlationId = parse(() => correlationIdSchema.parse(input.correlationId))
      const request = parse(() => changeRequestSchema.parse(input.request)) as AuthorisationChangeRequest
      const located = await locate(request, subject)
      const { group } = located
      const permission = AUTHORISATION_CHANGES[request.type].permission
      await authoriseOn(subject, permission, group.groupId)

      const facts = await governed(group.groupId, subject.principalId, correlationId)
      if (!facts || facts.tenantId !== group.tenantId) throw new AuthorisationFailure('forbidden')
      if (facts.state !== 'active') throw conflict('group-not-active')
      const inPersonal = facts.kind === 'personal' && facts.personalOfPrincipalId === subject.principalId
      if (isSelfGrant({ type: request.type, requesterId: subject.principalId, beneficiaryId: located.beneficiaryId, inRequestersPersonalGroup: inPersonal })) throw conflict('self-grant')

      const at = now()
      const { risk, riskier } = await io('store', () => assess(db, { type: request.type, target: located.target, tenantId: group.tenantId, groupId: group.groupId }, at))
      if (facts.approvals.referenceRequired && !request.justification.reference && !inPersonal) throw new AuthorisationFailure('validation-failed', 'reference-missing')
      const assurance: AuthorisationAssuranceRecord = { level: subject.assurance.level, phishingResistant: subject.assurance.phishingResistant, authenticatedAt: subject.authenticatedAt }
      if (!meetsStepUp(assurance, STEP_UP_REQUIREMENTS[risk], at)) throw new AuthorisationFailure('insufficient-assurance')

      // The route: qualifying approvers in the group, excluding the requester, the beneficiary and whoever the requester controls; then the owners above; else a published delay.
      const requirement = approvalRequirement({ risk, inRequestersPersonalGroup: inPersonal, groupRequirement: facts.approvals.required })
      const excluding = [...new Set([subject.principalId, ...(located.beneficiaryId ? [located.beneficiaryId] : []), ...facts.requester.controls])]
      let route = chooseRoute({ approvers: requirement.approvers, qualifyingInGroup: Number.MAX_SAFE_INTEGER, parentOwners: 0, tenantOwners: 0 })
      if (requirement.approvers > 0) {
        const qualifying = await service.countQualifying({ permission, resource: groupResource(permission, group.groupId), excludingPrincipalIds: excluding, limit: requirement.approvers })
        const parent = facts.parentGroupId
        const root = facts.rootGroupId !== group.groupId && facts.rootGroupId !== parent ? facts.rootGroupId : null
        const parentOwners = parent ? await countOwners(parent, excluding) : 0
        const tenantOwners = root ? await countOwners(root, excluding) : 0
        route = chooseRoute({ approvers: requirement.approvers, qualifyingInGroup: qualifying, parentOwners, tenantOwners })
      }

      const periods = facts.safetyPeriods
      const delayed = route === 'published-delay'
      let heldUntil: string | null = null
      if (facts.requester.recoveryHoldUntil && Date.parse(facts.requester.recoveryHoldUntil) > at.getTime()) heldUntil = new Date(facts.requester.recoveryHoldUntil).toISOString()
      if (riskier) heldUntil = later(heldUntil, hours(at, periods.recoveryHoldHours))
      const changeId = randomUUID()
      const record = {
        changeId,
        type: request.type,
        tenantId: group.tenantId,
        groupId: group.groupId,
        requesterId: subject.principalId,
        beneficiaryId: located.beneficiaryId,
        risk,
        justification: request.justification,
        target: located.target,
        requiredApprovals: route === 'parent-owner' || route === 'tenant-owner' ? 1 : requirement.approvers,
        route,
        basis: { approvals: facts.approvals, parentGroupId: facts.parentGroupId, rootGroupId: facts.rootGroupId },
      }
      const changeDigest = digestOf(digestInput(record))
      const delayEndsAt = delayed ? later(hours(at, risk === 'critical' ? periods.publishedDelayCriticalHours : periods.publishedDelayHighHours), heldUntil) : null
      const expiresAt = route === 'approvers' || route === 'parent-owner' || route === 'tenant-owner' ? hours(at, periods.approvalExpiryDays * 24) : null

      const recorded = await io('store', () => db.transaction(async (client) => {
        const s = createStore(client, schemaName)
        let change = await s.insertChange({
          ...record,
          changeDigest,
          delayEndsAt,
          expiresAt,
          heldUntil,
          state: delayed ? 'delayed' : 'awaiting-approval',
          correlationId,
          createdAt: at.toISOString(),
        })
        if (route === 'none') change = await settle(client, change, at, subject.principalId)
        const context = { actorPrincipalId: subject.principalId, correlationId, at }
        await enqueue(client, db.schema, {
          type: 'authorisation.change-requested',
          data: { ...decidedData(change, 'applied'), state: change.state as 'awaiting-approval' | 'delayed' | 'applied' | 'rejected', requiredApprovals: change.requiredApprovals, delayEndsAt: change.delayEndsAt, expiresAt: change.expiresAt },
        }, context)
        if (heldUntil && (change.state === 'awaiting-approval' || change.state === 'delayed')) {
          await enqueue(client, db.schema, { type: 'authorisation.change-held', data: { ...decidedData(change, 'applied'), state: change.state, heldUntil } }, context)
        }
        return change
      }))
      return publicChange(recorded)
    },

    /**
     * An approver approves or rejects a change, quoting the digest of the
     * change they were shown. Returns the change as it now stands.
     */
    async decide(input: { subject: AuthorisationSubject, changeId: string, changeDigest: string, decision: 'approve' | 'reject', correlationId: string }): Promise<AuthorisationPendingChange> {
      const subject = parse(() => subjectSchema.parse(input.subject)) as AuthorisationSubject
      parse(() => correlationIdSchema.parse(input.correlationId))
      const changeId = parse(() => uuidSchema.parse(input.changeId))
      const digest = parse(() => sha256DigestSchema.parse(input.changeDigest))
      if (input.decision !== 'approve' && input.decision !== 'reject') throw new AuthorisationFailure('validation-failed')
      const change = await load(changeId)
      if (!change) throw new AuthorisationFailure('forbidden')
      const involved = change.requesterId === subject.principalId || change.beneficiaryId === subject.principalId
      const qualifies = !involved && await qualifiesFor(change, subject.principalId)
      if (!involved && !qualifies) throw new AuthorisationFailure('forbidden')
      const at = now()
      if (change.state === 'awaiting-approval' && change.expiresAt && Date.parse(change.expiresAt) <= at.getTime()) {
        return publicChange(await io('store', () => db.transaction(async (client) => {
          const locked = await createStore(client, schemaName).change(changeId, true)
          return locked?.state === 'awaiting-approval' ? expire(client, locked, at) : locked!
        })))
      }
      const facts = await governed(change.groupId, change.requesterId, input.correlationId)
      const assurance: AuthorisationAssuranceRecord = { level: subject.assurance.level, phishingResistant: subject.assurance.phishingResistant, authenticatedAt: subject.authenticatedAt }
      const refusal = refuseApproval({ change, approverId: subject.principalId, qualifies, controls: facts?.requester.controls ?? [], assurance, changeDigest: digest, now: at })
      if (refusal === 'insufficient-assurance') throw new AuthorisationFailure('insufficient-assurance')
      if (refusal) throw conflict(refusal)
      if (digestOf(digestInput(change)) !== change.changeDigest) throw conflict('change-differs')

      const decided = await io('store', () => db.transaction(async (client) => {
        const s = createStore(client, schemaName)
        const locked = await s.change(changeId, true)
        if (!locked || locked.version !== change.version || locked.state !== 'awaiting-approval') throw conflict('not-pending')
        const approval: AuthorisationApprovalRecord = { approverId: subject.principalId, decision: input.decision, decidedAt: at.toISOString(), assurance, changeDigest: digest }
        const approvals = [...locked.approvals, approval]
        if (input.decision === 'reject') {
          const rejected = await s.updateChange(changeId, { state: 'rejected', approvals, decidedAt: at.toISOString() })
          await enqueue(client, db.schema, { type: 'authorisation.change-decided', data: decidedData(rejected, 'rejected') }, { actorPrincipalId: subject.principalId, correlationId: locked.correlationId, at })
          return rejected
        }
        const approved = await s.updateChange(changeId, { approvals })
        if (approvals.filter(a => a.decision === 'approve').length < locked.requiredApprovals) return approved
        return settle(client, approved, at, subject.principalId)
      }))
      return publicChange(decided)
    },

    /** The requester withdraws a change that has not yet taken effect. */
    async cancel(input: { subject: AuthorisationSubject, changeId: string, correlationId: string }): Promise<AuthorisationPendingChange> {
      const subject = parse(() => subjectSchema.parse(input.subject)) as AuthorisationSubject
      parse(() => correlationIdSchema.parse(input.correlationId))
      const changeId = parse(() => uuidSchema.parse(input.changeId))
      const change = await load(changeId)
      if (!change || change.requesterId !== subject.principalId) throw new AuthorisationFailure('forbidden')
      const at = now()
      const cancelled = await io('store', () => db.transaction(async (client) => {
        const s = createStore(client, schemaName)
        const locked = await s.change(changeId, true)
        if (!locked || !OPEN_CHANGE_STATES.includes(locked.state)) throw conflict('not-pending')
        const done = await s.updateChange(changeId, { state: 'cancelled', decidedAt: at.toISOString() })
        await enqueue(client, db.schema, { type: 'authorisation.change-decided', data: decidedData(done, 'cancelled') }, { actorPrincipalId: subject.principalId, correlationId: locked.correlationId, at })
        return done
      }))
      return publicChange(cancelled)
    },

    /** A change, for its requester, its beneficiary, whoever may decide it, or whoever may see the group's roles. Anyone else: `forbidden`. */
    async get(input: { subject: AuthorisationSubject, changeId: string }): Promise<AuthorisationPendingChange> {
      const subject = parse(() => subjectSchema.parse(input.subject)) as AuthorisationSubject
      const changeId = parse(() => uuidSchema.parse(input.changeId))
      const change = await load(changeId)
      if (!change) throw new AuthorisationFailure('forbidden')
      if (change.requesterId === subject.principalId || change.beneficiaryId === subject.principalId) return publicChange(change)
      if (await qualifiesFor(change, subject.principalId)) return publicChange(change)
      const view = await service.decide({ subject, permission: 'authorisation.roles:view', resource: groupResource('authorisation.roles:view', change.groupId) }, { strong: true })
      if (view.allowed) return publicChange(change)
      throw new AuthorisationFailure('forbidden')
    },

    /** A group's changes that have not yet taken effect (`authorisation.roles:view`). */
    async listForGroup(input: { subject: AuthorisationSubject, groupId: string }): Promise<AuthorisationPendingChange[]> {
      const subject = parse(() => subjectSchema.parse(input.subject)) as AuthorisationSubject
      const groupId = parse(() => identifierSchema.parse(input.groupId))
      await authoriseOn(subject, 'authorisation.roles:view', groupId)
      return (await io('store', () => store.openChangesIn(groupId))).map(publicChange)
    },

    /** Maintenance: expires changes nobody decided in time; applies delayed changes whose delay or hold has ended. */
    async sweep(limit: number): Promise<{ expiredChanges: number, appliedChanges: number, rejectedChanges: number, failedChanges: number }> {
      const at = now()
      const expiredChanges = await io('store', () => db.transaction(async (client) => {
        const due = await createStore(client, schemaName).expiredAwaiting(at, limit)
        for (const change of due) await expire(client, change, at)
        return due.length
      }))
      let appliedChanges = 0
      let rejectedChanges = 0
      let failedChanges = 0
      for (const changeId of await io('store', () => store.dueDelayed(at, limit))) {
        try {
          const settled = await db.transaction(async (client) => {
            const locked = await createStore(client, schemaName).change(changeId, true)
            if (!locked || locked.state !== 'delayed' || !locked.delayEndsAt || Date.parse(locked.delayEndsAt) > at.getTime()) return null
            return settle(client, locked, at, null)
          })
          if (settled?.state === 'applied') appliedChanges += 1
          if (settled?.state === 'rejected') rejectedChanges += 1
        }
        catch (error) {
          // A port or database failure leaves the change delayed, for the next run.
          console.error(`[authorisation] applying delayed change ${changeId} failed:`, error instanceof Error ? error.message : error)
          failedChanges += 1
        }
      }
      return { expiredChanges, appliedChanges, rejectedChanges, failedChanges }
    },

    /** Exposed for the queries and maintenance. */
    findRole,
    riskOfRole,
    roleInUse,
    authoriseOn,
  }
}

export type AuthorisationChanges = ReturnType<typeof createChanges>

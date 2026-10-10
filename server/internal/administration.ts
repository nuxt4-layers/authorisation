import { randomUUID } from 'node:crypto'
import { z } from 'zod'
import type {
  AuthorisationAccessReview,
  AuthorisationAssignmentView,
  AuthorisationDefaultRoles,
  AuthorisationDirectory,
  AuthorisationGrantView,
  AuthorisationGroupAccess,
  AuthorisationLegalHolds,
  AuthorisationPolicy,
  AuthorisationRoleDefinition,
  AuthorisationRoleDocument,
  AuthorisationRoleView,
  AuthorisationSelfView,
  AuthorisationSubject,
  AuthorisationTenantExport,
  AuthorisationTenantRoles,
} from '../../contracts'
import {
  AUTHORISATION_ROLE_DOCUMENT_FORMAT,
  AUTHORISATION_ROLE_DOCUMENT_VERSION,
  AuthorisationFailure,
  BUILT_IN_ROLE_IDS,
  correlationIdSchema,
  identifierSchema,
  instantSchema,
  roleDocumentSchema,
} from '../../contracts'
import type { AuthorisationChanges } from './changes'
import type { Database } from './database'
import { digestOf } from './digest'
import { enqueue } from './outbox'
import type { AuthorisationService } from './service'
import { createWriter, io } from './service'
import { createStore } from './store'

/**
 * PRIVATE. What the administration endpoints and pages read, each guarded by
 * the layer's own permissions (docs/contracts.md §16); a group's default
 * roles for the host's Identity event handler; maintenance; and the
 * operator's role documents (§18). Errors stay coarse: a refusal is
 * `forbidden`, whether or not the group exists.
 */

export interface AdministrationDependencies {
  db: Database
  schemaName: string
  service: AuthorisationService
  changes: AuthorisationChanges
  directory: AuthorisationDirectory
  now: () => Date
  /** For the retention periods. Defaults to the secure defaults. */
  policy?: AuthorisationPolicy
  /** The host's legal-hold port, or null: without it, retention keeps every change a hold might cover. */
  legalHolds?: () => AuthorisationLegalHolds | null
}

const subjectSchema = z.object({
  principalId: identifierSchema,
  authenticatedAt: instantSchema,
  assurance: z.object({ level: z.enum(['aal1', 'aal2']), phishingResistant: z.boolean() }),
})

function parse<T>(run: () => T): T {
  try {
    return run()
  }
  catch {
    throw new AuthorisationFailure('validation-failed')
  }
}

const DAY = 86_400_000

export function createAdministration({ db, schemaName, service, changes, directory, now, policy, legalHolds = () => null }: AdministrationDependencies) {
  const store = createStore(db, schemaName)
  const subjectOf = (value: unknown) => parse(() => subjectSchema.parse(value)) as AuthorisationSubject
  const groupOf = (value: unknown) => parse(() => identifierSchema.parse(value))
  const live = (at: Date) => (a: AuthorisationAssignmentView) => a.expiresAt === null || Date.parse(a.expiresAt) > at.getTime()

  async function knownGroup(groupId: string) {
    const group = await io('directory', () => directory.describeGroup(groupId, { consistency: 'strong' }))
    if (!group || group.groupId !== groupId || group.lineage.at(-1) !== groupId || !group.tenantId) throw new AuthorisationFailure('forbidden')
    return group
  }

  function roleView(role: AuthorisationRoleDefinition, builtIn: boolean): AuthorisationRoleView {
    return { id: role.id, name: role.name, description: role.description ?? null, builtIn, risk: changes.riskOfRole(role), permissions: role.permissions }
  }

  /**
   * Retention (iam-integration retention): delivered events and decided
   * changes past their period. A change is deleted only when the host's
   * legal-hold port says no hold covers its group; without the port, or when
   * it fails, the change is kept for the next run. Announced only when
   * something was deleted, with counts.
   */
  async function applyRetention(at: Date, correlationId: string, limit: number): Promise<{ outboxEvents: number, changes: number }> {
    const periods = policy?.retention ?? { outboxDays: 30, changeDays: 730 }
    const holds = legalHolds()
    const candidates = holds ? await io('store', () => store.decidedBefore(new Date(at.getTime() - periods.changeDays * DAY), limit)) : []
    const free: string[] = []
    for (const candidate of candidates) {
      try {
        if (!(await holds!.covers({ kind: 'group', id: candidate.groupId }))) free.push(candidate.changeId)
      }
      catch {
        // Unknown: keep it.
      }
    }
    return io('store', () => db.transaction(async (client) => {
      const s = createStore(client, schemaName)
      const outboxEvents = await s.deleteDeliveredEvents(new Date(at.getTime() - periods.outboxDays * DAY))
      const changes = await s.deleteChanges(free)
      if (outboxEvents + changes > 0) {
        await enqueue(client, db.schema, { type: 'authorisation.retention-applied', data: { outboxEvents, changes } }, { actorPrincipalId: null, correlationId, at })
      }
      return { outboxEvents, changes }
    }))
  }

  async function documentFor(tenantId: string): Promise<AuthorisationRoleDocument> {
    const roles = [...((await io('store', () => store.customRoles([tenantId]))).get(tenantId)?.values() ?? [])].sort((a, b) => (a.id < b.id ? -1 : 1))
    const body = { format: AUTHORISATION_ROLE_DOCUMENT_FORMAT, formatVersion: AUTHORISATION_ROLE_DOCUMENT_VERSION, tenantId, roles }
    return { ...body, digest: digestOf(body) } as AuthorisationRoleDocument
  }

  return {
    /** A group's live assignments, with provenance (`authorisation.roles:view`). */
    async assignments(input: { subject: AuthorisationSubject, groupId: string }): Promise<AuthorisationAssignmentView[]> {
      const subject = subjectOf(input.subject)
      const groupId = groupOf(input.groupId)
      await changes.authoriseOn(subject, 'authorisation.roles:view', groupId)
      const at = now()
      return (await io('store', () => store.assignmentViews({ groupId }))).filter(live(at))
    },

    /**
     * A group's access review (`authorisation.role-assignments:manage`): every
     * live assignment, when and by whom it was made, its end date, when it
     * was last confirmed, and whether it is overdue.
     */
    async accessReview(input: { subject: AuthorisationSubject, groupId: string }): Promise<AuthorisationAccessReview> {
      const subject = subjectOf(input.subject)
      const groupId = groupOf(input.groupId)
      await changes.authoriseOn(subject, 'authorisation.role-assignments:manage', groupId)
      const group = await knownGroup(groupId)
      const at = now()
      const [access, assignments] = await io('store', () => Promise.all([store.groupAccess(groupId, group.tenantId), store.assignmentViews({ groupId })]))
      const interval = access.reviewIntervalDays
      return {
        groupId,
        reviewIntervalDays: interval,
        entries: assignments.filter(live(at)).map((assignment) => {
          const lastConfirmedAt = assignment.confirmedAt ?? assignment.assignedAt
          const reviewDueAt = interval === null ? null : new Date(Date.parse(lastConfirmedAt) + interval * DAY).toISOString()
          return { ...assignment, lastConfirmedAt, reviewDueAt, overdue: reviewDueAt !== null && Date.parse(reviewDueAt) <= at.getTime() }
        }),
      }
    },

    /** A group's default roles and review interval (`authorisation.roles:view`). */
    async groupAccess(input: { subject: AuthorisationSubject, groupId: string }): Promise<AuthorisationGroupAccess> {
      const subject = subjectOf(input.subject)
      const groupId = groupOf(input.groupId)
      await changes.authoriseOn(subject, 'authorisation.roles:view', groupId)
      const group = await knownGroup(groupId)
      const access = await io('store', () => store.groupAccess(groupId, group.tenantId))
      return { groupId, tenantId: group.tenantId, defaultRoles: access.defaultRoles, reviewIntervalDays: access.reviewIntervalDays }
    },

    /** Grants on what the group owned when it shared it (`authorisation.grants:manage` on the group). */
    async grants(input: { subject: AuthorisationSubject, groupId: string }): Promise<AuthorisationGrantView[]> {
      const subject = subjectOf(input.subject)
      const groupId = groupOf(input.groupId)
      await changes.authoriseOn(subject, 'authorisation.grants:manage', groupId)
      return io('store', () => store.grantViewsOwnedBy(groupId))
    },

    /**
     * The roles a tenant's groups may assign, built-in and custom, with their
     * risk: for whoever holds `authorisation.roles:view` in a group of the
     * tenant they belong to.
     */
    async tenantRoles(input: { subject: AuthorisationSubject, tenantId: string }): Promise<AuthorisationTenantRoles> {
      const subject = subjectOf(input.subject)
      const tenantId = groupOf(input.tenantId)
      const actor = await io('directory', () => directory.resolveActor(subject.principalId, { consistency: 'strong' }))
      const groups = new Set<string>()
      for (const m of actor?.principalId === subject.principalId ? actor.memberships : []) {
        if (m.group.tenantId === tenantId && (m.status === 'active' || m.status === 'paused')) groups.add(m.group.groupId)
      }
      if (actor?.personalGroup?.tenantId === tenantId) groups.add(actor.personalGroup.groupId)
      let allowed = false
      for (const groupId of [...groups].sort()) {
        const decision = await service.decide({ subject, permission: 'authorisation.roles:view', resource: { type: 'authorisation.roles', id: groupId, owningGroupId: groupId } }, { strong: true })
        if (decision.allowed) {
          allowed = true
          break
        }
      }
      if (!allowed) throw new AuthorisationFailure('forbidden')
      const custom = (await io('store', () => store.customRoles([tenantId]))).get(tenantId) ?? new Map()
      const builtIn = await Promise.all(BUILT_IN_ROLE_IDS.map(async id => roleView((await changes.findRole(db, tenantId, id))!, true)))
      return { tenantId, roles: [...builtIn, ...[...custom.values()].sort((a, b) => (a.id < b.id ? -1 : 1)).map(role => roleView(role, false))] }
    },

    /** The signed-in principal's own live assignments: hints only. */
    async self(input: { subject: AuthorisationSubject }): Promise<AuthorisationSelfView> {
      const subject = subjectOf(input.subject)
      const at = now()
      return { principalId: subject.principalId, assignments: (await io('store', () => store.assignmentViews({ principalId: subject.principalId }))).filter(live(at)) }
    },

    /**
     * The roles a new member and a new guest of the group receive, for the
     * host's Identity event handler (`membership.added`). `member` and
     * `viewer` unless the group set others. A role that no longer exists,
     * `owner`, or a guest role that now holds a high or critical permission
     * is answered as none: fail closed.
     */
    async defaultRoles(groupId: string): Promise<AuthorisationDefaultRoles> {
      const group = await knownGroup(groupOf(groupId)).catch((error) => {
        throw error instanceof AuthorisationFailure && error.code === 'forbidden' ? new AuthorisationFailure('validation-failed', 'unknown-group') : error
      })
      const access = await io('store', () => store.groupAccess(group.groupId, group.tenantId))
      const usable = async (roleId: string | null, guest: boolean) => {
        if (!roleId || roleId === 'owner') return null
        const role = await io('store', () => changes.findRole(db, group.tenantId, roleId))
        if (!role) return null
        const risk = changes.riskOfRole(role)
        return guest && (risk === 'high' || risk === 'critical') ? null : roleId
      }
      return { member: await usable(access.defaultRoles.member, false), guest: await usable(access.defaultRoles.guest, true) }
    },

    /**
     * Maintenance: removes assignments past their end (`role-expired`),
     * expires changes nobody decided in time, applies delayed changes whose
     * delay or hold has ended, and announces assignments overdue for review
     * once (`review-overdue`).
     */
    async maintenance(input: { limit?: number } = {}) {
      const limit = input.limit ?? 500
      if (!Number.isInteger(limit) || limit < 1 || limit > 5000) throw new AuthorisationFailure('validation-failed', 'limit-out-of-range')
      const at = now()
      const correlationId = randomUUID()
      const removed = await io('store', () => db.transaction(async (client) => {
        const writer = createWriter(client, schemaName, db.schema, { actorPrincipalId: null, correlationId, at, changeId: null })
        const expired = await writer.store.removeExpired(at, limit)
        for (const assignment of expired) await writer.expire(assignment)
        return expired.length
      }))
      const swept = await changes.sweep(limit)
      const overdue = await io('store', () => db.transaction(async (client) => {
        const s = createStore(client, schemaName)
        const due = await s.overdueUnannounced(at, limit)
        for (const entry of due) {
          await enqueue(client, db.schema, { type: 'authorisation.review-overdue', data: { principalId: entry.principalId, groupId: entry.groupId, roleId: entry.roleId, lastConfirmedAt: entry.lastConfirmedAt, reviewDueAt: entry.reviewDueAt } }, { actorPrincipalId: null, correlationId, at })
          await s.markOverdueAnnounced(entry, at)
        }
        return due.length
      }))
      const retention = await applyRetention(at, correlationId, limit)
      return { expiredAssignments: removed, ...swept, overdueReviews: overdue, retention }
    },

    /**
     * Authorisation's part of a deleted group (iam-integration group
     * deletion), on Identity's `group.deleted` or `group.disposal-due` when
     * disposal is due: its assignments, the grants on what it owned and to it,
     * its access settings and its changes. Decides nothing: the host's event
     * handler calls it only when no hold defers it. Idempotent; announced as
     * `authorisation.group-disposed` every time, which Identity counts once.
     */
    async disposeGroup(input: { groupId: string, correlationId: string }): Promise<{ assignments: number, grants: number, changes: number }> {
      const groupId = groupOf(input.groupId)
      const correlationId = parse(() => correlationIdSchema.parse(input.correlationId))
      const at = now()
      return io('store', () => db.transaction(async (client) => {
        const removed = await createStore(client, schemaName).disposeGroup(groupId)
        await enqueue(client, db.schema, { type: 'authorisation.group-disposed', data: { groupId, ...removed } }, { actorPrincipalId: null, correlationId, at })
        return removed
      }))
    },

    /** Authorisation's part of a closed tenant: its custom roles. As `disposeGroup`, on `tenant.closed` or `tenant.disposal-due`. */
    async disposeTenant(input: { tenantId: string, correlationId: string }): Promise<{ roles: number, changes: number }> {
      const tenantId = groupOf(input.tenantId)
      const correlationId = parse(() => correlationIdSchema.parse(input.correlationId))
      const at = now()
      return io('store', () => db.transaction(async (client) => {
        const removed = await createStore(client, schemaName).disposeTenant(tenantId)
        await enqueue(client, db.schema, { type: 'authorisation.tenant-disposed', data: { tenantId, ...removed } }, { actorPrincipalId: null, correlationId, at })
        return removed
      }))
    },

    /**
     * Authorisation's part of a closing tenant's governance export, for the
     * groups Identity's part names. Server-only: iam-integration's adapter
     * asks for it only once Identity has authorised the requester.
     */
    async exportTenant(input: { tenantId: string, groupIds: readonly string[], correlationId: string }): Promise<AuthorisationTenantExport> {
      const tenantId = groupOf(input.tenantId)
      parse(() => correlationIdSchema.parse(input.correlationId))
      if (!Array.isArray(input.groupIds) || input.groupIds.length > 100_000) throw new AuthorisationFailure('validation-failed')
      const groupIds = [...new Set(input.groupIds.map(groupOf))].sort()
      const exportedAt = now().toISOString()
      const roles = await documentFor(tenantId)
      const assignments: AuthorisationAssignmentView[] = []
      const grants: AuthorisationGrantView[] = []
      const groupAccess: AuthorisationGroupAccess[] = []
      for (const groupId of groupIds) {
        assignments.push(...await io('store', () => store.assignmentViews({ groupId })))
        grants.push(...await io('store', () => store.grantViewsOwnedBy(groupId)))
        const { version: _version, ...access } = await io('store', () => store.groupAccess(groupId, tenantId))
        groupAccess.push(access)
      }
      return { tenantId, exportedAt, roles, assignments, grants, groupAccess }
    },

    /** The tenant's custom roles as a versioned document. Server-only. */
    async exportRoles(input: { tenantId: string }): Promise<AuthorisationRoleDocument> {
      now()
      return documentFor(groupOf(input.tenantId))
    },

    /**
     * Applies a role document after the operator's own review. Refuses a
     * digest that does not match, a built-in identifier, an exact permission
     * missing from the catalogue, deleting a role still assigned (or a
     * group's default role), and a guest default role that would hold a high
     * or critical permission. Server-only; `authorisation.roles-imported`.
     */
    async importRoles(input: { tenantId: string, document: unknown, correlationId: string }): Promise<{ defined: string[], changed: string[], deleted: string[] }> {
      const tenantId = groupOf(input.tenantId)
      const correlationId = parse(() => correlationIdSchema.parse(input.correlationId))
      const parsed = roleDocumentSchema.safeParse(input.document)
      if (!parsed.success) throw new AuthorisationFailure('validation-failed', 'invalid-document')
      const document = parsed.data
      if (document.tenantId !== tenantId) throw new AuthorisationFailure('validation-failed', 'tenant-mismatch')
      const { digest, ...body } = document
      if (digestOf(body) !== digest) throw new AuthorisationFailure('validation-failed', 'digest-mismatch')
      const roles = document.roles.map(role => service.validRole(role))
      const at = now()
      return io('store', () => db.transaction(async (client) => {
        const writer = createWriter(client, schemaName, db.schema, { actorPrincipalId: null, correlationId, at, changeId: null })
        await writer.store.lockTenantRoles(tenantId)
        const current = (await writer.store.customRoles([tenantId])).get(tenantId) ?? new Map<string, AuthorisationRoleDefinition>()
        const incoming = new Set(roles.map(role => role.id))
        const deleted = [...current.keys()].filter(id => !incoming.has(id)).sort()
        for (const roleId of deleted) {
          if (await changes.roleInUse(client, tenantId, roleId)) throw new AuthorisationFailure('conflict', 'role-in-use')
        }
        const defined: string[] = []
        const changed: string[] = []
        for (const role of roles) {
          const risk = changes.riskOfRole(role)
          if ((risk === 'high' || risk === 'critical') && (await writer.store.groupsDefaulting(tenantId, role.id)).some(entry => entry.as.includes('guest'))) {
            throw new AuthorisationFailure('conflict', 'guest-role-too-risky')
          }
          const outcome = await writer.store.defineRole(tenantId, role, at)
          if (outcome === 'defined') defined.push(role.id)
          if (outcome === 'changed') changed.push(role.id)
        }
        for (const roleId of deleted) await writer.store.deleteRole(tenantId, roleId)
        await writer.emit({ type: 'authorisation.roles-imported', data: { tenantId, digest, defined, changed, deleted } })
        return { defined, changed, deleted }
      }))
    },
  }
}

export type AuthorisationAdministration = ReturnType<typeof createAdministration>

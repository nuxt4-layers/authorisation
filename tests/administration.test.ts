import pg from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import type {
  AuthorisationDirectory,
  AuthorisationEvent,
  AuthorisationGovernance,
  AuthorisationGroup,
  AuthorisationMembershipStatus,
  AuthorisationPermissionDefinition,
  AuthorisationRequiredApprovers,
  AuthorisationSubject,
} from '../contracts'
import { AUTHORISATION_PERMISSIONS } from '../contracts'
import {
  clearAuthorisationComposition,
  provideAuthorisationClock,
  provideAuthorisationDatabase,
  provideAuthorisationDirectory,
  provideAuthorisationGovernance,
  provideAuthorisationLegalHolds,
  provideAuthorisationPermissions,
} from '../server/utils/authorisation-composition'
import {
  assignAuthorisationRole,
  authorisationDefaultRoles,
  createAuthorisationGrant,
  defineAuthorisationRole,
  disposeAuthorisationGroup,
  disposeAuthorisationTenant,
  exportAuthorisationTenantData,
  authorise,
  eraseAuthorisationPrincipal,
  exportAuthorisationRoles,
  getAuthorisationAdministration,
  getAuthorisationChanges,
  importAuthorisationRoles,
  listAuthorisationAccessReview,
  migrateAuthorisationDatabase,
  relayAuthorisationOutbox,
  runAuthorisationMaintenance,
  unassignAuthorisationRole,
} from '../server/utils/authorisation-server'
import { createTestDatabase, hasDatabase, requireDatabaseInCi } from './support/database'

requireDatabaseInCi()

const PERMISSIONS: AuthorisationPermissionDefinition[] = [
  ...AUTHORISATION_PERMISSIONS,
  { name: 'orders:view', description: 'See orders', risk: 'low', effect: 'view' },
  { name: 'orders:create', description: 'Place orders', risk: 'medium', effect: 'change' },
  { name: 'orders:process_refund', description: 'Refund an order', risk: 'high', effect: 'change' },
  { name: 'orders:purge', description: 'Purge an order', risk: 'critical', effect: 'change' },
]

const CORRELATION = '01a00000-0000-7000-8000-0000000000c1'
const START = Date.parse('2030-01-01T00:00:00.000Z')
const DEFAULT_REQUIRED: AuthorisationRequiredApprovers = { low: 0, medium: 0, high: 1, critical: 1 }
const PERIODS = { publishedDelayHighHours: 72, publishedDelayCriticalHours: 168, approvalExpiryDays: 7, recoveryHoldHours: 72 }

describe.skipIf(!hasDatabase)('access administration on PostgreSQL', () => {
  let pool: pg.Pool
  let drop: () => Promise<void>
  let at = new Date(START)
  const hoursLater = (n: number) => { at = new Date(at.getTime() + n * 3_600_000) }

  // Identity, as the host's adapters present it: the directory and the governance port.
  const groups = new Map<string, AuthorisationGroup>()
  const personalOf = new Map<string, string>()
  const memberships = new Map<string, { groupId: string, status: AuthorisationMembershipStatus }[]>()
  const owners = new Map<string, Set<string>>()
  const required = new Map<string, AuthorisationRequiredApprovers>()
  const holds = new Map<string, string>()
  const controls = new Map<string, string[]>()
  let governanceFails = false

  const group = (groupId: string, parent: string | null, tenantId = 'tenant-a') => {
    const lineage = parent ? [...groups.get(parent)!.lineage, groupId] : [groupId]
    groups.set(groupId, { groupId, lineage, tenantId })
  }
  const member = (principalId: string, groupId: string, status: AuthorisationMembershipStatus = 'active') => {
    memberships.set(principalId, [...(memberships.get(principalId) ?? []).filter(m => m.groupId !== groupId), { groupId, status }])
  }

  const directory: AuthorisationDirectory = {
    async resolveActor(principalId) {
      const personal = [...personalOf.entries()].find(([, owner]) => owner === principalId)?.[0]
      const list = memberships.get(principalId)
      if (!list && !personal) return null
      return {
        principalId,
        status: 'active',
        personalGroup: personal ? groups.get(personal)! : null,
        memberships: (list ?? []).map(m => ({ group: groups.get(m.groupId)!, status: m.status })),
      }
    },
    async describeGroup(groupId) {
      return groups.get(groupId) ?? null
    },
  }

  const governance: AuthorisationGovernance = {
    async describeGroup({ groupId, principalId }) {
      if (governanceFails) throw new Error('identity is down')
      const g = groups.get(groupId)
      if (!g) return null
      const personal = personalOf.get(groupId) ?? null
      return {
        groupId,
        tenantId: g.tenantId,
        kind: personal ? 'personal' : 'standard',
        state: 'active',
        parentGroupId: g.lineage.at(-2) ?? null,
        rootGroupId: g.lineage[0]!,
        personalOfPrincipalId: personal,
        approvals: { required: required.get(groupId) ?? DEFAULT_REQUIRED, referenceRequired: false },
        safetyPeriods: PERIODS,
        requester: { recoveryHoldUntil: holds.get(principalId) ?? null, controls: controls.get(principalId) ?? [] },
      }
    },
    async isOwner({ principalId, groupId }) {
      if (governanceFails) throw new Error('identity is down')
      return owners.get(groupId)?.has(principalId) ?? false
    },
    async countOwners({ groupId, excluding }) {
      if (governanceFails) throw new Error('identity is down')
      return [...(owners.get(groupId) ?? [])].filter(owner => !excluding.includes(owner)).length
    },
  }

  /** A session authenticated `minutesAgo` before the clock's time. */
  const subject = (principalId: string, options: { level?: 'aal1' | 'aal2', phishingResistant?: boolean, minutesAgo?: number } = {}): AuthorisationSubject => ({
    principalId,
    authenticatedAt: new Date(at.getTime() - (options.minutesAgo ?? 1) * 60_000).toISOString(),
    assurance: { level: options.level ?? 'aal2', phishingResistant: options.phishingResistant ?? true },
  })
  const weak = (principalId: string) => subject(principalId, { level: 'aal1', phishingResistant: false })

  const changes = () => getAuthorisationChanges()
  const justification = { reasonCode: 'new-starter', reference: null }
  const request = (as: AuthorisationSubject, type: string, target: object) =>
    changes().request({ subject: as, request: { type, target, justification }, correlationId: CORRELATION })
  const approve = async (as: AuthorisationSubject, changeId: string, decision: 'approve' | 'reject' = 'approve') => {
    const change = await changes().get({ subject: as, changeId })
    return changes().decide({ subject: as, changeId, changeDigest: change.changeDigest, decision, correlationId: CORRELATION })
  }
  const may = async (principalId: string, permission: string, owningGroupId: string, id = 'order-1') =>
    (await authorise({ subject: subject(principalId), permission, resource: { type: permission.split(':')[0]!, id, owningGroupId } })).allowed

  async function relayed(): Promise<AuthorisationEvent[]> {
    const events: AuthorisationEvent[] = []
    await relayAuthorisationOutbox({ publish: async (event) => { events.push(event) }, limit: 1000 })
    return events
  }

  const owner = async (principalId: string, groupId: string) => {
    owners.set(groupId, new Set([...(owners.get(groupId) ?? []), principalId]))
    member(principalId, groupId)
    await assignAuthorisationRole({ principalId, groupId, roleId: 'owner', actorPrincipalId: 'identity-events' })
  }

  beforeAll(async () => {
    const database = await createTestDatabase()
    drop = database.drop
    pool = new pg.Pool({ connectionString: database.url })

    // tenant-a: company ── sales ── team;  tenant-b: solo (one owner, no parent); pat's personal group.
    group('company', null)
    group('sales', 'company')
    group('team', 'sales')
    group('solo', null, 'tenant-b')
    group('personal-pat', null, 'personal-pat')
    personalOf.set('personal-pat', 'pat')

    clearAuthorisationComposition()
    provideAuthorisationDatabase({ dialect: 'postgres', pool })
    provideAuthorisationDirectory(directory)
    provideAuthorisationGovernance(governance)
    provideAuthorisationPermissions(PERMISSIONS)
    provideAuthorisationClock({ now: () => at })
    await migrateAuthorisationDatabase()

    await owner('olive', 'company')
    await owner('otto', 'company')
    await owner('sam', 'sales')
    for (const admin of ['adam', 'amy']) {
      member(admin, 'sales')
      await assignAuthorisationRole({ principalId: admin, groupId: 'sales', roleId: 'administrator', actorPrincipalId: 'olive' })
    }
    member('mia', 'sales')
    member('gus', 'sales')
    member('tara', 'team')
    await assignAuthorisationRole({ principalId: 'tara', groupId: 'team', roleId: 'administrator', actorPrincipalId: 'sam' })
    member('tim', 'team')
    await owner('sole', 'solo')
    member('mo', 'solo')
    await relayed()
  })

  beforeEach(() => {
    governanceFails = false
  })

  afterAll(async () => {
    clearAuthorisationComposition()
    await pool?.end()
    await drop?.()
  })

  describe('assignments and their risk', () => {
    it('applies assigning member at once, in one transaction with its events', async () => {
      const change = await request(weak('adam'), 'role.assign', { principalId: 'mia', groupId: 'sales', roleId: 'member' })
      expect(change).toMatchObject({ type: 'role.assign', risk: 'medium', route: 'none', requiredApprovals: 0, state: 'applied', requesterId: 'adam', beneficiaryId: 'mia' })
      expect(await may('mia', 'orders:create', 'sales')).toBe(true)
      const events = await relayed()
      expect(events.map(e => e.type)).toEqual(['authorisation.role-assigned', 'authorisation.change-decided', 'authorisation.change-requested'])
      expect(events[0]).toMatchObject({ actorPrincipalId: 'adam', correlationId: CORRELATION, data: { principalId: 'mia', roleId: 'member', changeId: change.changeId } })
      expect(events[2]).toMatchObject({ data: { changeId: change.changeId, state: 'applied', route: 'none', risk: 'medium' } })
    })

    it('makes assigning administrator wait for an approver, who must step up and may not be the requester', async () => {
      await expect(request(weak('adam'), 'role.assign', { principalId: 'mia', groupId: 'sales', roleId: 'administrator' })).rejects.toMatchObject({ code: 'insufficient-assurance' })
      const change = await request(subject('adam', { phishingResistant: false }), 'role.assign', { principalId: 'mia', groupId: 'sales', roleId: 'administrator' })
      expect(change).toMatchObject({ risk: 'high', route: 'approvers', requiredApprovals: 1, state: 'awaiting-approval' })
      expect(change.expiresAt).toBe(new Date(at.getTime() + 7 * 86_400_000).toISOString())
      expect(await may('mia', 'authorisation.grants:manage', 'sales')).toBe(false)
      await expect(approve(subject('adam'), change.changeId)).rejects.toMatchObject({ code: 'conflict', reason: 'own-request' })
      await expect(approve(subject('mia'), change.changeId)).rejects.toMatchObject({ code: 'conflict', reason: 'beneficiary' })
      await expect(approve(weak('amy'), change.changeId)).rejects.toMatchObject({ code: 'insufficient-assurance' })
      // Someone who does not qualify sees nothing at all.
      await expect(changes().get({ subject: subject('gus'), changeId: change.changeId })).rejects.toMatchObject({ code: 'forbidden' })
      expect(await approve(subject('amy', { phishingResistant: false }), change.changeId)).toMatchObject({ state: 'applied' })
      expect(await may('mia', 'authorisation.grants:manage', 'sales')).toBe(true)
      const decided = (await relayed()).find(e => e.type === 'authorisation.change-decided')
      expect(decided).toMatchObject({ actorPrincipalId: 'amy', data: { state: 'applied' } })
    })

    it('makes the descendants scope critical: an approver at phishing-resistant aal2 within 15 minutes', async () => {
      await expect(request(subject('adam', { phishingResistant: false }), 'role.assign', { principalId: 'gus', groupId: 'sales', roleId: 'viewer', scope: 'group-and-descendants' }))
        .rejects.toMatchObject({ code: 'insufficient-assurance' })
      const change = await request(subject('adam'), 'role.assign', { principalId: 'gus', groupId: 'sales', roleId: 'viewer', scope: 'group-and-descendants' })
      expect(change).toMatchObject({ risk: 'critical', route: 'approvers', state: 'awaiting-approval' })
      await expect(approve(subject('amy', { phishingResistant: false }), change.changeId)).rejects.toMatchObject({ code: 'insufficient-assurance' })
      await expect(approve(subject('amy', { minutesAgo: 20 }), change.changeId)).rejects.toMatchObject({ code: 'insufficient-assurance' })
      expect(await approve(subject('amy'), change.changeId)).toMatchObject({ state: 'applied' })
      expect(await may('gus', 'orders:view', 'team')).toBe(true)
    })

    it('never assigns or removes owner, which follows Identity', async () => {
      await expect(request(subject('adam'), 'role.assign', { principalId: 'mia', groupId: 'sales', roleId: 'owner' })).rejects.toMatchObject({ code: 'conflict', reason: 'owner-role' })
      await expect(request(subject('olive'), 'role.unassign', { principalId: 'otto', groupId: 'company', roleId: 'owner' })).rejects.toMatchObject({ code: 'conflict', reason: 'owner-role' })
      await expect(request(subject('olive'), 'group.change-default-roles', { groupId: 'company', defaultRoles: { member: 'owner', guest: null } })).rejects.toMatchObject({ code: 'conflict', reason: 'owner-role' })
    })

    it('refuses a role outside the tenant, and a principal who is not a member', async () => {
      await expect(request(subject('adam'), 'role.assign', { principalId: 'mia', groupId: 'sales', roleId: 'auditor' })).rejects.toMatchObject({ code: 'conflict', reason: 'unknown-role' })
      await expect(request(subject('adam'), 'role.assign', { principalId: 'stranger', groupId: 'sales', roleId: 'viewer' })).rejects.toMatchObject({ code: 'conflict', reason: 'not-a-member' })
      // Someone without the permission learns nothing, not even whether the group exists.
      await expect(request(subject('gus'), 'role.assign', { principalId: 'mia', groupId: 'sales', roleId: 'viewer' })).rejects.toMatchObject({ code: 'forbidden' })
      await expect(request(subject('gus'), 'role.assign', { principalId: 'mia', groupId: 'nowhere', roleId: 'viewer' })).rejects.toMatchObject({ code: 'forbidden' })
    })
  })

  describe('no self-grant, and personal-group sovereignty', () => {
    it('refuses assigning a role to oneself or confirming one\'s own assignment, at every risk', async () => {
      await expect(request(weak('adam'), 'role.assign', { principalId: 'adam', groupId: 'sales', roleId: 'viewer' })).rejects.toMatchObject({ code: 'conflict', reason: 'self-grant' })
      await expect(request(weak('adam'), 'assignment.confirm', { principalId: 'adam', groupId: 'sales', roleId: 'administrator' })).rejects.toMatchObject({ code: 'conflict', reason: 'self-grant' })
      await expect(changes().request({ subject: subject('olive'), request: { type: 'grant.create', target: { grant: { resource: { type: 'orders', id: 'order-7', owningGroupId: 'company' }, subject: { kind: 'principal', principalId: 'olive' }, permissions: ['orders:view'], expiresAt: null } }, justification }, correlationId: CORRELATION }))
        .rejects.toMatchObject({ code: 'conflict', reason: 'self-grant' })
    })

    it('lets a person share from their own personal group with no approver, after step-up only', async () => {
      const share = (as: AuthorisationSubject) => changes().request({
        subject: as,
        request: { type: 'grant.create', target: { grant: { resource: { type: 'orders', id: 'pat-order', owningGroupId: 'personal-pat' }, subject: { kind: 'principal', principalId: 'mia' }, permissions: ['orders:view'], expiresAt: null } }, justification },
        correlationId: CORRELATION,
      })
      await expect(share(weak('pat'))).rejects.toMatchObject({ code: 'insufficient-assurance' })
      // Beyond the personal group's tenant: critical, so a recent phishing-resistant sign-in.
      await expect(share(subject('pat', { minutesAgo: 30 }))).rejects.toMatchObject({ code: 'insufficient-assurance' })
      expect(await share(subject('pat'))).toMatchObject({ risk: 'critical', route: 'none', requiredApprovals: 0, state: 'applied' })
    })

    it('binds a grant to the owning group named, so a false claim confers nothing on the real owner\'s resource', async () => {
      const claimed = await changes().request({
        subject: subject('pat'),
        request: { type: 'grant.create', target: { grant: { resource: { type: 'orders', id: 'order-1', owningGroupId: 'personal-pat' }, subject: { kind: 'principal', principalId: 'tim' }, permissions: ['orders:view'], expiresAt: null } }, justification },
        correlationId: CORRELATION,
      })
      expect(claimed.state).toBe('applied')
      expect(await may('tim', 'orders:view', 'sales', 'order-1')).toBe(false)
    })
  })

  describe('approval routes', () => {
    it('takes a critical change by a sole owner without a parent only after the published delay, and lets it be cancelled meanwhile', async () => {
      const first = await request(subject('sole'), 'role.assign', { principalId: 'mo', groupId: 'solo', roleId: 'viewer', scope: 'group-and-descendants' })
      expect(first).toMatchObject({ route: 'published-delay', state: 'delayed', expiresAt: null, delayEndsAt: new Date(at.getTime() + 168 * 3_600_000).toISOString() })
      await expect(changes().cancel({ subject: subject('mo'), changeId: first.changeId, correlationId: CORRELATION })).rejects.toMatchObject({ code: 'forbidden' })
      expect(await changes().cancel({ subject: subject('sole'), changeId: first.changeId, correlationId: CORRELATION })).toMatchObject({ state: 'cancelled' })

      const second = await request(subject('sole'), 'role.assign', { principalId: 'mo', groupId: 'solo', roleId: 'viewer', scope: 'group-and-descendants' })
      hoursLater(167)
      expect(await runAuthorisationMaintenance()).toMatchObject({ appliedChanges: 0 })
      expect(await may('mo', 'orders:view', 'solo')).toBe(false)
      hoursLater(1)
      expect(await runAuthorisationMaintenance()).toMatchObject({ appliedChanges: 1 })
      expect((await changes().get({ subject: subject('sole'), changeId: second.changeId })).state).toBe('applied')
      expect(await may('mo', 'orders:view', 'solo')).toBe(true)
    })

    it('lets one owner of the parent group approve in a group that requires two approvers', async () => {
      required.set('team', { low: 0, medium: 0, high: 2, critical: 2 })
      const change = await request(subject('tara'), 'role.assign', { principalId: 'tim', groupId: 'team', roleId: 'administrator' })
      expect(change).toMatchObject({ route: 'parent-owner', requiredApprovals: 1, state: 'awaiting-approval' })
      // Not an owner of the parent: not someone who may decide.
      await expect(approve(subject('olive'), change.changeId)).rejects.toMatchObject({ code: 'forbidden' })
      expect(await approve(subject('sam'), change.changeId)).toMatchObject({ state: 'applied' })
      required.delete('team')
    })

    it('refuses an approver whose qualifying role was removed after the request', async () => {
      const change = await request(subject('adam'), 'role.assign', { principalId: 'gus', groupId: 'sales', roleId: 'administrator' })
      const seen = await changes().get({ subject: subject('amy'), changeId: change.changeId })
      await unassignAuthorisationRole({ principalId: 'amy', groupId: 'sales', roleId: 'administrator', actorPrincipalId: 'sam' })
      await expect(changes().decide({ subject: subject('amy'), changeId: change.changeId, changeDigest: seen.changeDigest, decision: 'approve', correlationId: CORRELATION })).rejects.toMatchObject({ code: 'forbidden' })
      await assignAuthorisationRole({ principalId: 'amy', groupId: 'sales', roleId: 'administrator', actorPrincipalId: 'sam' })
      expect(await approve(subject('amy'), change.changeId, 'reject')).toMatchObject({ state: 'rejected' })
    })

    it('never counts or accepts an identity the requester controls', async () => {
      controls.set('adam', ['amy', 'mia', 'sam'])
      member('cora', 'sales')
      const change = await request(subject('adam'), 'role.assign', { principalId: 'cora', groupId: 'sales', roleId: 'administrator', expiresAt: new Date(at.getTime() + 86_400_000).toISOString() })
      // amy does not count: the next route is an owner of the parent group.
      expect(change.route).toBe('parent-owner')
      controls.delete('adam')
      expect(await approve(subject('olive'), change.changeId)).toMatchObject({ state: 'applied' })
    })

    it('refuses an approved change that was modified before it applied', async () => {
      const change = await request(subject('adam'), 'role.assign', { principalId: 'gus', groupId: 'sales', roleId: 'administrator' })
      const seen = await changes().get({ subject: subject('amy'), changeId: change.changeId })
      await pool.query(`update "authorisation"."pending_change" set target = jsonb_set(target, '{principalId}', '"mia"') where change_id = $1`, [change.changeId])
      await expect(changes().decide({ subject: subject('amy'), changeId: change.changeId, changeDigest: seen.changeDigest, decision: 'approve', correlationId: CORRELATION })).rejects.toMatchObject({ code: 'conflict', reason: 'change-differs' })
      await expect(changes().decide({ subject: subject('amy'), changeId: change.changeId, changeDigest: 'f'.repeat(64), decision: 'approve', correlationId: CORRELATION })).rejects.toMatchObject({ code: 'conflict', reason: 'change-differs' })
    })

    it('checks every rule again when a change applies: an ended membership or a changed requirement rejects it', async () => {
      member('nia', 'sales')
      const first = await request(subject('adam'), 'role.assign', { principalId: 'nia', groupId: 'sales', roleId: 'administrator' })
      member('nia', 'sales', 'ended')
      expect(await approve(subject('amy'), first.changeId)).toMatchObject({ state: 'rejected' })
      member('nia', 'sales')
      const second = await request(subject('adam'), 'role.assign', { principalId: 'nia', groupId: 'sales', roleId: 'administrator' })
      required.set('sales', { low: 0, medium: 1, high: 2, critical: 2 })
      expect(await approve(subject('amy'), second.changeId)).toMatchObject({ state: 'rejected' })
      required.delete('sales')
      const failure = async (changeId: string) => (await pool.query(`select failure from "authorisation"."pending_change" where change_id = $1`, [changeId])).rows[0].failure
      expect([await failure(first.changeId), await failure(second.changeId)]).toEqual(['not-a-member', 'requirement-changed'])
    })

    it('expires a change nobody decided in time', async () => {
      const change = await request(subject('adam'), 'role.assign', { principalId: 'gus', groupId: 'sales', roleId: 'administrator' })
      hoursLater(7 * 24)
      expect((await runAuthorisationMaintenance()).expiredChanges).toBeGreaterThanOrEqual(1)
      expect((await changes().get({ subject: subject('adam'), changeId: change.changeId })).state).toBe('expired')
      await expect(approve(subject('amy'), change.changeId)).rejects.toMatchObject({ code: 'conflict', reason: 'not-pending' })
    })

    it('holds a change requested within the requester\'s recovery hold until the hold ends', async () => {
      holds.set('adam', new Date(at.getTime() + 24 * 3_600_000).toISOString())
      const change = await request(subject('adam'), 'role.assign', { principalId: 'gus', groupId: 'sales', roleId: 'viewer' })
      expect(change).toMatchObject({ route: 'none', state: 'delayed', heldUntil: holds.get('adam'), delayEndsAt: holds.get('adam') })
      expect((await relayed()).map(e => e.type)).toContain('authorisation.change-held')
      holds.delete('adam')
      hoursLater(24)
      expect(await runAuthorisationMaintenance()).toMatchObject({ appliedChanges: 1 })
      expect((await changes().get({ subject: subject('adam'), changeId: change.changeId })).state).toBe('applied')
    })

    it('fails closed without the governance port or when it fails, recording nothing', async () => {
      governanceFails = true
      await expect(request(subject('adam'), 'role.assign', { principalId: 'gus', groupId: 'sales', roleId: 'member' })).rejects.toMatchObject({ code: 'unavailable' })
      governanceFails = false
      await expect(request(subject('adam'), 'role.assign', { principalId: 'gus', groupId: 'sales', roleId: 'not a role' })).rejects.toMatchObject({ code: 'validation-failed' })
      const { rows } = await pool.query(`select count(*)::int as n from "authorisation"."pending_change" where beneficiary_id = 'gus' and target ->> 'roleId' = 'member'`)
      expect(rows[0].n).toBe(0)
      clearAuthorisationComposition()
      provideAuthorisationDatabase({ dialect: 'postgres', pool })
      provideAuthorisationDirectory(directory)
      provideAuthorisationPermissions(PERMISSIONS)
      provideAuthorisationClock({ now: () => at })
      await expect(request(subject('adam'), 'role.assign', { principalId: 'gus', groupId: 'sales', roleId: 'member' })).rejects.toMatchObject({ name: 'AuthorisationCompositionError' })
      provideAuthorisationGovernance(governance)
    })
  })

  describe('time-limited assignments', () => {
    it('confers nothing after its end, before maintenance runs, which then removes it', async () => {
      member('val', 'sales')
      await request(weak('adam'), 'role.assign', { principalId: 'val', groupId: 'sales', roleId: 'viewer', expiresAt: new Date(at.getTime() + 3_600_000).toISOString() })
      expect(await may('val', 'orders:view', 'sales')).toBe(true)
      hoursLater(1)
      expect(await may('val', 'orders:view', 'sales')).toBe(false)
      await relayed()
      expect(await runAuthorisationMaintenance()).toMatchObject({ expiredAssignments: 1 })
      expect((await relayed()).filter(e => e.type === 'authorisation.role-expired')).toEqual([expect.objectContaining({ actorPrincipalId: null, data: expect.objectContaining({ principalId: 'val', roleId: 'viewer' }) })])
    })
  })

  describe('default roles', () => {
    it('gives a new member and guest member and viewer by default, and the group\'s own once set, with approval and a hold for riskier ones', async () => {
      expect(await authorisationDefaultRoles('sales')).toEqual({ member: 'member', guest: 'viewer' })
      await expect(request(subject('sam'), 'group.change-default-roles', { groupId: 'sales', defaultRoles: { member: 'member', guest: 'administrator' } })).rejects.toMatchObject({ code: 'conflict', reason: 'guest-role-too-risky' })
      // Administrators cannot change a group's access; owners can.
      await expect(request(subject('adam'), 'group.change-default-roles', { groupId: 'sales', defaultRoles: { member: 'viewer', guest: null } })).rejects.toMatchObject({ code: 'forbidden' })
      const change = await request(subject('sam'), 'group.change-default-roles', { groupId: 'sales', defaultRoles: { member: 'administrator', guest: null } })
      expect(change).toMatchObject({ risk: 'high', route: 'parent-owner', state: 'awaiting-approval', heldUntil: new Date(at.getTime() + 72 * 3_600_000).toISOString() })
      expect(await approve(subject('olive'), change.changeId)).toMatchObject({ state: 'delayed' })
      expect(await authorisationDefaultRoles('sales')).toEqual({ member: 'member', guest: 'viewer' })
      hoursLater(72)
      await runAuthorisationMaintenance()
      expect(await authorisationDefaultRoles('sales')).toEqual({ member: 'administrator', guest: null })
      const safer = await request(subject('sam'), 'group.change-default-roles', { groupId: 'sales', defaultRoles: { member: 'member', guest: 'viewer' } })
      expect(safer.heldUntil).toBeNull()
      expect(await approve(subject('olive'), safer.changeId)).toMatchObject({ state: 'applied' })
      expect((await getAuthorisationAdministration().groupAccess({ subject: subject('mia'), groupId: 'sales' }))).toMatchObject({ defaultRoles: { member: 'member', guest: 'viewer' }, reviewIntervalDays: null })
    })
  })

  describe('access reviews', () => {
    it('shows an assignment not confirmed within the interval as overdue, announces it once, and keeps it working until removed', async () => {
      const change = await request(subject('sam'), 'group.change-review-interval', { groupId: 'sales', intervalDays: 30 })
      expect(await approve(subject('olive'), change.changeId)).toMatchObject({ state: 'applied' })
      member('rhea', 'sales')
      await request(weak('adam'), 'role.assign', { principalId: 'rhea', groupId: 'sales', roleId: 'viewer' })
      const entry = async () => (await listAuthorisationAccessReview({ subject: subject('adam'), groupId: 'sales' })).entries.find(e => e.principalId === 'rhea')!
      expect(await entry()).toMatchObject({ overdue: false, assignedBy: 'adam', confirmedAt: null })
      await expect(listAuthorisationAccessReview({ subject: subject('gus'), groupId: 'sales' })).rejects.toMatchObject({ code: 'forbidden' })
      hoursLater(30 * 24)
      expect(await entry()).toMatchObject({ overdue: true })
      expect(await may('rhea', 'orders:view', 'sales')).toBe(true)
      await relayed()
      const first = await runAuthorisationMaintenance()
      expect(first.overdueReviews).toBeGreaterThanOrEqual(1)
      expect((await relayed()).filter(e => e.type === 'authorisation.review-overdue' && e.data.principalId === 'rhea')).toHaveLength(1)
      await runAuthorisationMaintenance()
      expect((await relayed()).filter(e => e.type === 'authorisation.review-overdue' && e.data.principalId === 'rhea')).toHaveLength(0)
      expect(await may('rhea', 'orders:view', 'sales')).toBe(true)
      expect(await request(weak('adam'), 'assignment.confirm', { principalId: 'rhea', groupId: 'sales', roleId: 'viewer' })).toMatchObject({ risk: 'low', state: 'applied' })
      expect(await entry()).toMatchObject({ overdue: false, confirmedBy: 'adam' })
    })
  })

  describe('custom roles', () => {
    const clerk = { id: 'clerk', name: 'Clerk', permissions: [{ pattern: 'orders:process_refund' }] }

    it('is defined only by an owner of the tenant\'s root group, with an approval', async () => {
      await expect(request(subject('adam'), 'role.define', { tenantId: 'tenant-a', role: clerk })).rejects.toMatchObject({ code: 'forbidden' })
      await expect(request(subject('sam'), 'role.define', { tenantId: 'tenant-a', role: clerk })).rejects.toMatchObject({ code: 'forbidden' })
      await expect(request(subject('olive'), 'role.define', { tenantId: 'tenant-a', role: { ...clerk, id: 'viewer' } })).rejects.toMatchObject({ code: 'conflict', reason: 'built-in-role' })
      const change = await request(subject('olive'), 'role.define', { tenantId: 'tenant-a', role: clerk })
      expect(change).toMatchObject({ groupId: 'company', risk: 'critical', route: 'approvers', state: 'awaiting-approval' })
      expect(await approve(subject('otto'), change.changeId)).toMatchObject({ state: 'applied' })
      const roles = await getAuthorisationAdministration().tenantRoles({ subject: subject('mia'), tenantId: 'tenant-a' })
      expect(roles.roles.find(r => r.id === 'clerk')).toMatchObject({ builtIn: false, risk: 'high' })
      expect(roles.roles.find(r => r.id === 'administrator')).toMatchObject({ builtIn: true, risk: 'high' })
    })

    it('takes its assignment risk from its permissions, and refuses deleting it while assigned', async () => {
      member('cal', 'sales')
      const assign = await request(subject('adam'), 'role.assign', { principalId: 'cal', groupId: 'sales', roleId: 'clerk' })
      expect(assign).toMatchObject({ risk: 'high', state: 'awaiting-approval' })
      expect(await approve(subject('amy'), assign.changeId)).toMatchObject({ state: 'applied' })
      await expect(request(subject('olive'), 'role.delete', { tenantId: 'tenant-a', roleId: 'clerk' })).rejects.toMatchObject({ code: 'conflict', reason: 'role-in-use' })
    })

    it('exports roles as a versioned document, and imports only one whose digest matches and that removes nothing in use', async () => {
      const document = await exportAuthorisationRoles({ tenantId: 'tenant-a' })
      expect(document).toMatchObject({ format: 'nuxt4-layers.authorisation.roles', formatVersion: 1, tenantId: 'tenant-a', roles: [expect.objectContaining({ id: 'clerk' })] })
      const tampered = { ...document, roles: [{ ...document.roles[0]!, permissions: [{ pattern: 'orders:purge' }] }] }
      await expect(importAuthorisationRoles({ tenantId: 'tenant-a', document: tampered, correlationId: CORRELATION })).rejects.toMatchObject({ code: 'validation-failed', reason: 'digest-mismatch' })
      await expect(importAuthorisationRoles({ tenantId: 'tenant-b', document, correlationId: CORRELATION })).rejects.toMatchObject({ reason: 'tenant-mismatch' })
      const { createHash } = await import('node:crypto')
      const { canonicalJson } = await import('../contracts')
      const sign = (body: object) => ({ ...body, digest: createHash('sha256').update(canonicalJson(body)).digest('hex') })
      const base = { format: document.format, formatVersion: document.formatVersion, tenantId: 'tenant-a' }
      await expect(importAuthorisationRoles({ tenantId: 'tenant-a', document: sign({ ...base, roles: [] }), correlationId: CORRELATION })).rejects.toMatchObject({ code: 'conflict', reason: 'role-in-use' })
      await expect(importAuthorisationRoles({ tenantId: 'tenant-a', document: sign({ ...base, roles: [{ id: 'member', name: 'M', permissions: [] }] }), correlationId: CORRELATION })).rejects.toMatchObject({ reason: 'built-in-role' })
      const auditor = { id: 'auditor', name: 'Auditor', permissions: [{ pattern: '*:view' }] }
      const imported = await importAuthorisationRoles({ tenantId: 'tenant-a', document: sign({ ...base, roles: [auditor, document.roles[0]!] }), correlationId: CORRELATION })
      expect(imported).toEqual({ defined: ['auditor'], changed: [], deleted: [] })
      const event = (await relayed()).find(e => e.type === 'authorisation.roles-imported')
      expect(event).toMatchObject({ actorPrincipalId: null, data: { tenantId: 'tenant-a', defined: ['auditor'] } })
      expect((await exportAuthorisationRoles({ tenantId: 'tenant-a' })).roles.map(r => r.id)).toEqual(['auditor', 'clerk'])
    })
  })

  describe('reads, erasure and the outbox', () => {
    it('lists a group\'s open changes, assignments and grants only for those entitled to', async () => {
      const open = await request(subject('adam'), 'role.assign', { principalId: 'gus', groupId: 'sales', roleId: 'administrator' })
      expect((await changes().listForGroup({ subject: subject('mia'), groupId: 'sales' })).map(c => c.changeId)).toContain(open.changeId)
      await expect(changes().listForGroup({ subject: subject('pat'), groupId: 'sales' })).rejects.toMatchObject({ code: 'forbidden' })
      const assignments = await getAuthorisationAdministration().assignments({ subject: subject('mia'), groupId: 'sales' })
      expect(assignments.find(a => a.principalId === 'mia' && a.roleId === 'member')).toMatchObject({ assignedBy: 'adam' })
      await expect(getAuthorisationAdministration().grants({ subject: subject('gus'), groupId: 'sales' })).rejects.toMatchObject({ code: 'forbidden' })
      expect(await getAuthorisationAdministration().grants({ subject: subject('pat'), groupId: 'personal-pat' })).toHaveLength(2)
      expect((await getAuthorisationAdministration().self({ subject: subject('mia') })).assignments.map(a => a.roleId).sort()).toEqual(['administrator', 'member'])
    })

    it('rejects the open changes of an erased principal', async () => {
      member('zed', 'sales')
      const open = await request(subject('adam'), 'role.assign', { principalId: 'zed', groupId: 'sales', roleId: 'administrator' })
      await eraseAuthorisationPrincipal({ principalId: 'zed', actorPrincipalId: 'iam-integration' })
      expect((await changes().get({ subject: subject('adam'), changeId: open.changeId })).state).toBe('rejected')
    })

    it('relays every change event at least once, retrying a failed publication', async () => {
      await relayed()
      await request(weak('adam'), 'assignment.confirm', { principalId: 'mia', groupId: 'sales', roleId: 'member' })
      const error = vi.spyOn(console, 'error').mockImplementation(() => {})
      expect(await relayAuthorisationOutbox({ publish: async () => { throw new Error('down') } })).toEqual({ published: 0, failed: 1 })
      error.mockRestore()
      expect((await relayed()).map(e => e.type)).toEqual(['authorisation.assignment-confirmed', 'authorisation.change-decided', 'authorisation.change-requested'])
    })
  })

  describe('end of life (iam-integration group deletion, tenant lifecycle and retention)', () => {
    it('disposes of a deleted group\'s assignments, grants, access settings and changes, and confirms it every time', async () => {
      group('doomed', 'company')
      await owner('dora', 'doomed')
      member('dan', 'doomed')
      await assignAuthorisationRole({ principalId: 'dan', groupId: 'doomed', roleId: 'member', actorPrincipalId: 'dora' })
      await createAuthorisationGrant({ grant: { resource: { type: 'orders', id: 'order-doomed', owningGroupId: 'doomed' }, subject: { kind: 'principal', principalId: 'mia' }, permissions: ['orders:view'], expiresAt: null }, actorPrincipalId: 'dora' })
      await createAuthorisationGrant({ grant: { resource: { type: 'orders', id: 'order-sales', owningGroupId: 'sales' }, subject: { kind: 'group', groupId: 'doomed' }, permissions: ['orders:view'], expiresAt: null }, actorPrincipalId: 'sam' })
      await request(subject('dora'), 'role.assign', { principalId: 'dan', groupId: 'doomed', roleId: 'administrator' })
      await relayed()

      expect(await disposeAuthorisationGroup({ groupId: 'doomed', correlationId: CORRELATION })).toEqual({ assignments: 2, grants: 2, changes: 1 })
      expect((await relayed()).map(e => [e.type, e.data])).toEqual([['authorisation.group-disposed', { groupId: 'doomed', assignments: 2, grants: 2, changes: 1 }]])
      const { rows } = await pool.query(`select (select count(*)::int from authorisation."role_assignment" where group_id = 'doomed') as a,
        (select count(*)::int from authorisation."grant" where owning_group_id = 'doomed' or subject_id = 'doomed') as g`)
      expect(rows[0]).toEqual({ a: 0, g: 0 })
      // Delivered again: nothing left, and confirmed again, which Identity counts once.
      expect(await disposeAuthorisationGroup({ groupId: 'doomed', correlationId: CORRELATION })).toEqual({ assignments: 0, grants: 0, changes: 0 })
      expect((await relayed()).map(e => e.type)).toEqual(['authorisation.group-disposed'])
      await expect(disposeAuthorisationGroup({ groupId: 'not an id!', correlationId: CORRELATION })).rejects.toMatchObject({ code: 'validation-failed' })
    })

    it('disposes of a closed tenant\'s custom roles', async () => {
      await defineAuthorisationRole({ tenantId: 'tenant-b', role: { id: 'auditor', name: 'Auditor', permissions: [{ pattern: 'orders:view' }] }, actorPrincipalId: 'sole' })
      await relayed()
      expect(await disposeAuthorisationTenant({ tenantId: 'tenant-b', correlationId: CORRELATION })).toEqual({ roles: 1, changes: 0 })
      expect((await relayed()).map(e => [e.type, e.data])).toEqual([['authorisation.tenant-disposed', { tenantId: 'tenant-b', roles: 1, changes: 0 }]])
      expect((await exportAuthorisationRoles({ tenantId: 'tenant-b' })).roles).toEqual([])
    })

    it('gives the tenant\'s governance export for the groups Identity names, and nothing else', async () => {
      const exported = await exportAuthorisationTenantData({ tenantId: 'tenant-a', groupIds: ['sales', 'company'], correlationId: CORRELATION })
      expect(exported).toMatchObject({ tenantId: 'tenant-a', roles: { tenantId: 'tenant-a' } })
      expect(new Set(exported.assignments.map(a => a.groupId))).toEqual(new Set(['company', 'sales']))
      expect(exported.groupAccess.map(a => a.groupId)).toEqual(['company', 'sales'])
      expect(exported.assignments.some(a => a.groupId === 'team')).toBe(false)
    })

    it('deletes delivered events and decided changes past their period, never a change a hold may cover', async () => {
      const decided = await request(subject('adam'), 'role.assign', { principalId: 'gus', groupId: 'sales', roleId: 'viewer' })
      if (decided.state === 'awaiting-approval' || decided.state === 'delayed') await changes().cancel({ subject: subject('adam'), changeId: decided.changeId, correlationId: CORRELATION })
      await relayed()
      hoursLater(24 * 800)
      // Without the legal-hold port, no change is deleted.
      expect((await runAuthorisationMaintenance()).retention.changes).toBe(0)
      const kept = async () => (await pool.query(`select 1 from authorisation."pending_change" where change_id = $1`, [decided.changeId])).rows.length
      const held = new Set(['sales'])
      provideAuthorisationLegalHolds({ async covers({ id }) { return held.has(id) } })
      await runAuthorisationMaintenance()
      expect(await kept()).toBe(1)
      held.clear()
      const { retention } = await runAuthorisationMaintenance()
      expect(retention.changes).toBeGreaterThan(0)
      expect(await kept()).toBe(0)
      expect((await relayed()).find(e => e.type === 'authorisation.retention-applied')).toBeTruthy()
    })
  })
})

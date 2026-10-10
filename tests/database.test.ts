import pg from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import type {
  AuthorisationActorContext,
  AuthorisationDirectory,
  AuthorisationDirectoryReadOptions,
  AuthorisationDenialEvent,
  AuthorisationEvent,
  AuthorisationGroup,
  AuthorisationMembershipStatus,
  AuthorisationPermissionDefinition,
  AuthorisationResource,
  AuthorisationSubject,
} from '../contracts'
import { AUTHORISATION_PERMISSIONS, AuthorisationFailure, resolveAuthorisationPolicy } from '../contracts'
import { AUTHORISATION_MIGRATIONS, runAuthorisationMigrations } from '../server/database/migrations'
import { createService } from '../server/internal/service'
import { createDatabase } from '../server/internal/database'
import { relayOutbox } from '../server/internal/outbox'
import {
  clearAuthorisationComposition,
  provideAuthorisationClock,
  provideAuthorisationDatabase,
  provideAuthorisationDirectory,
  provideAuthorisationEventSink,
  provideAuthorisationPermissions,
} from '../server/utils/authorisation-composition'
import { assignAuthorisationRole, authorise, createAuthorisationGrant } from '../server/utils/authorisation-server'
import { createTestDatabase, hasDatabase, requireDatabaseInCi } from './support/database'

requireDatabaseInCi()

const PERMISSIONS: AuthorisationPermissionDefinition[] = [
  ...AUTHORISATION_PERMISSIONS,
  { name: 'orders:view', description: 'See orders', risk: 'low', effect: 'view' },
  { name: 'orders:update', description: 'Change orders', risk: 'medium', effect: 'change' },
  { name: 'orders:process_refund', description: 'Refund an order', risk: 'high', effect: 'change' },
  { name: 'identity.groups:archive', description: 'Archive a group', risk: 'high', effect: 'change' },
  { name: 'orders:purge', description: 'Purge an order', risk: 'critical', effect: 'change' },
]

describe.skipIf(!hasDatabase)('authorisation storage and decisions on PostgreSQL', () => {
  let pool: pg.Pool
  let drop: () => Promise<void>
  const denials: AuthorisationDenialEvent[] = []
  let seen = 0
  /** Outbox events written since the last call. */
  async function outbox(): Promise<AuthorisationEvent[]> {
    const { rows } = await pool.query(`select "sequence", "payload" from "authorisation"."outbox" where "sequence" > $1 order by "sequence"`, [seen])
    if (rows.length > 0) seen = Number(rows.at(-1).sequence)
    return rows.map(row => row.payload)
  }
  const reads: AuthorisationDirectoryReadOptions['consistency'][] = []

  // A stand-in for the host's Identity adapter.
  const groups = new Map<string, AuthorisationGroup>()
  const memberships = new Map<string, { groupId: string, status: AuthorisationMembershipStatus }[]>()
  let failing = false
  const group = (groupId: string, parent: string | null, tenantId = 'tenant-a') => {
    const lineage = parent ? [...groups.get(parent)!.lineage, groupId] : [groupId]
    groups.set(groupId, { groupId, lineage, tenantId })
  }
  const member = (principalId: string, groupId: string, status: AuthorisationMembershipStatus = 'active') => {
    memberships.set(principalId, [...(memberships.get(principalId) ?? []).filter(m => m.groupId !== groupId), { groupId, status }])
  }
  const directory: AuthorisationDirectory = {
    async resolveActor(principalId, options): Promise<AuthorisationActorContext | null> {
      reads.push(options.consistency)
      if (failing) throw new Error('directory down')
      const list = memberships.get(principalId)
      if (!list) return null
      return { principalId, status: 'active', personalGroup: null, memberships: list.map(m => ({ group: groups.get(m.groupId)!, status: m.status })) }
    },
    async describeGroup(groupId, options) {
      reads.push(options.consistency)
      if (failing) throw new Error('directory down')
      return groups.get(groupId) ?? null
    },
  }

  const service = () => createService({
    db: createDatabase(pool, 'authorisation'),
    schemaName: 'authorisation',
    directory,
    catalogue: new Map(PERMISSIONS.map(p => [p.name, p])),
    policy: resolveAuthorisationPolicy(),
    emitDenial: async (event) => { denials.push(event) },
  })
  const subject = (principalId: string, level: 'aal1' | 'aal2' = 'aal2'): AuthorisationSubject =>
    ({ principalId, authenticatedAt: new Date().toISOString(), assurance: { level, phishingResistant: true } })
  const order = (owningGroupId: string, id = 'order-1'): AuthorisationResource => ({ type: 'orders', id, owningGroupId })
  const groupResource = (groupId: string): AuthorisationResource => ({ type: 'identity.groups', id: groupId, owningGroupId: groupId })

  beforeAll(async () => {
    const database = await createTestDatabase()
    drop = database.drop
    pool = new pg.Pool({ connectionString: database.url })
    group('company', null)
    group('sales', 'company')
    group('other-tenant', null, 'tenant-b')
  })

  beforeEach(async () => {
    denials.length = 0
    reads.length = 0
    failing = false
    await outbox().catch(() => [])
  })

  afterAll(async () => {
    await pool?.end()
    await drop?.()
  })

  it('applies every migration once, even when instances race', async () => {
    const results = await Promise.all([runAuthorisationMigrations(pool, 'authorisation'), runAuthorisationMigrations(pool, 'authorisation')])
    expect(results.flat()).toEqual(AUTHORISATION_MIGRATIONS.map(m => m.id))
    expect(await runAuthorisationMigrations(pool, 'authorisation')).toEqual([])
    const { rows } = await pool.query(`select table_name from information_schema.tables where table_schema = 'authorisation' order by table_name`)
    expect(rows.map(r => r.table_name)).toEqual(['custom_role', 'grant', 'group_access', 'outbox', 'pending_change', 'role_assignment', 'schema_migration'])
  })

  it('decides from stored assignments, reading the directory strongly for high-risk permissions', async () => {
    member('alice', 'sales')
    expect(await service().assign({ principalId: 'alice', groupId: 'sales', roleId: 'administrator', actorPrincipalId: 'system' })).toBe(true)
    expect((await outbox()).at(-1)).toMatchObject({ type: 'authorisation.role-assigned', actorPrincipalId: 'system', data: { principalId: 'alice', groupId: 'sales', roleId: 'administrator', scope: 'group', expiresAt: null, changeId: null } })
    reads.length = 0
    expect(await service().authorise({ subject: subject('alice'), permission: 'orders:view', resource: order('sales') })).toMatchObject({ allowed: true, via: 'role' })
    expect(reads).toEqual(['bounded', 'bounded'])
    reads.length = 0
    expect(await service().authorise({ subject: subject('alice'), permission: 'orders:process_refund', resource: order('sales') })).toMatchObject({ allowed: false, reason: 'not-permitted' })
    expect(reads).toEqual(['strong', 'strong'])
    expect(denials.at(-1)).toMatchObject({ type: 'authorisation.denied', actorPrincipalId: 'alice', permission: 'orders:process_refund', reason: 'not-permitted' })
  })

  it('ends access with the membership, and never reaches up or across', async () => {
    member('bob', 'sales')
    await service().assign({ principalId: 'bob', groupId: 'sales', roleId: 'viewer', actorPrincipalId: 'system' })
    expect((await service().authorise({ subject: subject('bob'), permission: 'orders:view', resource: order('company') })).allowed).toBe(false)
    member('bob', 'sales', 'suspended')
    expect((await service().authorise({ subject: subject('bob'), permission: 'orders:view', resource: order('sales') })).allowed).toBe(false)
  })

  it('lets a paused member view but not change, and never qualify to change', async () => {
    member('paula', 'sales', 'paused')
    await service().assign({ principalId: 'paula', groupId: 'sales', roleId: 'administrator', actorPrincipalId: 'system' })
    expect(await service().authorise({ subject: subject('paula'), permission: 'orders:view', resource: order('sales') })).toMatchObject({ allowed: true, via: 'role' })
    expect(await service().authorise({ subject: subject('paula'), permission: 'orders:update', resource: order('sales') })).toMatchObject({ allowed: false, reason: 'paused' })
    expect(denials.at(-1)).toMatchObject({ type: 'authorisation.denied', actorPrincipalId: 'paula', permission: 'orders:update', reason: 'paused' })
    expect(await service().qualifies({ principalId: 'paula', permission: 'orders:update', resource: order('sales') })).toBe(false)
    member('paula', 'sales')
    expect(await service().qualifies({ principalId: 'paula', permission: 'orders:update', resource: order('sales') })).toBe(true)
  })

  it('reaches descendants only through an explicit scope', async () => {
    member('carol', 'company')
    await service().assign({ principalId: 'carol', groupId: 'company', roleId: 'viewer', scope: 'group-and-descendants', actorPrincipalId: 'system' })
    expect((await service().authorise({ subject: subject('carol'), permission: 'orders:view', resource: order('sales') })).allowed).toBe(true)
  })

  it('fails closed when the directory is unreachable', async () => {
    failing = true
    await expect(service().authorise({ subject: subject('alice'), permission: 'orders:view', resource: order('sales') })).rejects.toMatchObject({ code: 'unavailable' })
    await expect(service().countQualifying({ permission: 'orders:view', resource: order('sales'), excludingPrincipalIds: [], limit: 2 })).rejects.toBeInstanceOf(AuthorisationFailure)
  })

  it('refuses assignments to unknown groups and roles', async () => {
    await expect(service().assign({ principalId: 'alice', groupId: 'nowhere', roleId: 'viewer', actorPrincipalId: 'system' })).rejects.toMatchObject({ code: 'validation-failed' })
    await expect(service().assign({ principalId: 'alice', groupId: 'sales', roleId: 'auditor', actorPrincipalId: 'system' })).rejects.toMatchObject({ code: 'validation-failed' })
  })

  it('stores custom roles per tenant, and assigns them only in that tenant', async () => {
    const role = { id: 'refunder', name: 'Refunder', permissions: [{ pattern: 'orders:process_refund' }] }
    expect(await service().defineRole({ tenantId: 'tenant-a', role, actorPrincipalId: 'system' })).toBe('defined')
    expect(await service().defineRole({ tenantId: 'tenant-a', role, actorPrincipalId: 'system' })).toBe('changed')
    await expect(service().defineRole({ tenantId: 'tenant-a', role: { ...role, id: 'owner' }, actorPrincipalId: 'system' })).rejects.toMatchObject({ code: 'validation-failed' })
    await expect(service().defineRole({ tenantId: 'tenant-a', role: { ...role, id: 'typo', permissions: [{ pattern: 'orders:refnd' }] }, actorPrincipalId: 'system' })).rejects.toMatchObject({ code: 'validation-failed' })
    await expect(service().assign({ principalId: 'dave', groupId: 'other-tenant', roleId: 'refunder', actorPrincipalId: 'system' })).rejects.toMatchObject({ code: 'validation-failed' })
    member('dave', 'sales')
    await service().assign({ principalId: 'dave', groupId: 'sales', roleId: 'refunder', actorPrincipalId: 'system' })
    expect((await service().authorise({ subject: subject('dave'), permission: 'orders:process_refund', resource: order('sales') })).allowed).toBe(true)
    expect(await service().deleteRole({ tenantId: 'tenant-a', roleId: 'refunder', actorPrincipalId: 'system' })).toBe(true)
    expect((await service().authorise({ subject: subject('dave'), permission: 'orders:process_refund', resource: order('sales') })).allowed).toBe(false)
  })

  it('shares a resource through a grant until it is revoked', async () => {
    member('erin', 'company')
    const grantId = await service().createGrant({ grant: { resource: { type: 'orders', id: 'order-9' }, subject: { kind: 'principal', principalId: 'erin' }, permissions: ['orders:view'], expiresAt: null }, actorPrincipalId: 'alice' })
    expect((await service().authorise({ subject: subject('erin'), permission: 'orders:view', resource: order('sales', 'order-9') })).allowed).toBe(true)
    await expect(service().createGrant({ grant: { resource: { type: 'orders', id: 'order-9' }, subject: { kind: 'principal', principalId: 'erin' }, permissions: ['identity.groups:archive'], expiresAt: null }, actorPrincipalId: 'alice' })).rejects.toMatchObject({ code: 'validation-failed' })
    expect(await service().revokeGrant({ grantId, actorPrincipalId: 'alice' })).toBe(true)
    expect((await service().authorise({ subject: subject('erin'), permission: 'orders:view', resource: order('sales', 'order-9') })).allowed).toBe(false)
    expect((await outbox()).map(e => e.type)).toEqual(['authorisation.grant-created', 'authorisation.grant-revoked'])
  })

  describe('the clock, through the public server functions', () => {
    let at = new Date('2030-01-01T00:00:00.000Z')
    const minutes = (n: number) => new Date(Date.parse('2030-01-01T00:00:00.000Z') + n * 60_000)
    const signedIn = (principalId: string): AuthorisationSubject =>
      ({ principalId, authenticatedAt: '2030-01-01T00:00:00.000Z', assurance: { level: 'aal2', phishingResistant: true } })

    beforeEach(() => {
      clearAuthorisationComposition()
      provideAuthorisationDatabase({ dialect: 'postgres', pool })
      provideAuthorisationDirectory(directory)
      provideAuthorisationPermissions(PERMISSIONS)
      provideAuthorisationEventSink({ emit: (event) => { denials.push(event) } })
    })

    afterAll(() => clearAuthorisationComposition())

    it('uses the system clock when the host supplies none', async () => {
      member('gina', 'sales')
      const before = Date.now()
      const grantId = await createAuthorisationGrant({ grant: { resource: { type: 'orders', id: 'order-system' }, subject: { kind: 'principal', principalId: 'gina' }, permissions: ['orders:view'], expiresAt: new Date(Date.now() + 60_000).toISOString() }, actorPrincipalId: 'alice' })
      const { rows } = await pool.query(`select created_at from "authorisation"."grant" where grant_id = $1`, [grantId])
      expect(rows[0].created_at.getTime()).toBeGreaterThanOrEqual(before - 1000)
      expect(rows[0].created_at.getTime()).toBeLessThanOrEqual(Date.now() + 1000)
      expect((await authorise({ subject: subject('gina'), permission: 'orders:view', resource: order('sales', 'order-system') })).allowed).toBe(true)
    })

    it('decides a grant\'s expiry and a critical permission\'s authentication age by the supplied clock, and records its times', async () => {
      provideAuthorisationClock({ now: () => at })
      member('frank', 'sales')
      at = minutes(0)
      // In the past by the clock, though still in the future by the system's.
      await expect(createAuthorisationGrant({ grant: { resource: { type: 'orders', id: 'order-clock' }, subject: { kind: 'principal', principalId: 'frank' }, permissions: ['orders:view'], expiresAt: '2029-12-31T23:00:00.000Z' }, actorPrincipalId: 'alice' }))
        .rejects.toMatchObject({ code: 'validation-failed' })
      const grantId = await createAuthorisationGrant({ grant: { resource: { type: 'orders', id: 'order-clock' }, subject: { kind: 'principal', principalId: 'frank' }, permissions: ['orders:view', 'orders:purge'], expiresAt: '2030-01-01T01:00:00.000Z' }, actorPrincipalId: 'alice' })
      const { rows } = await pool.query(`select created_at from "authorisation"."grant" where grant_id = $1`, [grantId])
      expect(rows[0].created_at.toISOString()).toBe('2030-01-01T00:00:00.000Z')
      expect(await assignAuthorisationRole({ principalId: 'frank', groupId: 'sales', roleId: 'viewer', actorPrincipalId: 'system' })).toBe(true)
      const assigned = await pool.query(`select created_at from "authorisation"."role_assignment" where principal_id = 'frank' and role_id = 'viewer'`)
      expect(assigned.rows[0].created_at.toISOString()).toBe('2030-01-01T00:00:00.000Z')
      expect((await outbox()).at(-1)).toMatchObject({ type: 'authorisation.role-assigned', occurredAt: '2030-01-01T00:00:00.000Z' })

      const purge = () => authorise({ subject: signedIn('frank'), permission: 'orders:purge', resource: order('sales', 'order-clock') })
      const view = () => authorise({ subject: signedIn('frank'), permission: 'orders:view', resource: order('sales', 'order-clock') })
      at = minutes(5)
      expect(await purge()).toMatchObject({ allowed: true, via: 'grant' })
      // Twenty minutes after signing in, by the clock: too long ago for a critical permission.
      at = minutes(20)
      expect(await purge()).toMatchObject({ allowed: false, reason: 'insufficient-assurance' })
      expect(denials.at(-1)).toMatchObject({ type: 'authorisation.denied', permission: 'orders:purge', occurredAt: minutes(20).toISOString() })
      // Only the grant now: past its expiry by the clock it no longer counts, though by the system's clock it has years to run.
      await pool.query(`delete from "authorisation"."role_assignment" where principal_id = 'frank'`)
      expect(await view()).toMatchObject({ allowed: true, via: 'grant' })
      at = minutes(90)
      expect((await view()).allowed).toBe(false)
    })

    it('fails closed when the clock answers an invalid time or fails: no decision, nothing read or written', async () => {
      member('hana', 'sales')
      for (const now of [() => new Date(Number.NaN), () => 'soon' as unknown as Date, () => { throw new Error('clock down') }]) {
        provideAuthorisationClock({ now })
        reads.length = 0
        denials.length = 0
        await outbox()
        await expect(authorise({ subject: subject('hana'), permission: 'orders:view', resource: order('sales') })).rejects.toMatchObject({ name: 'AuthorisationFailure', code: 'unavailable' })
        expect(reads).toEqual([])
        await expect(assignAuthorisationRole({ principalId: 'hana', groupId: 'sales', roleId: 'viewer', actorPrincipalId: 'system' })).rejects.toMatchObject({ code: 'unavailable' })
        await expect(createAuthorisationGrant({ grant: { resource: { type: 'orders', id: 'order-bad-clock' }, subject: { kind: 'principal', principalId: 'hana' }, permissions: ['orders:view'], expiresAt: null }, actorPrincipalId: 'alice' })).rejects.toMatchObject({ code: 'unavailable' })
        expect(denials).toEqual([])
        expect(await outbox()).toEqual([])
      }
      const { rows } = await pool.query(`select 1 from "authorisation"."role_assignment" where principal_id = 'hana' union all select 1 from "authorisation"."grant" where subject_id = 'hana'`)
      expect(rows).toEqual([])
    })
  })

  it('exports what a principal holds, and erases it on closure, leaving others untouched', async () => {
    member('fay', 'company')
    member('gus', 'company')
    await service().assign({ principalId: 'fay', groupId: 'sales', roleId: 'member', actorPrincipalId: 'alice' })
    await service().assign({ principalId: 'gus', groupId: 'sales', roleId: 'member', actorPrincipalId: 'fay' })
    const grantId = await service().createGrant({ grant: { resource: { type: 'orders', id: 'order-7' }, subject: { kind: 'principal', principalId: 'fay' }, permissions: ['orders:view'], expiresAt: null }, actorPrincipalId: 'alice' })
    await service().createGrant({ grant: { resource: { type: 'orders', id: 'order-7' }, subject: { kind: 'group', groupId: 'sales' }, permissions: ['orders:view'], expiresAt: null }, actorPrincipalId: 'fay' })

    const exported = await service().exportPrincipal({ principalId: 'fay', correlationId: '01a00000-0000-7000-8000-000000000001' })
    expect(exported).toMatchObject({ principalId: 'fay', correlationId: '01a00000-0000-7000-8000-000000000001' })
    expect(exported.roleAssignments).toEqual([{ principalId: 'fay', groupId: 'sales', roleId: 'member', scope: 'group', expiresAt: null }])
    expect(exported.grants).toEqual([{ grantId, resource: { type: 'orders', id: 'order-7' }, permissions: ['orders:view'], expiresAt: null }])

    expect(await service().erasePrincipal({ principalId: 'fay', actorPrincipalId: 'iam-integration' })).toEqual({ assignments: 1, grants: 1 })
    expect((await outbox()).filter(e => e.type === 'authorisation.principal-erased')).toEqual([expect.objectContaining({ actorPrincipalId: 'iam-integration', data: { principalId: 'fay', assignments: 1, grants: 1 } })])
    const after = await service().exportPrincipal({ principalId: 'fay', correlationId: '01a00000-0000-7000-8000-000000000001' })
    expect(after.roleAssignments).toEqual([])
    expect(after.grants).toEqual([])
    // What fay did for others stays, keeping only her opaque identifier.
    expect(await service().listAssignments({ principalId: 'gus' })).toEqual([{ principalId: 'gus', groupId: 'sales', roleId: 'member', scope: 'group', expiresAt: null }])
    expect(await service().erasePrincipal({ principalId: 'fay', actorPrincipalId: 'iam-integration' })).toEqual({ assignments: 0, grants: 0 })
    expect(await outbox()).toEqual([])
  })

  it('writes each change and its event in one transaction, and relays them in order, at least once', async () => {
    member('ivy', 'sales')
    await service().assign({ principalId: 'ivy', groupId: 'sales', roleId: 'viewer', actorPrincipalId: 'system', correlationId: '01a00000-0000-7000-8000-00000000000a' })
    const db = createDatabase(pool, 'authorisation')
    const published: AuthorisationEvent[] = []
    let failNext = true
    const publish = async (event: AuthorisationEvent) => {
      if (event.type === 'authorisation.role-assigned' && event.data.principalId === 'ivy' && failNext) {
        failNext = false
        throw new Error('broker down')
      }
      published.push(event)
    }
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    // Drain what earlier tests left, stopping at ivy's event, which fails once.
    let result = await relayOutbox(db, { publish }, 1000, () => new Date())
    expect(result.failed).toBe(1)
    result = await relayOutbox(db, { publish }, 1000, () => new Date())
    expect(result.failed).toBe(0)
    error.mockRestore()
    const ivy = published.filter(e => e.type === 'authorisation.role-assigned' && e.data.principalId === 'ivy')
    expect(ivy).toEqual([expect.objectContaining({ correlationId: '01a00000-0000-7000-8000-00000000000a', actorPrincipalId: 'system' })])
    expect(await relayOutbox(db, { publish }, 1000, () => new Date())).toEqual({ published: 0, failed: 0 })
    // A change whose event cannot be written is not made.
    await expect(service().assign({ principalId: 'ivy', groupId: 'sales', roleId: 'member', actorPrincipalId: 'not an identifier!' })).rejects.toMatchObject({ code: 'validation-failed' })
    await expect(relayOutbox(db, { publish }, 0, () => new Date())).rejects.toMatchObject({ code: 'validation-failed' })
  })

  it('ends a time-limited assignment at once, before maintenance removes it', async () => {
    member('jay', 'sales')
    let at = new Date('2030-01-01T00:00:00.000Z')
    const timed = createService({
      db: createDatabase(pool, 'authorisation'),
      schemaName: 'authorisation',
      directory,
      catalogue: new Map(PERMISSIONS.map(p => [p.name, p])),
      policy: resolveAuthorisationPolicy(),
      emitDenial: async () => {},
      now: () => at,
    })
    await expect(timed.assign({ principalId: 'jay', groupId: 'sales', roleId: 'viewer', expiresAt: '2029-12-31T00:00:00.000Z', actorPrincipalId: 'system' })).rejects.toMatchObject({ reason: 'expiry-in-the-past' })
    expect(await timed.assign({ principalId: 'jay', groupId: 'sales', roleId: 'viewer', expiresAt: '2030-01-01T01:00:00.000Z', actorPrincipalId: 'system' })).toBe(true)
    const view = () => timed.authorise({ subject: { principalId: 'jay', authenticatedAt: at.toISOString(), assurance: { level: 'aal2', phishingResistant: true } }, permission: 'orders:view', resource: order('sales') })
    expect((await view()).allowed).toBe(true)
    at = new Date('2030-01-01T01:00:00.000Z')
    expect((await view()).allowed).toBe(false)
    expect(await timed.listAssignments({ principalId: 'jay' })).toEqual([{ principalId: 'jay', groupId: 'sales', roleId: 'viewer', scope: 'group', expiresAt: '2030-01-01T01:00:00.000Z' }])
  })

  describe('qualification for approvals', () => {
    beforeAll(async () => {
      // Wildcards never cover high or critical permissions: a role names them.
      await service().defineRole({ tenantId: 'tenant-a', role: { id: 'governor', name: 'Governor', permissions: [{ pattern: 'orders:process_refund' }, { pattern: 'identity.groups:archive' }] }, actorPrincipalId: 'system' })
    })

    it('qualifies whatever the session, but only while a member', async () => {
      member('frank', 'sales')
      await service().assign({ principalId: 'frank', groupId: 'sales', roleId: 'governor', actorPrincipalId: 'system' })
      expect(await service().qualifies({ principalId: 'frank', permission: 'orders:process_refund', resource: order('sales') })).toBe(true)
      member('frank', 'sales', 'ended')
      expect(await service().qualifies({ principalId: 'frank', permission: 'orders:process_refund', resource: order('sales') })).toBe(false)
    })

    it('counts who qualifies, excluding the requester, up to the limit', async () => {
      group('team', 'company')
      for (const name of ['g1', 'g2', 'g3']) {
        member(name, 'team')
        await service().assign({ principalId: name, groupId: 'team', roleId: 'governor', actorPrincipalId: 'system' })
      }
      member('g4', 'team')
      await service().assign({ principalId: 'g4', groupId: 'team', roleId: 'viewer', actorPrincipalId: 'system' })
      const count = (excluding: string[], limit = 10) => service().countQualifying({ permission: 'identity.groups:archive', resource: groupResource('team'), excludingPrincipalIds: excluding, limit })
      expect(await count([])).toBe(3)
      expect(await count(['g1'])).toBe(2)
      expect(await count([], 2)).toBe(2)
      member('g2', 'team', 'suspended')
      expect(await count(['g1'])).toBe(1)
      expect(await service().unassign({ principalId: 'g3', groupId: 'team', roleId: null, actorPrincipalId: 'system' })).toEqual(['governor'])
      expect(await count(['g1'])).toBe(0)
    })
  })
})

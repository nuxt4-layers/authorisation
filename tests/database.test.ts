import pg from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import type {
  AuthorisationActorContext,
  AuthorisationDirectory,
  AuthorisationDirectoryReadOptions,
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
import { createStore } from '../server/internal/store'
import { createTestDatabase, hasDatabase, requireDatabaseInCi } from './support/database'

requireDatabaseInCi()

const PERMISSIONS: AuthorisationPermissionDefinition[] = [
  ...AUTHORISATION_PERMISSIONS,
  { name: 'orders:view', description: 'See orders', risk: 'low' },
  { name: 'orders:process_refund', description: 'Refund an order', risk: 'high' },
  { name: 'identity.groups:archive', description: 'Archive a group', risk: 'high' },
]

describe.skipIf(!hasDatabase)('authorisation storage and decisions on PostgreSQL', () => {
  let pool: pg.Pool
  let drop: () => Promise<void>
  const events: AuthorisationEvent[] = []
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
      return { principalId, personalGroup: null, memberships: list.map(m => ({ group: groups.get(m.groupId)!, status: m.status })) }
    },
    async describeGroup(groupId, options) {
      reads.push(options.consistency)
      if (failing) throw new Error('directory down')
      return groups.get(groupId) ?? null
    },
  }

  const service = () => createService({
    store: createStore(pool, 'authorisation'),
    directory,
    catalogue: new Map(PERMISSIONS.map(p => [p.name, p])),
    policy: resolveAuthorisationPolicy(),
    emit: async (event) => { events.push(event) },
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

  beforeEach(() => {
    events.length = 0
    reads.length = 0
    failing = false
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
    expect(rows.map(r => r.table_name)).toEqual(['custom_role', 'grant', 'role_assignment', 'schema_migration'])
  })

  it('decides from stored assignments, reading the directory strongly for high-risk permissions', async () => {
    member('alice', 'sales')
    expect(await service().assign({ principalId: 'alice', groupId: 'sales', roleId: 'administrator', actorPrincipalId: 'system' })).toBe(true)
    expect(events.at(-1)).toMatchObject({ type: 'authorisation.role-assigned', subjectPrincipalId: 'alice', groupId: 'sales', roleId: 'administrator' })
    reads.length = 0
    expect(await service().authorise({ subject: subject('alice'), permission: 'orders:view', resource: order('sales') })).toMatchObject({ allowed: true, via: 'role' })
    expect(reads).toEqual(['bounded', 'bounded'])
    reads.length = 0
    expect(await service().authorise({ subject: subject('alice'), permission: 'orders:process_refund', resource: order('sales') })).toMatchObject({ allowed: false, reason: 'not-permitted' })
    expect(reads).toEqual(['strong', 'strong'])
    expect(events.at(-1)).toMatchObject({ type: 'authorisation.denied', actorPrincipalId: 'alice', permission: 'orders:process_refund', reason: 'not-permitted' })
  })

  it('ends access with the membership, and never reaches up or across', async () => {
    member('bob', 'sales')
    await service().assign({ principalId: 'bob', groupId: 'sales', roleId: 'viewer', actorPrincipalId: 'system' })
    expect((await service().authorise({ subject: subject('bob'), permission: 'orders:view', resource: order('company') })).allowed).toBe(false)
    member('bob', 'sales', 'suspended')
    expect((await service().authorise({ subject: subject('bob'), permission: 'orders:view', resource: order('sales') })).allowed).toBe(false)
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
    expect(events.map(e => e.type)).toContain('authorisation.grant-revoked')
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

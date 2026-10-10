import { readdirSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { EventHandler, H3Event } from 'h3'
import { createApp, createRouter, defineEventHandler, getRequestHeader, toWebHandler } from 'h3'
import pg from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import type { AuthorisationDirectory, AuthorisationGovernance, AuthorisationGroup, AuthorisationPermissionDefinition } from '../contracts'
import { AUTHORISATION_PERMISSIONS } from '../contracts'
import { originRejected } from '../server/internal/http'
import {
  clearAuthorisationComposition,
  provideAuthorisationClock,
  provideAuthorisationDatabase,
  provideAuthorisationDirectory,
  provideAuthorisationGovernance,
  provideAuthorisationPermissions,
  provideAuthorisationSubjectResolver,
} from '../server/utils/authorisation-composition'
import { assignAuthorisationRole, migrateAuthorisationDatabase, requireAuthorisation } from '../server/utils/authorisation-server'
import { createTestDatabase, hasDatabase, requireDatabaseInCi } from './support/database'

requireDatabaseInCi()

const API = fileURLToPath(new URL('../server/api/authorisation', import.meta.url))

/** Every endpoint file, routed as Nuxt routes it: `[param]` → `:param`, `index` dropped, method from the suffix. */
function endpointFiles(directory: string = API): { file: string, method: string, route: string }[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) return endpointFiles(path)
    const match = /^(.*)\.(get|post|patch|delete)\.ts$/.exec(relative(API, path))
    if (!match) throw new Error(`Unexpected file in server/api/authorisation: ${entry.name}`)
    const route = `/api/authorisation/${match[1]!}`.replace(/\[(\w+)\]/g, ':$1').replace(/\/index$/, '')
    return [{ file: path, method: match[2]!, route }]
  })
}

const PERMISSIONS: AuthorisationPermissionDefinition[] = [
  ...AUTHORISATION_PERMISSIONS,
  { name: 'orders:view', description: 'See orders', risk: 'low', effect: 'view' },
]
const GROUPS: Record<string, AuthorisationGroup> = {
  company: { groupId: 'company', lineage: ['company'], tenantId: 'tenant-a' },
  sales: { groupId: 'sales', lineage: ['company', 'sales'], tenantId: 'tenant-a' },
}
const MEMBERS: Record<string, string[]> = { olive: ['company'], otto: ['company'], adam: ['sales'], amy: ['sales'], mia: ['sales'], out: [] }

describe('the /api/authorisation endpoints', () => {
  it('mounts every endpoint file under a route Nuxt would give it, and never one for operators\' functions', () => {
    const routes = endpointFiles().map(endpoint => `${endpoint.method.toUpperCase()} ${endpoint.route}`).sort()
    expect(routes).toEqual([
      'GET /api/authorisation/changes/:changeId',
      'GET /api/authorisation/groups/:groupId/access',
      'GET /api/authorisation/groups/:groupId/access-review',
      'GET /api/authorisation/groups/:groupId/assignments',
      'GET /api/authorisation/groups/:groupId/changes',
      'GET /api/authorisation/groups/:groupId/grants',
      'GET /api/authorisation/me',
      'GET /api/authorisation/tenants/:tenantId/roles',
      'POST /api/authorisation/changes',
      'POST /api/authorisation/changes/:changeId/cancel',
      'POST /api/authorisation/changes/:changeId/decision',
    ])
    // Role documents, maintenance, the relay and erasure are server-only.
    expect(routes.filter(route => /import|export|maintenance|outbox|erase/.test(route))).toEqual([])
  })

  it('refuses state-changing requests from another origin, or with no base URL configured', () => {
    const event = (method: string, path: string, headers: Record<string, string>) =>
      ({ method, path, node: { req: { method, url: path, headers, originalUrl: path } }, headers: new Headers(headers) }) as unknown as H3Event
    const base = 'https://host.example'
    expect(originRejected(event('POST', '/api/authorisation/changes', { origin: base, host: 'host.example' }), base)).toBe(false)
    expect(originRejected(event('POST', '/api/authorisation/changes', { origin: 'https://evil.example', host: 'host.example' }), base)).toBe(true)
    expect(originRejected(event('POST', '/api/authorisation/changes', { referer: `${base}/groups/sales/access`, host: 'host.example' }), base)).toBe(false)
    expect(originRejected(event('POST', '/api/authorisation/changes', { host: 'host.example' }), base)).toBe(true)
    expect(originRejected(event('POST', '/api/authorisation/changes', { origin: base, host: 'host.example' }), '')).toBe(true)
    expect(originRejected(event('GET', '/api/authorisation/me', { host: 'host.example' }), '')).toBe(false)
    expect(originRejected(event('POST', '/api/other', { host: 'host.example' }), '')).toBe(false)
  })
})

describe.skipIf(!hasDatabase)('the /api/authorisation endpoints on PostgreSQL', () => {
  let pool: pg.Pool
  let drop: () => Promise<void>
  let handler: (request: Request) => Promise<Response>
  let resolverFails = false
  const at = new Date('2030-01-01T00:00:00.000Z')

  const directory: AuthorisationDirectory = {
    async resolveActor(principalId) {
      const groups = MEMBERS[principalId]
      if (!groups) return null
      return { principalId, status: 'active', personalGroup: null, memberships: groups.map(groupId => ({ group: GROUPS[groupId]!, status: 'active' as const })) }
    },
    async describeGroup(groupId) {
      return GROUPS[groupId] ?? null
    },
  }
  const governance: AuthorisationGovernance = {
    async describeGroup({ groupId, principalId }) {
      const group = GROUPS[groupId]
      if (!group) return null
      return {
        groupId,
        tenantId: group.tenantId,
        kind: 'standard',
        state: 'active',
        parentGroupId: group.lineage.at(-2) ?? null,
        rootGroupId: group.lineage[0]!,
        personalOfPrincipalId: null,
        approvals: { required: { low: 0, medium: 0, high: 1, critical: 1 }, referenceRequired: false },
        safetyPeriods: { publishedDelayHighHours: 72, publishedDelayCriticalHours: 168, approvalExpiryDays: 7, recoveryHoldHours: 72 },
        requester: { recoveryHoldUntil: null, controls: principalId === 'nobody' ? ['x'] : [] },
      }
    },
    async isOwner({ principalId, groupId }) {
      return groupId === 'company' && (principalId === 'olive' || principalId === 'otto')
    },
    async countOwners({ groupId, excluding }) {
      return groupId === 'company' ? ['olive', 'otto'].filter(o => !excluding.includes(o)).length : 0
    },
  }

  async function call(method: string, path: string, options: { as?: string, body?: unknown, aal?: 'aal1' | 'aal2', headers?: Record<string, string> } = {}) {
    const headers: Record<string, string> = { 'content-type': 'application/json', ...options.headers }
    if (options.as) headers['x-test-principal'] = `${options.as}|${options.aal ?? 'aal2'}`
    const response = await handler(new Request(`http://authorisation.test${path}`, { method, headers, body: options.body === undefined ? undefined : JSON.stringify(options.body) }))
    const text = await response.text()
    const json = text ? JSON.parse(text) : null
    return { status: response.status, data: json?.data ?? json }
  }

  const compose = () => {
    clearAuthorisationComposition()
    provideAuthorisationDatabase({ dialect: 'postgres', pool })
    provideAuthorisationDirectory(directory)
    provideAuthorisationGovernance(governance)
    provideAuthorisationPermissions(PERMISSIONS)
    provideAuthorisationClock({ now: () => at })
    provideAuthorisationSubjectResolver({
      async resolve(event) {
        if (resolverFails) throw new Error('authentication is down')
        const header = getRequestHeader(event as H3Event, 'x-test-principal')
        if (!header) return null
        const [principalId, level] = header.split('|')
        if (principalId === 'malformed') return { principalId: 'not an id!' } as never
        return { principalId: principalId!, authenticatedAt: new Date(at.getTime() - 60_000).toISOString(), assurance: { level: level as 'aal1' | 'aal2', phishingResistant: true } }
      },
    })
  }

  const justification = { reasonCode: 'new-starter', reference: null }
  const assign = (principalId: string, roleId: string, extra: object = {}) =>
    ({ request: { type: 'role.assign', target: { principalId, groupId: 'sales', roleId, ...extra }, justification } })

  beforeAll(async () => {
    const database = await createTestDatabase()
    drop = database.drop
    pool = new pg.Pool({ connectionString: database.url })
    compose()
    await migrateAuthorisationDatabase()
    for (const owner of ['olive', 'otto']) await assignAuthorisationRole({ principalId: owner, groupId: 'company', roleId: 'owner', actorPrincipalId: 'identity-events' })
    for (const admin of ['adam', 'amy']) await assignAuthorisationRole({ principalId: admin, groupId: 'sales', roleId: 'administrator', actorPrincipalId: 'olive' })
    const app = createApp()
    const router = createRouter()
    for (const endpoint of endpointFiles()) {
      const module = await import(endpoint.file) as { default: EventHandler }
      router[endpoint.method as 'get' | 'post'](endpoint.route, module.default)
    }
    router.get('/protected', defineEventHandler(async () => {
      await requireAuthorisation({ subject: { principalId: 'mia', authenticatedAt: at.toISOString(), assurance: { level: 'aal1', phishingResistant: false } }, permission: 'orders:view', resource: { type: 'orders', id: 'o1', owningGroupId: 'company' } })
      return { ok: true }
    }))
    app.use(router)
    handler = toWebHandler(app)
  })

  beforeEach(() => {
    resolverFails = false
    compose()
  })

  afterAll(async () => {
    clearAuthorisationComposition()
    await pool?.end()
    await drop?.()
  })

  it('answers unauthenticated without a subject, and unavailable when the resolver or a port fails', async () => {
    expect(await call('GET', '/api/authorisation/me')).toEqual({ status: 401, data: { code: 'unauthenticated', messageKey: 'authorisation.error.unauthenticated' } })
    resolverFails = true
    expect(await call('GET', '/api/authorisation/me', { as: 'mia' })).toMatchObject({ status: 503, data: { code: 'unavailable' } })
    resolverFails = false
    expect(await call('GET', '/api/authorisation/me', { as: 'malformed' })).toMatchObject({ status: 503, data: { code: 'unavailable' } })
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    clearAuthorisationComposition()
    expect(await call('GET', '/api/authorisation/me', { as: 'mia' })).toMatchObject({ status: 503, data: { code: 'unavailable' } })
    error.mockRestore()
  })

  it('requests a change, taking the requester only from the signed-in subject and parsing the body strictly', async () => {
    const created = await call('POST', '/api/authorisation/changes', { as: 'adam', aal: 'aal1', body: assign('mia', 'member') })
    expect(created).toMatchObject({ status: 201, data: { requesterId: 'adam', state: 'applied', route: 'none' } })
    expect(await call('POST', '/api/authorisation/changes', { as: 'adam', body: { ...assign('mia', 'member'), requesterId: 'amy' } })).toMatchObject({ status: 400, data: { code: 'validation-failed' } })
    expect(await call('POST', '/api/authorisation/changes', { as: 'adam', body: { request: { type: 'role.assign', target: { principalId: 'mia', groupId: 'sales', roleId: 'member', requesterId: 'amy' }, justification } } })).toMatchObject({ status: 400 })
    expect(await call('GET', '/api/authorisation/me', { as: 'mia' })).toMatchObject({ status: 200, data: { principalId: 'mia', assignments: [expect.objectContaining({ roleId: 'member', assignedBy: 'adam' })] } })
  })

  it('reports a rule only to someone entitled to the change, and forbidden to everyone else, without saying why', async () => {
    expect(await call('POST', '/api/authorisation/changes', { as: 'adam', body: assign('adam', 'viewer') })).toEqual({ status: 409, data: { code: 'conflict', messageKey: 'authorisation.error.conflict', reason: 'self-grant' } })
    expect(await call('POST', '/api/authorisation/changes', { as: 'mia', body: assign('amy', 'viewer') })).toEqual({ status: 403, data: { code: 'forbidden', messageKey: 'authorisation.error.forbidden' } })
    expect(await call('POST', '/api/authorisation/changes', { as: 'adam', aal: 'aal1', body: assign('mia', 'administrator') })).toMatchObject({ status: 403, data: { code: 'insufficient-assurance' } })
  })

  it('lets an approver read and decide a change by its digest, and the requester cancel one', async () => {
    const { data: change } = await call('POST', '/api/authorisation/changes', { as: 'adam', body: assign('mia', 'administrator') })
    expect(change).toMatchObject({ state: 'awaiting-approval', route: 'approvers' })
    expect(await call('GET', `/api/authorisation/changes/${change.changeId}`, { as: 'out' })).toMatchObject({ status: 403 })
    expect(await call('GET', `/api/authorisation/changes/not-a-change`, { as: 'amy' })).toMatchObject({ status: 400 })
    const { data: seen } = await call('GET', `/api/authorisation/changes/${change.changeId}`, { as: 'amy' })
    expect(await call('POST', `/api/authorisation/changes/${change.changeId}/decision`, { as: 'amy', body: { decision: 'approve', changeDigest: 'f'.repeat(64) } })).toMatchObject({ status: 409, data: { reason: 'change-differs' } })
    expect(await call('POST', `/api/authorisation/changes/${change.changeId}/decision`, { as: 'amy', body: { decision: 'approve', changeDigest: seen.changeDigest } })).toMatchObject({ status: 200, data: { state: 'applied' } })

    const { data: other } = await call('POST', '/api/authorisation/changes', { as: 'adam', body: assign('mia', 'viewer', { scope: 'group-and-descendants' }) })
    expect(await call('POST', `/api/authorisation/changes/${other.changeId}/cancel`, { as: 'amy' })).toMatchObject({ status: 403 })
    expect(await call('POST', `/api/authorisation/changes/${other.changeId}/cancel`, { as: 'adam', body: { reason: 'x' } })).toMatchObject({ status: 400 })
    expect(await call('POST', `/api/authorisation/changes/${other.changeId}/cancel`, { as: 'adam' })).toMatchObject({ status: 200, data: { state: 'cancelled' } })
  })

  it('serves a group\'s changes, assignments, access, access review and grants only under the layer\'s permissions', async () => {
    await call('POST', '/api/authorisation/changes', { as: 'adam', body: assign('mia', 'viewer', { scope: 'group-and-descendants' }) })
    expect((await call('GET', '/api/authorisation/groups/sales/changes', { as: 'mia' })).data).toHaveLength(1)
    expect((await call('GET', '/api/authorisation/groups/sales/assignments', { as: 'mia' })).data.map((a: { principalId: string }) => a.principalId).sort()).toEqual(['adam', 'amy', 'mia', 'mia'])
    expect(await call('GET', '/api/authorisation/groups/sales/access', { as: 'mia' })).toMatchObject({ status: 200, data: { defaultRoles: { member: 'member', guest: 'viewer' }, reviewIntervalDays: null } })
    expect(await call('GET', '/api/authorisation/groups/sales/access-review', { as: 'adam' })).toMatchObject({ status: 200, data: { groupId: 'sales' } })
    expect(await call('GET', '/api/authorisation/groups/sales/grants', { as: 'adam' })).toEqual({ status: 200, data: [] })
    expect(await call('GET', '/api/authorisation/tenants/tenant-a/roles', { as: 'mia' })).toMatchObject({ status: 200, data: { tenantId: 'tenant-a' } })
    for (const path of ['/groups/sales/changes', '/groups/sales/assignments', '/groups/sales/access', '/groups/sales/access-review', '/groups/sales/grants', '/tenants/tenant-a/roles', '/groups/nowhere/assignments']) {
      expect(await call('GET', `/api/authorisation${path}`, { as: 'out' }), path).toMatchObject({ status: 403, data: { code: 'forbidden' } })
    }
    expect(await call('GET', '/api/authorisation/groups/bad%20id/assignments', { as: 'mia' })).toMatchObject({ status: 400 })
  })

  it('lets requireAuthorisation answer only coarse errors', async () => {
    expect(await call('GET', '/protected')).toEqual({ status: 403, data: { code: 'forbidden', messageKey: 'authorisation.error.forbidden' } })
  })
})

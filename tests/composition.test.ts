import { afterEach, describe, expect, it, vi } from 'vitest'
import type { AuthorisationDenialEvent } from '../contracts'
import { AuthorisationCompositionError, AuthorisationFailure, DEFAULT_AUTHORISATION_POLICY } from '../contracts'
import { timeFrom } from '../server/internal/clock'
import {
  clearAuthorisationComposition,
  emitAuthorisationDenial,
  provideAuthorisationClock,
  provideAuthorisationDatabase,
  provideAuthorisationDirectory,
  provideAuthorisationEventSink,
  provideAuthorisationGovernance,
  provideAuthorisationPermissions,
  provideAuthorisationSubjectResolver,
  provideAuthorisationPolicy,
  useAuthorisationCatalogue,
  useAuthorisationClock,
  useAuthorisationDatabase,
  useAuthorisationDirectory,
  useAuthorisationGovernance,
  useAuthorisationPolicy,
  useAuthorisationSubjectResolver,
} from '../server/utils/authorisation-composition'

const pool = { query: vi.fn(), connect: vi.fn(), end: vi.fn() }
const directory = { resolveActor: vi.fn(), describeGroup: vi.fn() }

const event: AuthorisationDenialEvent = {
  type: 'authorisation.denied',
  occurredAt: '2026-10-08T12:00:00.000Z',
  actorPrincipalId: 'principal-1',
  groupId: 'group-1',
  resource: { type: 'orders', id: 'order-1' },
  permission: 'orders:view',
  reason: 'not-permitted',
}

afterEach(() => {
  clearAuthorisationComposition()
  vi.restoreAllMocks()
})

describe('Authorisation composition ports', () => {
  it('fails closed when the database port is absent', () => {
    expect(() => useAuthorisationDatabase()).toThrow(AuthorisationCompositionError)
    expect(() => useAuthorisationDatabase()).toThrow(/AuthorisationDatabase/)
  })

  it('fails closed when the directory port is absent', () => {
    expect(() => useAuthorisationDirectory()).toThrow(AuthorisationCompositionError)
    expect(() => useAuthorisationDirectory()).toThrow(/AuthorisationDirectory/)
  })

  it('supplies the database with the default capability-owned schema', () => {
    provideAuthorisationDatabase({ dialect: 'postgres', pool })
    expect(useAuthorisationDatabase()).toEqual({ dialect: 'postgres', pool, schema: 'authorisation' })
  })

  it.each([
    ['a non-postgres dialect', { dialect: 'mysql', pool }],
    ['a pool without query()', { dialect: 'postgres', pool: {} }],
    ['an unsafe schema name', { dialect: 'postgres', pool, schema: 'authz; drop schema public' }],
    ['an upper-case schema name', { dialect: 'postgres', pool, schema: 'Authorisation' }],
  ])('rejects %s', (_label, input) => {
    expect(() => provideAuthorisationDatabase(input as never)).toThrow(TypeError)
    expect(() => useAuthorisationDatabase()).toThrow(AuthorisationCompositionError)
  })

  it('fails closed when the governance port or the subject resolver is absent, and refuses malformed ones', () => {
    expect(() => useAuthorisationGovernance()).toThrow(/AuthorisationGovernance/)
    expect(() => useAuthorisationSubjectResolver()).toThrow(/AuthorisationSubjectResolver/)
    expect(() => provideAuthorisationGovernance({ describeGroup: vi.fn(), isOwner: vi.fn() } as never)).toThrow(TypeError)
    expect(() => provideAuthorisationSubjectResolver({} as never)).toThrow(TypeError)
    const governance = { describeGroup: vi.fn(), isOwner: vi.fn(), countOwners: vi.fn() }
    const resolver = { resolve: vi.fn() }
    provideAuthorisationGovernance(governance)
    provideAuthorisationSubjectResolver(resolver)
    expect(useAuthorisationGovernance()).toBe(governance)
    expect(useAuthorisationSubjectResolver()).toBe(resolver)
    clearAuthorisationComposition()
    expect(() => useAuthorisationGovernance()).toThrow(AuthorisationCompositionError)
  })

  it('supplies the directory', () => {
    provideAuthorisationDirectory(directory)
    expect(useAuthorisationDirectory()).toBe(directory)
  })

  it('rejects a directory, or event sink, without the required functions', () => {
    expect(() => provideAuthorisationDirectory({ resolveActor: vi.fn() } as never)).toThrow(TypeError)
    expect(() => provideAuthorisationEventSink({} as never)).toThrow(TypeError)
  })

  it('uses the secure default policy when the host supplies none', () => {
    expect(useAuthorisationPolicy()).toEqual(DEFAULT_AUTHORISATION_POLICY)
  })

  it('validates host policy when it is supplied, not when it is first used', () => {
    expect(() => provideAuthorisationPolicy({ assurance: { high: { minimumLevel: 'aal1' } } })).toThrow()
    provideAuthorisationPolicy({ externalGrants: true })
    expect(useAuthorisationPolicy().externalGrants).toBe(true)
  })
})

describe('Authorisation permission catalogue', () => {
  it('always contains the layer\'s own permissions', () => {
    expect(useAuthorisationCatalogue().has('authorisation.roles:manage')).toBe(true)
  })

  it('adds domain permissions from several capabilities', () => {
    provideAuthorisationPermissions([{ name: 'orders:view', description: 'See orders', risk: 'low' }])
    provideAuthorisationPermissions([{ name: 'notes:view', description: 'Read notes', risk: 'low' }])
    expect(useAuthorisationCatalogue().get('orders:view')?.risk).toBe('low')
    expect(useAuthorisationCatalogue().has('notes:view')).toBe(true)
  })

  it('accepts an identical redefinition but refuses a conflicting one', () => {
    provideAuthorisationPermissions([{ name: 'orders:view', description: 'See orders', risk: 'low' }])
    expect(() => provideAuthorisationPermissions([{ name: 'orders:view', description: 'See orders', risk: 'low' }])).not.toThrow()
    expect(() => provideAuthorisationPermissions([{ name: 'orders:view', description: 'See orders', risk: 'medium' }])).toThrow(TypeError)
    expect(() => provideAuthorisationPermissions([{ name: 'orders:view', description: 'See orders', risk: 'low', effect: 'view' }])).toThrow(TypeError)
  })

  it('records each permission\'s effect, change unless declared', () => {
    provideAuthorisationPermissions([
      { name: 'orders:view', description: 'See orders', risk: 'low', effect: 'view' },
      { name: 'orders:create', description: 'Place orders', risk: 'medium' },
    ])
    expect(useAuthorisationCatalogue().get('orders:view')?.effect).toBe('view')
    expect(useAuthorisationCatalogue().get('orders:create')?.effect).toBe('change')
    expect(useAuthorisationCatalogue().get('authorisation.roles:view')?.effect).toBe('view')
  })

  it('refuses an invalid definition and adds nothing from that call', () => {
    expect(() => provideAuthorisationPermissions([
      { name: 'orders:view', description: 'See orders', risk: 'low' },
      { name: 'Orders:Delete', description: 'x', risk: 'critical' },
    ])).toThrow()
    expect(useAuthorisationCatalogue().has('orders:view')).toBe(false)
  })

  it('refuses a role that names a permission missing from the catalogue, whichever is supplied first', () => {
    expect(() => provideAuthorisationPolicy({ roles: { administrator: [{ pattern: 'orders:process_refnd' }] } })).toThrow(/not in the catalogue/)
    provideAuthorisationPermissions([{ name: 'orders:process_refund', description: 'Refund', risk: 'high' }])
    expect(() => provideAuthorisationPolicy({ roles: { administrator: [{ pattern: 'orders:process_refund' }] } })).not.toThrow()
  })
})

describe('Authorisation events', () => {
  it('treats a missing event sink as a no-op', async () => {
    await expect(emitAuthorisationDenial(event)).resolves.toBeUndefined()
  })

  it('delivers events to the supplied sink', async () => {
    const emit = vi.fn()
    provideAuthorisationEventSink({ emit })
    await emitAuthorisationDenial(event)
    expect(emit).toHaveBeenCalledWith(event)
  })

  it('never lets a failing event sink change the operation outcome', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    provideAuthorisationEventSink({ emit: () => Promise.reject(new Error('sink down')) })
    await expect(emitAuthorisationDenial(event)).resolves.toBeUndefined()
    expect(error).toHaveBeenCalledOnce()
    expect(String(error.mock.calls[0])).toContain('authorisation.denied')
  })
})

describe('Authorisation clock', () => {
  it('uses the system clock when the host supplies none, and the host\'s clock when it does', () => {
    const before = Date.now()
    const now = timeFrom(useAuthorisationClock())
    expect(now.getTime()).toBeGreaterThanOrEqual(before)
    expect(now.getTime()).toBeLessThanOrEqual(Date.now())
    expect(() => provideAuthorisationClock({} as never)).toThrow(TypeError)
    provideAuthorisationClock({ now: () => new Date('2030-01-02T03:04:05Z') })
    expect(timeFrom(useAuthorisationClock()).toISOString()).toBe('2030-01-02T03:04:05.000Z')
    clearAuthorisationComposition()
    expect(Math.abs(timeFrom(useAuthorisationClock()).getTime() - Date.now())).toBeLessThan(1000)
  })

  it('fails closed on a clock that throws or answers anything but a valid Date', () => {
    for (const now of [() => new Date(Number.NaN), () => Date.now() as unknown as Date, () => null as unknown as Date, () => { throw new Error('down') }]) {
      let failure: unknown
      try {
        timeFrom({ now })
      }
      catch (error) {
        failure = error
      }
      expect(failure).toBeInstanceOf(AuthorisationFailure)
      expect((failure as AuthorisationFailure).code).toBe('unavailable')
    }
  })
})

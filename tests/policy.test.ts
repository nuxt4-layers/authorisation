import { describe, expect, it } from 'vitest'
import { conditionSchema, DEFAULT_AUTHORISATION_POLICY, resolveAuthorisationPolicy, roleDefinitionSchema } from '../contracts'

describe('Authorisation policy', () => {
  it('resolves to the secure defaults when nothing is supplied', () => {
    expect(resolveAuthorisationPolicy()).toEqual(DEFAULT_AUTHORISATION_POLICY)
  })

  it('keeps information inside its tenant by default', () => {
    expect(DEFAULT_AUTHORISATION_POLICY.externalGrants).toBe(false)
  })

  it('makes personal-group rights an explicit, configurable setting', () => {
    expect(DEFAULT_AUTHORISATION_POLICY.personalGroupRole).toBe('owner')
    expect(resolveAuthorisationPolicy({ personalGroupRole: null }).personalGroupRole).toBeNull()
    expect(() => resolveAuthorisationPolicy({ personalGroupRole: 'superuser' } as never)).toThrow()
  })

  it('accepts tightening', () => {
    const policy = resolveAuthorisationPolicy({ assurance: { medium: { minimumLevel: 'aal2' }, critical: { maxAuthenticationAgeSeconds: 300 } } })
    expect(policy.assurance.medium.minimumLevel).toBe('aal2')
    expect(policy.assurance.critical.maxAuthenticationAgeSeconds).toBe(300)
  })

  it.each([
    ['high below aal2', { assurance: { high: { minimumLevel: 'aal1' as const } } }],
    ['critical below aal2', { assurance: { critical: { minimumLevel: 'aal1' as const } } }],
    ['critical without a re-authentication window', { assurance: { critical: { maxAuthenticationAgeSeconds: null } } }],
    ['critical with a window over an hour', { assurance: { critical: { maxAuthenticationAgeSeconds: 7200 } } }],
    ['a level weaker than the one below', { assurance: { medium: { phishingResistant: true } } }],
    ['an unknown key', { superuser: true }],
    ['an unknown role', { roles: { superuser: [{ pattern: '*' }] } }],
    ['a malformed pattern', { roles: { viewer: [{ pattern: 'orders:*:view' }] } }],
  ])('refuses %s', (_label, input) => {
    expect(() => resolveAuthorisationPolicy(input as never)).toThrow()
  })

  it('allows dropping the phishing-resistant requirement for critical (documented risk treatment)', () => {
    expect(resolveAuthorisationPolicy({ assurance: { critical: { phishingResistant: false } } }).assurance.critical.phishingResistant).toBe(false)
  })
})

describe('Role and condition schemas', () => {
  it('accepts a well-formed custom role', () => {
    expect(() => roleDefinitionSchema.parse({
      id: 'shop-manager',
      name: 'Shop manager',
      permissions: [{ pattern: 'orders:*' }, { pattern: 'orders:process_refund', when: [{ attribute: 'resource.attributes.total', operator: 'not-equals', value: 0 }] }],
    })).not.toThrow()
  })

  it.each([
    ['an upper-case ID', { id: 'Admin', name: 'x', permissions: [] }],
    ['an extra key', { id: 'x', name: 'x', permissions: [], superuser: true }],
  ])('refuses a role with %s', (_label, input) => {
    expect(() => roleDefinitionSchema.parse(input)).toThrow()
  })

  it.each([
    ['a list for equals', { attribute: 'resource.attributes.status', operator: 'equals', value: ['a'] }],
    ['a scalar for in', { attribute: 'resource.attributes.status', operator: 'in', value: 'a' }],
    ['an arbitrary path', { attribute: 'subject.principalId', operator: 'equals', value: 'a' }],
    ['a nested path', { attribute: 'resource.attributes.a.b', operator: 'equals', value: 'a' }],
    ['an unknown reference', { attribute: 'resource.attributes.a', operator: 'equals', value: { ref: 'subject.roles' } }],
  ])('refuses a condition with %s', (_label, input) => {
    expect(() => conditionSchema.parse(input)).toThrow()
  })
})

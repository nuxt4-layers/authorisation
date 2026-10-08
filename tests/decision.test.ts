import { describe, expect, it } from 'vitest'
import type {
  AuthorisationActorContext,
  AuthorisationGrant,
  AuthorisationPermissionDefinition,
  AuthorisationResource,
  AuthorisationRoleAssignment,
  AuthorisationRoleDefinition,
  AuthorisationSubject,
} from '../contracts'
import { AUTHORISATION_PERMISSIONS, DEFAULT_AUTHORISATION_POLICY, resolveAuthorisationPolicy } from '../contracts'
import type { AuthorisationFacts } from '../server/internal/decide'
import { decideAuthorisation } from '../server/internal/decide'

/*
 * Fixture world:
 *
 *   company-a ── london ── sales        (tenant A)
 *   company-b                           (tenant B)
 *   personal-alice, personal-bob        (personal groups)
 */
const LINEAGE: Record<string, string[]> = {
  'company-a': ['company-a'],
  'london': ['company-a', 'london'],
  'sales': ['company-a', 'london', 'sales'],
  'company-b': ['company-b'],
  'personal-alice': ['personal-alice'],
  'personal-bob': ['personal-bob'],
}

const PERMISSIONS: AuthorisationPermissionDefinition[] = [
  ...AUTHORISATION_PERMISSIONS,
  { name: 'orders:view', description: 'See orders', risk: 'low' },
  { name: 'orders:create', description: 'Place orders', risk: 'medium' },
  { name: 'orders:update', description: 'Change orders', risk: 'medium' },
  { name: 'orders:process_refund', description: 'Refund an order', risk: 'high' },
  { name: 'orders:delete', description: 'Delete an order', risk: 'critical' },
  { name: 'notes:view', description: 'Read notes', risk: 'low' },
  { name: 'notes:update', description: 'Edit notes', risk: 'medium' },
]
const catalogue = new Map(PERMISSIONS.map(p => [p.name, p]))

const NOW = new Date('2026-10-08T12:00:00.000Z')

const strong: AuthorisationSubject = {
  principalId: 'alice',
  authenticatedAt: '2026-10-08T11:58:00.000Z',
  assurance: { level: 'aal2', phishingResistant: true },
}

const membership = (groupId: string) => ({ groupId, lineage: LINEAGE[groupId]! })

const alice = (...groups: string[]): AuthorisationActorContext =>
  ({ principalId: 'alice', personalGroupId: 'personal-alice', memberships: groups.map(membership) })

const order = (owningGroupId: string, extra: Partial<AuthorisationResource> = {}): AuthorisationResource =>
  ({ type: 'orders', id: 'order-1', owningGroupId, ...extra })

const assign = (groupId: string, roleId: string, principalId = 'alice'): AuthorisationRoleAssignment =>
  ({ principalId, groupId, roleId })

function decide(overrides: Partial<AuthorisationFacts> & { resource: AuthorisationResource }) {
  return decideAuthorisation({
    subject: strong,
    actor: alice(),
    permission: 'orders:view',
    resourceLineage: LINEAGE[overrides.resource.owningGroupId] ?? null,
    assignments: [],
    customRoles: new Map(),
    grants: [],
    catalogue,
    policy: DEFAULT_AUTHORISATION_POLICY,
    now: NOW,
    ...overrides,
  })
}

describe('decision: deny by default', () => {
  it('refuses a member with no role', () => {
    expect(decide({ actor: alice('sales'), resource: order('sales') }))
      .toMatchObject({ allowed: false, reason: 'not-permitted' })
  })

  it('refuses a permission missing from the catalogue, even for an owner', () => {
    const decision = decide({ actor: alice('sales'), assignments: [assign('sales', 'owner')], permission: 'orders:veiw', resource: order('sales') })
    expect(decision).toMatchObject({ allowed: false, reason: 'unknown-permission' })
  })

  it('refuses a permission that does not belong to the resource type', () => {
    const decision = decide({ actor: alice('sales'), assignments: [assign('sales', 'owner')], permission: 'notes:view', resource: order('sales') })
    expect(decision).toMatchObject({ allowed: false, reason: 'unknown-permission' })
  })

  it('refuses when the directory does not know the principal', () => {
    expect(decide({ actor: null, resource: order('sales') })).toMatchObject({ allowed: false, reason: 'unknown-subject' })
  })

  it('refuses when the directory answers for a different principal', () => {
    const bob = { ...alice('sales'), principalId: 'bob' }
    expect(decide({ actor: bob, assignments: [assign('sales', 'owner')], resource: order('sales') }))
      .toMatchObject({ allowed: false, reason: 'unknown-subject' })
  })

  it('refuses when the owning group is unknown or its lineage does not end at it', () => {
    expect(decide({ resource: order('ghost') })).toMatchObject({ reason: 'unknown-group' })
    expect(decide({ resource: order('sales'), resourceLineage: LINEAGE.london! })).toMatchObject({ reason: 'unknown-group' })
    expect(decide({ resource: order('sales'), resourceLineage: [] })).toMatchObject({ reason: 'unknown-group' })
  })
})

describe('decision: roles in groups', () => {
  it('allows what a role covers in the owning group', () => {
    expect(decide({ actor: alice('sales'), assignments: [assign('sales', 'viewer')], resource: order('sales') }))
      .toEqual({ allowed: true, permission: 'orders:view', via: 'role' })
  })

  it('refuses what the role does not cover', () => {
    const decision = decide({ actor: alice('sales'), assignments: [assign('sales', 'viewer')], permission: 'orders:update', resource: order('sales') })
    expect(decision).toMatchObject({ allowed: false, reason: 'not-permitted' })
  })

  it('lets a role in an ancestor group reach resources of its descendants', () => {
    const decision = decide({ actor: alice('company-a'), assignments: [assign('company-a', 'administrator')], permission: 'orders:update', resource: order('sales') })
    expect(decision).toMatchObject({ allowed: true, via: 'role' })
  })

  it('never lets a role in a descendant group reach its ancestors', () => {
    const decision = decide({ actor: alice('sales', 'company-a'), assignments: [assign('sales', 'administrator')], resource: order('company-a') })
    expect(decision).toMatchObject({ allowed: false, reason: 'not-permitted' })
  })

  it('never lets a role in a sibling group reach across', () => {
    const decision = decide({ actor: alice('london'), assignments: [assign('london', 'owner')], resource: order('company-a') })
    expect(decision).toMatchObject({ allowed: false })
  })

  it('ignores role assignments that belong to someone else', () => {
    const decision = decide({ actor: alice('sales'), assignments: [assign('sales', 'owner', 'bob')], resource: order('sales') })
    expect(decision).toMatchObject({ allowed: false, reason: 'not-permitted' })
  })

  it('evaluates a tenant\'s custom roles, and only that tenant\'s', () => {
    const auditor: AuthorisationRoleDefinition = { id: 'auditor', name: 'Auditor', permissions: [{ pattern: 'orders:view' }] }
    const customRoles = new Map([['company-a', new Map([['auditor', auditor]])]])
    expect(decide({ actor: alice('sales'), assignments: [assign('sales', 'auditor')], customRoles, resource: order('sales') }))
      .toMatchObject({ allowed: true, via: 'role' })
    const elsewhere = new Map([['company-b', new Map([['auditor', auditor]])]])
    expect(decide({ actor: alice('sales'), assignments: [assign('sales', 'auditor')], customRoles: elsewhere, resource: order('sales') }))
      .toMatchObject({ allowed: false })
  })

  it('resolves built-in role IDs before custom ones', () => {
    const impostor: AuthorisationRoleDefinition = { id: 'viewer', name: 'Viewer', permissions: [{ pattern: '*' }] }
    const customRoles = new Map([['company-a', new Map([['viewer', impostor]])]])
    const decision = decide({ actor: alice('sales'), assignments: [assign('sales', 'viewer')], customRoles, permission: 'orders:update', resource: order('sales') })
    expect(decision).toMatchObject({ allowed: false })
  })
})

describe('decision: tenant isolation', () => {
  it('never lets a role in one tenant reach another tenant', () => {
    const decision = decide({ actor: alice('company-a', 'company-b'), assignments: [assign('company-a', 'owner')], resource: order('company-b') })
    expect(decision).toMatchObject({ allowed: false, reason: 'not-permitted' })
  })

  it('holds even when the client claims a group: only the resource\'s own lineage counts', () => {
    // Alice owns company-a; the resource belongs to company-b whatever the request says.
    const decision = decide({ actor: alice('company-a'), assignments: [assign('company-a', 'owner')], resource: order('company-b'), resourceLineage: LINEAGE['company-b']! })
    expect(decision).toMatchObject({ allowed: false })
  })
})

describe('decision: leaving a group ends access', () => {
  const assignments = [assign('company-a', 'administrator')]

  it('allows while a member', () => {
    expect(decide({ actor: alice('company-a'), assignments, resource: order('sales') })).toMatchObject({ allowed: true })
  })

  it('refuses once the directory no longer lists the membership, though the assignment remains', () => {
    expect(decide({ actor: alice('company-b'), assignments, resource: order('sales') }))
      .toMatchObject({ allowed: false, reason: 'not-permitted' })
  })

  it('takes away the resources the leaver created, too', () => {
    const own = order('sales', { ownerPrincipalId: 'alice' })
    expect(decide({ actor: alice('sales'), permission: 'orders:update', resource: own }))
      .toMatchObject({ allowed: true, via: 'resource-owner' })
    expect(decide({ actor: alice('company-b'), permission: 'orders:update', resource: own }))
      .toMatchObject({ allowed: false, reason: 'not-permitted' })
  })

  it('takes away grants made to the leaver as a principal, unless external grants are allowed', () => {
    const grants: AuthorisationGrant[] = [{ resource: { type: 'orders', id: 'order-1' }, subject: { kind: 'principal', principalId: 'alice' }, permissions: ['orders:view'], expiresAt: null }]
    expect(decide({ actor: alice('sales'), grants, resource: order('sales') })).toMatchObject({ allowed: true, via: 'grant' })
    expect(decide({ actor: alice(), grants, resource: order('sales') })).toMatchObject({ allowed: false })
    const policy = resolveAuthorisationPolicy({ externalGrants: true })
    expect(decide({ actor: alice(), grants, policy, resource: order('sales') })).toMatchObject({ allowed: true, via: 'grant' })
  })
})

describe('decision: personal groups', () => {
  it('makes every principal the owner of their personal group', () => {
    const decision = decide({ permission: 'orders:update', resource: order('personal-alice') })
    expect(decision).toMatchObject({ allowed: true, via: 'role' })
  })

  it('gives nobody else access to it', () => {
    const decision = decide({ actor: alice('sales'), resource: order('personal-bob') })
    expect(decision).toMatchObject({ allowed: false, reason: 'not-permitted' })
  })
})

describe('decision: grants', () => {
  const grant = (subject: AuthorisationGrant['subject'], extra: Partial<AuthorisationGrant> = {}): AuthorisationGrant =>
    ({ resource: { type: 'orders', id: 'order-1' }, subject, permissions: ['orders:view'], expiresAt: null, ...extra })

  it('allows only members of a granted group', () => {
    const grants = [grant({ kind: 'group', groupId: 'london' })]
    expect(decide({ actor: alice('london'), grants, resource: order('sales') })).toMatchObject({ allowed: true, via: 'grant' })
    expect(decide({ actor: alice('company-a'), grants, resource: order('sales') })).toMatchObject({ allowed: false })
  })

  it('keeps group grants inside the resource\'s tenant unless external grants are allowed', () => {
    const external = resolveAuthorisationPolicy({ externalGrants: true })
    const toCompanyB = [grant({ kind: 'group', groupId: 'company-b' })]
    expect(decide({ actor: alice('company-b'), grants: toCompanyB, resource: order('sales') })).toMatchObject({ allowed: false })
    expect(decide({ actor: alice('company-b'), grants: toCompanyB, policy: external, resource: order('sales') })).toMatchObject({ allowed: true, via: 'grant' })
    // A personal group is its own tenant, so it cannot be used to slip past the rule.
    const toPersonal = [grant({ kind: 'group', groupId: 'personal-alice' })]
    expect(decide({ grants: toPersonal, resource: order('sales') })).toMatchObject({ allowed: false })
    expect(decide({ grants: toPersonal, policy: external, resource: order('sales') })).toMatchObject({ allowed: true })
  })

  it('covers only the named permissions on the named resource', () => {
    const grants = [grant({ kind: 'principal', principalId: 'alice' })]
    expect(decide({ actor: alice('sales'), grants, permission: 'orders:update', resource: order('sales') })).toMatchObject({ allowed: false })
    expect(decide({ actor: alice('sales'), grants, resource: order('sales', { id: 'order-2' }) })).toMatchObject({ allowed: false })
  })

  it('stops at its expiry', () => {
    const grants = [grant({ kind: 'principal', principalId: 'alice' }, { expiresAt: '2026-10-08T12:00:00.000Z' })]
    expect(decide({ actor: alice('sales'), grants, resource: order('sales') })).toMatchObject({ allowed: false })
    const malformed = [grant({ kind: 'principal', principalId: 'alice' }, { expiresAt: 'tomorrow' })]
    expect(decide({ actor: alice('sales'), grants: malformed, resource: order('sales') })).toMatchObject({ allowed: false })
  })
})

describe('decision: wildcards and risk', () => {
  it('never lets a wildcard cover a high or critical permission', () => {
    const assignments = [assign('sales', 'owner')]
    expect(decide({ actor: alice('sales'), assignments, permission: 'orders:process_refund', resource: order('sales') }))
      .toMatchObject({ allowed: false, reason: 'not-permitted' })
  })

  it('allows a high permission that a role names explicitly', () => {
    const policy = resolveAuthorisationPolicy({ roles: { administrator: [{ pattern: '*' }, { pattern: 'orders:process_refund' }] } })
    const decision = decide({ actor: alice('sales'), assignments: [assign('sales', 'administrator')], permission: 'orders:process_refund', policy, resource: order('sales') })
    expect(decision).toMatchObject({ allowed: true })
  })

  it('demands aal2 for high permissions', () => {
    const policy = resolveAuthorisationPolicy({ roles: { administrator: [{ pattern: 'orders:process_refund' }] } })
    const weak = { ...strong, assurance: { level: 'aal1' as const, phishingResistant: false } }
    const decision = decide({ subject: weak, actor: alice('sales'), assignments: [assign('sales', 'administrator')], permission: 'orders:process_refund', policy, resource: order('sales') })
    expect(decision).toEqual({
      allowed: false,
      permission: 'orders:process_refund',
      reason: 'insufficient-assurance',
      requirement: { minimumLevel: 'aal2', phishingResistant: false, maxAuthenticationAgeSeconds: null },
    })
  })

  it('demands a recent, phishing-resistant authentication for critical permissions', () => {
    const policy = resolveAuthorisationPolicy({ roles: { owner: [{ pattern: 'orders:delete' }] } })
    const facts = { actor: alice('sales'), assignments: [assign('sales', 'owner')], permission: 'orders:delete', policy, resource: order('sales') }
    expect(decide(facts)).toMatchObject({ allowed: true })
    expect(decide({ ...facts, subject: { ...strong, authenticatedAt: '2026-10-08T11:44:59.000Z' } }))
      .toMatchObject({ reason: 'insufficient-assurance' })
    expect(decide({ ...facts, subject: { ...strong, assurance: { level: 'aal2', phishingResistant: false } } }))
      .toMatchObject({ reason: 'insufficient-assurance' })
    expect(decide({ ...facts, subject: { ...strong, authenticatedAt: 'not a date' } }))
      .toMatchObject({ reason: 'insufficient-assurance' })
  })

  it('does not reveal an assurance requirement for something that is not permitted anyway', () => {
    const weak = { ...strong, assurance: { level: 'aal1' as const, phishingResistant: false } }
    expect(decide({ subject: weak, actor: alice('sales'), permission: 'orders:process_refund', resource: order('sales') }))
      .toMatchObject({ reason: 'not-permitted', requirement: null })
  })
})

describe('decision: conditions', () => {
  const editor = (when: NonNullable<AuthorisationRoleDefinition['permissions'][number]['when']>): AuthorisationRoleDefinition =>
    ({ id: 'editor', name: 'Editor', permissions: [{ pattern: 'orders:update', when }] })
  // A resource owner who may only view, so ownership does not mask the conditions.
  const policy = resolveAuthorisationPolicy({ resourceOwnerRole: 'viewer' })
  const facts = (role: AuthorisationRoleDefinition, resource: AuthorisationResource) => ({
    policy,
    actor: alice('sales'),
    assignments: [assign('sales', 'editor')],
    customRoles: new Map([['company-a', new Map([['editor', role]])]]),
    permission: 'orders:update',
    resource,
  })

  it('applies a role entry only when every condition holds', () => {
    const role = editor([
      { attribute: 'resource.attributes.status', operator: 'in', value: ['draft', 'open'] },
      { attribute: 'resource.ownerPrincipalId', operator: 'equals', value: { ref: 'subject.principalId' } },
    ])
    expect(decide(facts(role, order('sales', { ownerPrincipalId: 'alice', attributes: { status: 'draft' } })))).toMatchObject({ allowed: true })
    expect(decide(facts(role, order('sales', { ownerPrincipalId: 'alice', attributes: { status: 'closed' } })))).toMatchObject({ allowed: false })
    expect(decide(facts(role, order('sales', { ownerPrincipalId: 'bob', attributes: { status: 'draft' } })))).toMatchObject({ allowed: false })
  })

  it('treats a missing attribute as failing, even for negative operators', () => {
    const role = editor([{ attribute: 'resource.attributes.locked', operator: 'not-equals', value: true }])
    expect(decide(facts(role, order('sales')))).toMatchObject({ allowed: false })
    expect(decide(facts(role, order('sales', { attributes: { locked: false } })))).toMatchObject({ allowed: true })
  })

  it('does not read inherited properties as attributes', () => {
    const role = editor([{ attribute: 'resource.attributes.constructor', operator: 'not-equals', value: null }])
    expect(decide(facts(role, order('sales', { attributes: {} })))).toMatchObject({ allowed: false })
  })
})

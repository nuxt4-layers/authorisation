import { describe, expect, it } from 'vitest'
import type {
  AuthorisationActorContext,
  AuthorisationGrant,
  AuthorisationGroup,
  AuthorisationMembershipStatus,
  AuthorisationPermissionDefinition,
  AuthorisationResource,
  AuthorisationRoleAssignment,
  AuthorisationRoleAssignmentScope,
  AuthorisationRoleDefinition,
  AuthorisationSubject,
} from '../contracts'
import { AUTHORISATION_PERMISSIONS, DEFAULT_AUTHORISATION_POLICY, resolveAuthorisationPolicy } from '../contracts'
import type { AuthorisationFacts } from '../server/internal/decide'
import { decideAuthorisation } from '../server/internal/decide'

/*
 * Fixture world (a forest of single-parent trees; tenants are separate from roots):
 *
 *   tenant-a:  company-a ── london ── sales
 *              club-x                              (a second root in the same tenant)
 *   tenant-b:  company-b
 *   personal groups: personal-alice (tenant personal-alice), personal-bob (tenant personal-bob)
 */
const GROUPS: Record<string, AuthorisationGroup> = {
  'company-a': { groupId: 'company-a', lineage: ['company-a'], tenantId: 'tenant-a' },
  'london': { groupId: 'london', lineage: ['company-a', 'london'], tenantId: 'tenant-a' },
  'sales': { groupId: 'sales', lineage: ['company-a', 'london', 'sales'], tenantId: 'tenant-a' },
  'club-x': { groupId: 'club-x', lineage: ['club-x'], tenantId: 'tenant-a' },
  'company-b': { groupId: 'company-b', lineage: ['company-b'], tenantId: 'tenant-b' },
  'personal-alice': { groupId: 'personal-alice', lineage: ['personal-alice'], tenantId: 'personal-alice' },
  'personal-bob': { groupId: 'personal-bob', lineage: ['personal-bob'], tenantId: 'personal-bob' },
}

const PERMISSIONS: AuthorisationPermissionDefinition[] = [
  ...AUTHORISATION_PERMISSIONS,
  { name: 'orders:view', description: 'See orders', risk: 'low', effect: 'view' },
  { name: 'orders:create', description: 'Place orders', risk: 'medium', effect: 'change' },
  { name: 'orders:update', description: 'Change orders', risk: 'medium', effect: 'change' },
  { name: 'orders:view_history', description: 'See who changed an order', risk: 'medium', effect: 'view' },
  { name: 'orders:view_payment', description: 'See an order\'s payment details', risk: 'high', effect: 'view' },
  { name: 'orders:export', description: 'Download orders', risk: 'low', effect: 'change' },
  { name: 'orders:process_refund', description: 'Refund an order', risk: 'high', effect: 'change' },
  { name: 'orders:delete', description: 'Delete an order', risk: 'critical', effect: 'change' },
  { name: 'notes:view', description: 'Read notes', risk: 'low', effect: 'view' },
]
const catalogue = new Map(PERMISSIONS.map(p => [p.name, p]))

const NOW = new Date('2026-10-08T12:00:00.000Z')

const strong: AuthorisationSubject = {
  principalId: 'alice',
  authenticatedAt: '2026-10-08T11:58:00.000Z',
  assurance: { level: 'aal2', phishingResistant: true },
}

/** Alice, with the given direct memberships (active unless stated). */
const alice = (...memberships: (string | [string, AuthorisationMembershipStatus])[]): AuthorisationActorContext => ({
  principalId: 'alice',
  status: 'active',
  personalGroup: GROUPS['personal-alice']!,
  memberships: memberships.map((m) => {
    const [groupId, status] = typeof m === 'string' ? [m, 'active' as const] : m
    return { group: GROUPS[groupId]!, status }
  }),
})

const order = (owningGroupId: string, extra: Partial<AuthorisationResource> = {}): AuthorisationResource =>
  ({ type: 'orders', id: 'order-1', owningGroupId, ...extra })

const assign = (groupId: string, roleId: string, scope: AuthorisationRoleAssignmentScope = 'group', principalId = 'alice'): AuthorisationRoleAssignment =>
  ({ principalId, groupId, roleId, scope, expiresAt: null })

function decide(overrides: Partial<AuthorisationFacts> & { resource: AuthorisationResource }) {
  return decideAuthorisation({
    subject: strong,
    actor: alice(),
    permission: 'orders:view',
    owningGroup: GROUPS[overrides.resource.owningGroupId] ?? null,
    requestTenantId: null,
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
  it('refuses an active member with no role: membership alone grants nothing', () => {
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

  it('refuses when the directory does not know the principal, or answers for someone else', () => {
    expect(decide({ actor: null, resource: order('sales') })).toMatchObject({ reason: 'unknown-subject' })
    const bob = { ...alice('sales'), principalId: 'bob' }
    expect(decide({ actor: bob, assignments: [assign('sales', 'owner')], resource: order('sales') })).toMatchObject({ reason: 'unknown-subject' })
  })

  it('refuses when the owning group is unknown or inconsistent', () => {
    expect(decide({ resource: order('ghost') })).toMatchObject({ reason: 'unknown-group' })
    expect(decide({ resource: order('sales'), owningGroup: GROUPS.london! })).toMatchObject({ reason: 'unknown-group' })
    expect(decide({ resource: order('sales'), owningGroup: { ...GROUPS.sales!, lineage: [] } })).toMatchObject({ reason: 'unknown-group' })
    expect(decide({ resource: order('sales'), owningGroup: { ...GROUPS.sales!, tenantId: '' } })).toMatchObject({ reason: 'unknown-group' })
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

  it('ignores role assignments that belong to someone else', () => {
    const decision = decide({ actor: alice('sales'), assignments: [assign('sales', 'owner', 'group', 'bob')], resource: order('sales') })
    expect(decision).toMatchObject({ allowed: false, reason: 'not-permitted' })
  })

  it('evaluates a tenant\'s custom roles, and only that tenant\'s', () => {
    const auditor: AuthorisationRoleDefinition = { id: 'auditor', name: 'Auditor', permissions: [{ pattern: 'orders:view' }] }
    const customRoles = new Map([['tenant-a', new Map([['auditor', auditor]])]])
    expect(decide({ actor: alice('sales'), assignments: [assign('sales', 'auditor')], customRoles, resource: order('sales') }))
      .toMatchObject({ allowed: true, via: 'role' })
    const elsewhere = new Map([['tenant-b', new Map([['auditor', auditor]])]])
    expect(decide({ actor: alice('sales'), assignments: [assign('sales', 'auditor')], customRoles: elsewhere, resource: order('sales') }))
      .toMatchObject({ allowed: false })
  })

  it('resolves built-in role IDs before custom ones', () => {
    const impostor: AuthorisationRoleDefinition = { id: 'viewer', name: 'Viewer', permissions: [{ pattern: '*' }] }
    const customRoles = new Map([['tenant-a', new Map([['viewer', impostor]])]])
    const decision = decide({ actor: alice('sales'), assignments: [assign('sales', 'viewer')], customRoles, permission: 'orders:update', resource: order('sales') })
    expect(decision).toMatchObject({ allowed: false })
  })
})

describe('decision: the hierarchy confers no privilege by default', () => {
  it('does not let a role in an ancestor reach a descendant\'s resources', () => {
    const decision = decide({ actor: alice('company-a'), assignments: [assign('company-a', 'administrator')], resource: order('sales') })
    expect(decision).toMatchObject({ allowed: false, reason: 'not-permitted' })
  })

  it('reaches descendants only with the explicit group-and-descendants scope', () => {
    const decision = decide({ actor: alice('company-a'), assignments: [assign('company-a', 'administrator', 'group-and-descendants')], permission: 'orders:update', resource: order('sales') })
    expect(decision).toMatchObject({ allowed: true, via: 'role' })
  })

  it('never lets a role reach upwards, even with the descendants scope', () => {
    const decision = decide({ actor: alice('sales', 'company-a'), assignments: [assign('sales', 'owner', 'group-and-descendants')], resource: order('company-a') })
    expect(decision).toMatchObject({ allowed: false, reason: 'not-permitted' })
  })

  it('never lets a role reach a sibling or another tree', () => {
    const assignments = [assign('london', 'owner', 'group-and-descendants')]
    expect(decide({ actor: alice('london'), assignments, resource: order('company-a') })).toMatchObject({ allowed: false })
    expect(decide({ actor: alice('london'), assignments, resource: order('club-x') })).toMatchObject({ allowed: false })
  })

  it('follows the current tree: moving a group out from under an ancestor ends that ancestor\'s reach', () => {
    const assignments = [assign('company-a', 'administrator', 'group-and-descendants')]
    const moved: AuthorisationGroup = { groupId: 'sales', lineage: ['club-x', 'sales'], tenantId: 'tenant-a' }
    expect(decide({ actor: alice('company-a'), assignments, resource: order('sales') })).toMatchObject({ allowed: true })
    expect(decide({ actor: alice('company-a'), assignments, resource: order('sales'), owningGroup: moved })).toMatchObject({ allowed: false })
  })
})

describe('decision: tenant isolation is a separate check', () => {
  it('refuses a resource outside the request\'s tenant before considering roles', () => {
    const decision = decide({ actor: alice('sales'), assignments: [assign('sales', 'owner')], requestTenantId: 'tenant-b', resource: order('sales') })
    expect(decision).toMatchObject({ allowed: false, reason: 'tenant-mismatch' })
    expect(decide({ actor: alice('sales'), assignments: [assign('sales', 'viewer')], requestTenantId: 'tenant-a', resource: order('sales') }))
      .toMatchObject({ allowed: true })
  })

  it('never lets a role in one tenant reach another tenant', () => {
    const decision = decide({ actor: alice('company-a', 'company-b'), assignments: [assign('company-a', 'owner', 'group-and-descendants')], resource: order('company-b') })
    expect(decision).toMatchObject({ allowed: false, reason: 'not-permitted' })
  })

  it('treats a tenant as distinct from a root: one tenant may hold several trees', () => {
    const decision = decide({ actor: alice('company-a'), assignments: [assign('company-a', 'owner', 'group-and-descendants')], resource: order('club-x') })
    expect(decision).toMatchObject({ allowed: false })
  })

  it('ignores an assignment whose group the directory places in another tenant', () => {
    const elsewhere: AuthorisationActorContext = {
      ...alice(),
      memberships: [{ group: { groupId: 'company-a', lineage: ['company-a'], tenantId: 'tenant-b' }, status: 'active' }],
    }
    const decision = decide({ actor: elsewhere, assignments: [assign('company-a', 'owner', 'group-and-descendants')], resource: order('sales') })
    expect(decision).toMatchObject({ allowed: false })
  })
})

describe('decision: membership status and departure', () => {
  const assignments = [assign('company-a', 'administrator', 'group-and-descendants')]

  it('allows while the membership is active', () => {
    expect(decide({ actor: alice('company-a'), assignments, resource: order('sales') })).toMatchObject({ allowed: true })
  })

  it.each(['suspended', 'ended'] as const)('refuses a %s membership even if the directory still returns it', (status) => {
    expect(decide({ actor: alice(['company-a', status]), assignments, resource: order('sales') }))
      .toMatchObject({ allowed: false, reason: 'not-permitted' })
  })

  it('refuses once the membership is gone, though the assignment remains', () => {
    expect(decide({ actor: alice('company-b'), assignments, resource: order('sales') }))
      .toMatchObject({ allowed: false, reason: 'not-permitted' })
  })

  it('takes away grants made to the leaver as a principal, unless external grants are allowed', () => {
    const grants: AuthorisationGrant[] = [{ resource: { type: 'orders', id: 'order-1' }, subject: { kind: 'principal', principalId: 'alice' }, permissions: ['orders:view'], expiresAt: null }]
    expect(decide({ actor: alice('sales'), grants, resource: order('sales') })).toMatchObject({ allowed: true, via: 'grant' })
    expect(decide({ actor: alice(), grants, resource: order('sales') })).toMatchObject({ allowed: false })
    const policy = resolveAuthorisationPolicy({ externalGrants: true })
    expect(decide({ actor: alice(), grants, policy, resource: order('sales') })).toMatchObject({ allowed: true, via: 'grant' })
  })

  it('keeps access from a genuinely independent grant when an unrelated membership ends', () => {
    const grants: AuthorisationGrant[] = [{ resource: { type: 'orders', id: 'order-1' }, subject: { kind: 'group', groupId: 'london' }, permissions: ['orders:view'], expiresAt: null }]
    const salesAssignments = [assign('sales', 'viewer')]
    expect(decide({ actor: alice('sales', 'london'), assignments: salesAssignments, resource: order('sales') })).toMatchObject({ allowed: true, via: 'role' })
    expect(decide({ actor: alice('london'), assignments: salesAssignments, grants, resource: order('sales') })).toMatchObject({ allowed: true, via: 'grant' })
  })
})

describe('decision: paused memberships and principals (contract 3)', () => {
  const owner = [assign('sales', 'owner')]
  const viewable = ['orders:view', 'orders:view_history']
  const notViewable = ['orders:create', 'orders:update', 'orders:export', 'orders:view_payment', 'orders:process_refund', 'orders:delete']

  it.each(viewable)('lets a paused member %s: a view at low or medium risk', (permission) => {
    expect(decide({ actor: alice(['sales', 'paused']), assignments: owner, permission, resource: order('sales') }))
      .toMatchObject({ allowed: true, via: 'role' })
  })

  it.each(notViewable)('refuses a paused member %s: a change, or a view at high risk', (permission) => {
    // Wildcards never cover high or critical permissions, so the role names each one.
    const full: AuthorisationRoleDefinition = { id: 'full', name: 'Full', permissions: notViewable.map(pattern => ({ pattern })) }
    const facts = { assignments: [assign('sales', 'full')], customRoles: new Map([['tenant-a', new Map([['full', full]])]]), permission, resource: order('sales') }
    expect(decide({ ...facts, actor: alice('sales') })).toMatchObject({ allowed: true, via: 'role' })
    expect(decide({ ...facts, actor: alice(['sales', 'paused']) })).toMatchObject({ allowed: false, reason: 'paused', requirement: null })
  })

  it('still needs a role that covers the view', () => {
    expect(decide({ actor: alice(['sales', 'paused']), resource: order('sales') })).toMatchObject({ allowed: false, reason: 'not-permitted' })
  })

  it('takes the effect from the definition, never from the action\'s name', () => {
    expect(decide({ actor: alice(['sales', 'paused']), assignments: owner, permission: 'orders:export', resource: order('sales') }))
      .toMatchObject({ allowed: false, reason: 'paused' })
  })

  it('treats a catalogue entry without an effect as a change', () => {
    const undeclared = new Map(catalogue)
    undeclared.set('orders:view', { name: 'orders:view', description: 'See orders', risk: 'low' } as AuthorisationPermissionDefinition)
    expect(decide({ actor: alice(['sales', 'paused']), assignments: owner, catalogue: undeclared, resource: order('sales') }))
      .toMatchObject({ allowed: false, reason: 'paused' })
  })

  it('prefers an active route: a paused membership never hides one', () => {
    const assignments = [assign('sales', 'owner'), assign('london', 'administrator', 'group-and-descendants')]
    expect(decide({ actor: alice(['sales', 'paused'], 'london'), assignments, permission: 'orders:update', resource: order('sales') }))
      .toMatchObject({ allowed: true, via: 'role' })
  })

  describe('a paused principal', () => {
    const paused = (...memberships: Parameters<typeof alice>): AuthorisationActorContext => ({ ...alice(...memberships), status: 'paused' })

    it('caps every membership, even one the directory reports active', () => {
      expect(decide({ actor: paused('sales'), assignments: owner, resource: order('sales') })).toMatchObject({ allowed: true })
      expect(decide({ actor: paused('sales'), assignments: owner, permission: 'orders:update', resource: order('sales') }))
        .toMatchObject({ allowed: false, reason: 'paused' })
    })

    it('is view-only in their own personal group', () => {
      expect(decide({ actor: paused(), resource: order('personal-alice') })).toMatchObject({ allowed: true, via: 'personal-group' })
      expect(decide({ actor: paused(), permission: 'orders:update', resource: order('personal-alice') }))
        .toMatchObject({ allowed: false, reason: 'paused' })
    })
  })

  it.each(['suspended', 'unknown', undefined])('gives a principal whose status is %s nothing, not even their personal group', (status) => {
    const actor = { ...alice('sales'), status } as unknown as AuthorisationActorContext
    expect(decide({ actor, resource: order('personal-alice') })).toMatchObject({ allowed: false, reason: 'not-permitted' })
    expect(decide({ actor, assignments: owner, resource: order('sales') })).toMatchObject({ allowed: false, reason: 'not-permitted' })
  })

  describe('grants', () => {
    const grant = (subject: AuthorisationGrant['subject']): AuthorisationGrant[] =>
      [{ resource: { type: 'orders', id: 'order-1' }, subject, permissions: ['orders:view', 'orders:update'], expiresAt: null }]

    it('limits a grant to a group to views while the membership is paused', () => {
      const grants = grant({ kind: 'group', groupId: 'london' })
      expect(decide({ actor: alice(['london', 'paused']), grants, resource: order('sales') })).toMatchObject({ allowed: true, via: 'grant' })
      expect(decide({ actor: alice(['london', 'paused']), grants, permission: 'orders:update', resource: order('sales') }))
        .toMatchObject({ allowed: false, reason: 'paused' })
    })

    it('limits a direct grant to views when every membership in the tenant is paused', () => {
      const grants = grant({ kind: 'principal', principalId: 'alice' })
      expect(decide({ actor: alice(['club-x', 'paused']), grants, permission: 'orders:update', resource: order('sales') }))
        .toMatchObject({ allowed: false, reason: 'paused' })
      expect(decide({ actor: alice(['club-x', 'paused'], 'company-a'), grants, permission: 'orders:update', resource: order('sales') }))
        .toMatchObject({ allowed: true, via: 'grant' })
    })

    it('limits an external grant to views while the principal is paused', () => {
      const grants = grant({ kind: 'principal', principalId: 'alice' })
      const policy = resolveAuthorisationPolicy({ externalGrants: true })
      const actor: AuthorisationActorContext = { ...alice(), status: 'paused' }
      expect(decide({ actor, grants, policy, resource: order('sales') })).toMatchObject({ allowed: true, via: 'grant' })
      expect(decide({ actor, grants, policy, permission: 'orders:update', resource: order('sales') })).toMatchObject({ allowed: false, reason: 'paused' })
    })
  })
})

describe('decision: creator provenance and ownership', () => {
  const report = order('sales', { creatorPrincipalId: 'alice' })

  it('gives the creator no access by provenance alone, even while a member', () => {
    expect(decide({ actor: alice('sales'), resource: report })).toMatchObject({ allowed: false, reason: 'not-permitted' })
  })

  it('lets a role grant creators rights explicitly, through a condition', () => {
    const editor: AuthorisationRoleDefinition = {
      id: 'editor',
      name: 'Editor',
      permissions: [{ pattern: 'orders:update', when: [{ attribute: 'resource.creatorPrincipalId', operator: 'equals', value: { ref: 'subject.principalId' } }] }],
    }
    const facts = {
      assignments: [assign('sales', 'editor')],
      customRoles: new Map([['tenant-a', new Map([['editor', editor]])]]),
      permission: 'orders:update',
    }
    expect(decide({ ...facts, actor: alice('sales'), resource: report })).toMatchObject({ allowed: true, via: 'role' })
    expect(decide({ ...facts, actor: alice('sales'), resource: order('sales', { creatorPrincipalId: 'bob' }) })).toMatchObject({ allowed: false })
    // The creator leaves: the report stays with the group, and their access ends.
    expect(decide({ ...facts, actor: alice(), resource: report })).toMatchObject({ allowed: false })
  })

  it('keeps the resource with its owning group after the creator leaves', () => {
    const bob: AuthorisationActorContext = { principalId: 'bob', status: 'active', personalGroup: GROUPS['personal-bob']!, memberships: [{ group: GROUPS.sales!, status: 'active' }] }
    const decision = decide({ subject: { ...strong, principalId: 'bob' }, actor: bob, assignments: [assign('sales', 'viewer', 'group', 'bob')], resource: report })
    expect(decision).toMatchObject({ allowed: true, via: 'role' })
  })
})

describe('decision: personal groups', () => {
  it('gives a principal the policy\'s personal-group role in their own personal group', () => {
    const decision = decide({ permission: 'orders:update', resource: order('personal-alice') })
    expect(decision).toMatchObject({ allowed: true, via: 'personal-group' })
  })

  it('follows the policy: a narrower role, or none', () => {
    const viewer = resolveAuthorisationPolicy({ personalGroupRole: 'viewer' })
    expect(decide({ policy: viewer, resource: order('personal-alice') })).toMatchObject({ allowed: true })
    expect(decide({ policy: viewer, permission: 'orders:update', resource: order('personal-alice') })).toMatchObject({ allowed: false })
    const none = resolveAuthorisationPolicy({ personalGroupRole: null })
    expect(decide({ policy: none, resource: order('personal-alice') })).toMatchObject({ allowed: false })
  })

  it('gives nobody else access to it', () => {
    expect(decide({ actor: alice('sales'), resource: order('personal-bob') })).toMatchObject({ allowed: false, reason: 'not-permitted' })
  })

  it('works for an identity without a personal group', () => {
    const service: AuthorisationActorContext = { principalId: 'alice', status: 'active', personalGroup: null, memberships: [{ group: GROUPS.sales!, status: 'active' }] }
    expect(decide({ actor: service, assignments: [assign('sales', 'viewer')], resource: order('sales') })).toMatchObject({ allowed: true })
    expect(decide({ actor: service, resource: order('personal-alice') })).toMatchObject({ allowed: false })
  })
})

describe('decision: grants', () => {
  const grant = (subject: AuthorisationGrant['subject'], extra: Partial<AuthorisationGrant> = {}): AuthorisationGrant =>
    ({ resource: { type: 'orders', id: 'order-1' }, subject, permissions: ['orders:view'], expiresAt: null, ...extra })

  it('allows only active members of a granted group', () => {
    const grants = [grant({ kind: 'group', groupId: 'london' })]
    expect(decide({ actor: alice('london'), grants, resource: order('sales') })).toMatchObject({ allowed: true, via: 'grant' })
    expect(decide({ actor: alice(['london', 'suspended']), grants, resource: order('sales') })).toMatchObject({ allowed: false })
    expect(decide({ actor: alice('company-a'), grants, resource: order('sales') })).toMatchObject({ allowed: false })
  })

  it('keeps group grants inside the resource\'s tenant unless external grants are allowed', () => {
    const external = resolveAuthorisationPolicy({ externalGrants: true })
    const toCompanyB = [grant({ kind: 'group', groupId: 'company-b' })]
    expect(decide({ actor: alice('company-b'), grants: toCompanyB, resource: order('sales') })).toMatchObject({ allowed: false })
    expect(decide({ actor: alice('company-b'), grants: toCompanyB, policy: external, resource: order('sales') })).toMatchObject({ allowed: true, via: 'grant' })
    // A personal group is in its own tenant, so it cannot be used to slip past the rule.
    const toPersonal = [grant({ kind: 'group', groupId: 'personal-alice' })]
    expect(decide({ grants: toPersonal, resource: order('sales') })).toMatchObject({ allowed: false })
    expect(decide({ grants: toPersonal, policy: external, resource: order('sales') })).toMatchObject({ allowed: true })
  })

  it('allows a grant to another group in the same tenant, even in another tree', () => {
    const grants = [grant({ kind: 'group', groupId: 'club-x' })]
    expect(decide({ actor: alice('club-x'), grants, resource: order('sales') })).toMatchObject({ allowed: true, via: 'grant' })
  })

  it('covers only the named permissions on the named resource', () => {
    const grants = [grant({ kind: 'principal', principalId: 'alice' })]
    expect(decide({ actor: alice('sales'), grants, permission: 'orders:update', resource: order('sales') })).toMatchObject({ allowed: false })
    expect(decide({ actor: alice('sales'), grants, resource: order('sales', { id: 'order-2' }) })).toMatchObject({ allowed: false })
  })

  it('stops at its expiry, and treats a malformed expiry as expired', () => {
    const expired = [grant({ kind: 'principal', principalId: 'alice' }, { expiresAt: '2026-10-08T12:00:00.000Z' })]
    expect(decide({ actor: alice('sales'), grants: expired, resource: order('sales') })).toMatchObject({ allowed: false })
    const malformed = [grant({ kind: 'principal', principalId: 'alice' }, { expiresAt: 'tomorrow' })]
    expect(decide({ actor: alice('sales'), grants: malformed, resource: order('sales') })).toMatchObject({ allowed: false })
  })

  it('counts a grant bound to an owning group only while that group owns the resource (contract 4)', () => {
    const bound = [grant({ kind: 'principal', principalId: 'alice' }, { resource: { type: 'orders', id: 'order-1', owningGroupId: 'sales' } })]
    expect(decide({ actor: alice('sales'), grants: bound, resource: order('sales') })).toMatchObject({ allowed: true, via: 'grant' })
    // A grant whose requester claimed the resource for another group confers nothing on the real one.
    const forged = [grant({ kind: 'principal', principalId: 'alice' }, { resource: { type: 'orders', id: 'order-1', owningGroupId: 'personal-alice' } })]
    expect(decide({ actor: alice('sales'), grants: forged, resource: order('sales') })).toMatchObject({ allowed: false, reason: 'not-permitted' })
  })
})

describe('decision: time-limited assignments (contract 4)', () => {
  it('confers nothing past its end, before maintenance removes it, and treats a malformed end as passed', () => {
    const until = (expiresAt: string) => [{ ...assign('sales', 'viewer'), expiresAt }]
    expect(decide({ actor: alice('sales'), assignments: until('2026-10-08T12:00:01.000Z'), resource: order('sales') })).toMatchObject({ allowed: true, via: 'role' })
    expect(decide({ actor: alice('sales'), assignments: until('2026-10-08T12:00:00.000Z'), resource: order('sales') })).toMatchObject({ allowed: false, reason: 'not-permitted' })
    expect(decide({ actor: alice('sales'), assignments: until('soon'), resource: order('sales') })).toMatchObject({ allowed: false })
  })
})

describe('decision: wildcards and risk', () => {
  it('never lets a wildcard cover a high or critical permission', () => {
    expect(decide({ actor: alice('sales'), assignments: [assign('sales', 'owner')], permission: 'orders:process_refund', resource: order('sales') }))
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
    expect(decide({ ...facts, subject: { ...strong, authenticatedAt: '2026-10-08T11:44:59.000Z' } })).toMatchObject({ reason: 'insufficient-assurance' })
    expect(decide({ ...facts, subject: { ...strong, assurance: { level: 'aal2', phishingResistant: false } } })).toMatchObject({ reason: 'insufficient-assurance' })
    expect(decide({ ...facts, subject: { ...strong, authenticatedAt: 'not a date' } })).toMatchObject({ reason: 'insufficient-assurance' })
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
  const facts = (role: AuthorisationRoleDefinition, resource: AuthorisationResource) => ({
    actor: alice('sales'),
    assignments: [assign('sales', 'editor')],
    customRoles: new Map([['tenant-a', new Map([['editor', role]])]]),
    permission: 'orders:update',
    resource,
  })

  it('applies a role entry only when every condition holds', () => {
    const role = editor([
      { attribute: 'resource.attributes.status', operator: 'in', value: ['draft', 'open'] },
      { attribute: 'resource.creatorPrincipalId', operator: 'equals', value: { ref: 'subject.principalId' } },
    ])
    expect(decide(facts(role, order('sales', { creatorPrincipalId: 'alice', attributes: { status: 'draft' } })))).toMatchObject({ allowed: true })
    expect(decide(facts(role, order('sales', { creatorPrincipalId: 'alice', attributes: { status: 'closed' } })))).toMatchObject({ allowed: false })
    expect(decide(facts(role, order('sales', { creatorPrincipalId: 'bob', attributes: { status: 'draft' } })))).toMatchObject({ allowed: false })
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

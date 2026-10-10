import { describe, expect, it } from 'vitest'
import type { AuthorisationPermissionDefinition } from '../contracts'
import {
  AUTHORISATION_CHANGE_TYPES,
  AUTHORISATION_CHANGES,
  AUTHORISATION_EVENT_TYPES,
  AUTHORISATION_PERMISSIONS,
  DEFAULT_AUTHORISATION_POLICY,
  approvalRequirement,
  assignmentRisk,
  authorisationEventSchema,
  canonicalJson,
  changeRequestSchema,
  chooseRoute,
  isSelfGrant,
  pendingChangeSchema,
  refuseApproval,
  roleDocumentSchema,
  roleRisk,
} from '../contracts'

const PERMISSIONS: AuthorisationPermissionDefinition[] = [
  ...AUTHORISATION_PERMISSIONS,
  { name: 'orders:view', description: 'See orders', risk: 'low', effect: 'view' },
  { name: 'orders:create', description: 'Place orders', risk: 'medium', effect: 'change' },
  { name: 'orders:process_refund', description: 'Refund', risk: 'high', effect: 'change' },
  { name: 'orders:purge', description: 'Purge', risk: 'critical', effect: 'change' },
]
const catalogue = new Map(PERMISSIONS.map(p => [p.name, p]))
const roles = DEFAULT_AUTHORISATION_POLICY.roles

describe('the risk of a role and of an assignment', () => {
  it('resolves wildcards against the catalogue, covering only low and medium permissions', () => {
    expect(roleRisk(roles.viewer, catalogue)).toBe('low')
    expect(roleRisk(roles.member, catalogue)).toBe('medium')
    expect(roleRisk([{ pattern: '*' }], catalogue)).toBe('medium')
    expect(roleRisk(roles.administrator, catalogue)).toBe('high')
    expect(roleRisk(roles.owner, catalogue)).toBe('critical')
    expect(roleRisk([{ pattern: 'orders:purge', when: [{ attribute: 'resource.attributes.status', operator: 'equals', value: 'draft' }] }], catalogue)).toBe('critical')
    expect(roleRisk([], catalogue)).toBe('low')
    // An exact name missing from the catalogue never lowers a risk.
    expect(roleRisk([{ pattern: 'orders:unknown' }], catalogue)).toBe('critical')
  })

  it('takes medium as the floor of any assignment, and critical for the descendants scope', () => {
    expect(assignmentRisk('low', 'group')).toBe('medium')
    expect(assignmentRisk('medium', 'group')).toBe('medium')
    expect(assignmentRisk('high', 'group')).toBe('high')
    expect(assignmentRisk('low', 'group-and-descendants')).toBe('critical')
  })
})

describe('approval rules', () => {
  it('needs no approver for low and medium changes, one for high and critical, more only if the group raises it', () => {
    expect(approvalRequirement({ risk: 'medium', inRequestersPersonalGroup: false, groupRequirement: null }).approvers).toBe(0)
    expect(approvalRequirement({ risk: 'high', inRequestersPersonalGroup: false, groupRequirement: null }).approvers).toBe(1)
    expect(approvalRequirement({ risk: 'critical', inRequestersPersonalGroup: false, groupRequirement: { low: 0, medium: 0, high: 1, critical: 2 } }).approvers).toBe(2)
    // A group can never lower the floor.
    expect(approvalRequirement({ risk: 'high', inRequestersPersonalGroup: false, groupRequirement: { low: 0, medium: 0, high: 0 as never, critical: 1 } }).approvers).toBe(1)
  })

  it('needs no approver in one\'s own personal group, but still the step-up', () => {
    const requirement = approvalRequirement({ risk: 'critical', inRequestersPersonalGroup: true, groupRequirement: null })
    expect(requirement.approvers).toBe(0)
    expect(requirement.stepUp).toEqual({ minimumLevel: 'aal2', phishingResistant: true, maxAuthenticationAgeSeconds: 900 })
  })

  it('chooses approvers in the group, then a parent owner, then a root owner, then a published delay', () => {
    expect(chooseRoute({ approvers: 0, qualifyingInGroup: 0, parentOwners: 0, tenantOwners: 0 })).toBe('none')
    expect(chooseRoute({ approvers: 2, qualifyingInGroup: 2, parentOwners: 1, tenantOwners: 1 })).toBe('approvers')
    expect(chooseRoute({ approvers: 2, qualifyingInGroup: 1, parentOwners: 1, tenantOwners: 1 })).toBe('parent-owner')
    expect(chooseRoute({ approvers: 1, qualifyingInGroup: 0, parentOwners: 0, tenantOwners: 1 })).toBe('tenant-owner')
    expect(chooseRoute({ approvers: 1, qualifyingInGroup: 0, parentOwners: 0, tenantOwners: 0 })).toBe('published-delay')
  })

  it('treats a change conferring on its requester as a self-grant, outside their personal group only', () => {
    expect(isSelfGrant({ type: 'role.assign', requesterId: 'a', beneficiaryId: 'a', inRequestersPersonalGroup: false })).toBe(true)
    expect(isSelfGrant({ type: 'assignment.confirm', requesterId: 'a', beneficiaryId: 'a', inRequestersPersonalGroup: false })).toBe(true)
    expect(isSelfGrant({ type: 'grant.create', requesterId: 'a', beneficiaryId: 'a', inRequestersPersonalGroup: true })).toBe(false)
    expect(isSelfGrant({ type: 'role.unassign', requesterId: 'a', beneficiaryId: 'a', inRequestersPersonalGroup: false })).toBe(false)
    expect(Object.entries(AUTHORISATION_CHANGES).filter(([, c]) => c.confers).map(([type]) => type).sort()).toEqual(['assignment.confirm', 'grant.create', 'role.assign'])
  })

  it('refuses the requester, the beneficiary, someone the requester controls, a stale digest and a weak session', () => {
    const change = { requesterId: 'req', beneficiaryId: 'ben', changeDigest: 'a'.repeat(64), state: 'awaiting-approval' as const, approvals: [], risk: 'critical' as const }
    const now = new Date('2030-01-01T00:10:00.000Z')
    const assurance = { level: 'aal2' as const, phishingResistant: true, authenticatedAt: '2030-01-01T00:00:00.000Z' }
    const base = { change, approverId: 'app', qualifies: true, controls: ['svc'], assurance, changeDigest: 'a'.repeat(64), now }
    expect(refuseApproval(base)).toBeNull()
    expect(refuseApproval({ ...base, approverId: 'req' })).toBe('own-request')
    expect(refuseApproval({ ...base, approverId: 'ben' })).toBe('beneficiary')
    expect(refuseApproval({ ...base, approverId: 'svc' })).toBe('controlled-by-requester')
    expect(refuseApproval({ ...base, qualifies: false })).toBe('not-qualified')
    expect(refuseApproval({ ...base, changeDigest: 'b'.repeat(64) })).toBe('change-differs')
    expect(refuseApproval({ ...base, assurance: { ...assurance, phishingResistant: false } })).toBe('insufficient-assurance')
    expect(refuseApproval({ ...base, now: new Date('2030-01-01T00:20:00.000Z') })).toBe('insufficient-assurance')
    expect(refuseApproval({ ...base, change: { ...change, state: 'applied' } })).toBe('not-pending')
  })
})

describe('change requests and pending changes', () => {
  const justification = { reasonCode: 'new-starter', reference: null }

  it('parses each change type strictly, refusing unknown fields and free text', () => {
    expect(changeRequestSchema.safeParse({ type: 'role.assign', target: { principalId: 'p', groupId: 'g', roleId: 'member' }, justification }).success).toBe(true)
    expect(changeRequestSchema.safeParse({ type: 'role.assign', target: { principalId: 'p', groupId: 'g', roleId: 'member', name: 'Ada' }, justification }).success).toBe(false)
    expect(changeRequestSchema.safeParse({ type: 'role.assign', target: { principalId: 'p', groupId: 'g', roleId: 'member' }, justification: { reasonCode: 'Because I said so', reference: null } }).success).toBe(false)
    expect(changeRequestSchema.safeParse({ type: 'role.assign', target: { principalId: 'ada@example.com', groupId: 'g', roleId: 'member' }, justification }).success).toBe(false)
    expect(changeRequestSchema.safeParse({ type: 'grant.create', target: { grant: { resource: { type: 'orders', id: 'o1' }, subject: { kind: 'principal', principalId: 'p' }, permissions: ['orders:view'], expiresAt: null } }, justification }).success).toBe(false)
    expect(changeRequestSchema.safeParse({ type: 'group.change-review-interval', target: { groupId: 'g', intervalDays: 0 }, justification }).success).toBe(false)
    expect(changeRequestSchema.safeParse({ type: 'superuser.grant', target: {}, justification }).success).toBe(false)
    expect(AUTHORISATION_CHANGE_TYPES).toHaveLength(9)
  })

  it('refuses a pending change whose target does not match its type', () => {
    const change = {
      changeId: '01a00000-0000-7000-8000-000000000001',
      type: 'role.unassign',
      tenantId: 't',
      groupId: 'g',
      requesterId: 'r',
      beneficiaryId: 'p',
      risk: 'medium',
      justification,
      target: { principalId: 'p', groupId: 'g', roleId: 'member' },
      requiredApprovals: 0,
      route: 'none',
      approvals: [],
      changeDigest: 'a'.repeat(64),
      delayEndsAt: null,
      expiresAt: null,
      heldUntil: null,
      state: 'applied',
      correlationId: '01a00000-0000-7000-8000-000000000002',
      createdAt: '2030-01-01T00:00:00.000Z',
      decidedAt: '2030-01-01T00:00:00.000Z',
      version: 1,
    }
    expect(pendingChangeSchema.safeParse(change).success).toBe(true)
    expect(pendingChangeSchema.safeParse({ ...change, target: { groupId: 'g', intervalDays: 30 } }).success).toBe(false)
  })
})

describe('events', () => {
  const envelope = { eventId: '01a00000-0000-7000-8000-000000000003', occurredAt: '2030-01-01T00:00:00.000Z', correlationId: '01a00000-0000-7000-8000-000000000004', actorPrincipalId: 'p' }

  it('carries identifiers, codes and times only, in strict schemas', () => {
    const assigned = { ...envelope, type: 'authorisation.role-assigned', data: { principalId: 'p', groupId: 'g', roleId: 'member', scope: 'group', expiresAt: null, changeId: null } }
    expect(authorisationEventSchema.safeParse(assigned).success).toBe(true)
    expect(authorisationEventSchema.safeParse({ ...assigned, data: { ...assigned.data, name: 'Ada Lovelace' } }).success).toBe(false)
    expect(authorisationEventSchema.safeParse({ ...assigned, email: 'ada@example.com' }).success).toBe(false)
    expect(authorisationEventSchema.safeParse({ ...assigned, data: { ...assigned.data, principalId: 'ada@example.com' } }).success).toBe(false)
    expect(AUTHORISATION_EVENT_TYPES).toEqual(expect.arrayContaining([
      'authorisation.change-requested', 'authorisation.change-decided', 'authorisation.change-held', 'authorisation.role-expired',
      'authorisation.group-access-changed', 'authorisation.review-overdue', 'authorisation.roles-imported', 'authorisation.principal-erased',
    ]))
  })
})

describe('canonical JSON and role documents', () => {
  it('sorts keys at every depth and keeps array order, so equal content has equal text', () => {
    expect(canonicalJson({ b: 1, a: [{ d: 2, c: 'x' }], e: undefined })).toBe('{"a":[{"c":"x","d":2}],"b":1}')
    expect(canonicalJson({ a: 1, b: 2 })).toBe(canonicalJson({ b: 2, a: 1 }))
    expect(() => canonicalJson({ a: Number.NaN })).toThrow(TypeError)
  })

  it('refuses a role document with repeated role identifiers or another format', () => {
    const document = { format: 'nuxt4-layers.authorisation.roles', formatVersion: 1, tenantId: 't', roles: [{ id: 'clerk', name: 'Clerk', permissions: [] }], digest: 'a'.repeat(64) }
    expect(roleDocumentSchema.safeParse(document).success).toBe(true)
    expect(roleDocumentSchema.safeParse({ ...document, roles: [...document.roles, ...document.roles] }).success).toBe(false)
    expect(roleDocumentSchema.safeParse({ ...document, formatVersion: 2 }).success).toBe(false)
  })
})

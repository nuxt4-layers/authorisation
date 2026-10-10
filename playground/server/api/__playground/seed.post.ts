import { randomBytes, randomUUID } from 'node:crypto'
import { createError, defineEventHandler } from 'h3'
import type { AuthorisationSubject } from '../../../../contracts'
import { playground } from '../../plugins/composition'

/**
 * Test mode only: builds a fresh scenario for a browser test, through the
 * layer's own server functions, and returns its identifiers. A tenant whose
 * root group is owned by `olive` and `otto`; a child group `sales` owned by
 * `sam`, with administrators `adam` and `amy` and a member `mia`; forty days
 * ago, a 30-day review interval and a custom role, so `mia`'s role is
 * overdue for review; a grant of an order to `mia`; a change waiting for an
 * approver (`adam` asks for `mia` to become an administrator); and an
 * `outsider`, who belongs to nothing.
 */
export default defineEventHandler(async () => {
  if (process.env.AUTHORISATION_PLAYGROUND_TEST !== '1') throw createError({ statusCode: 404 })
  await playground.ready
  const s = randomBytes(4).toString('hex')
  // Identifiers end with the name, so the default placeholder names (their last characters) differ.
  const id = (name: string) => `${s}-${name}`
  const [tenantId, company, sales] = [id('tenant'), id('company'), id('sales')]
  const [olive, otto, sam, adam, amy, mia, outsider] = ['olive', 'otto', 'sam', 'adam', 'amy', 'mia', 'outsider'].map(id)
  playground.groups.set(company, { groupId: company, lineage: [company], tenantId })
  playground.groups.set(sales, { groupId: sales, lineage: [company, sales], tenantId })
  const join = (principalId: string, groupId: string) => playground.memberships.set(principalId, new Set([...(playground.memberships.get(principalId) ?? []), groupId]))
  for (const [principalId, groupId] of [[olive, company], [otto, company], [sam, sales], [adam, sales], [amy, sales], [mia, sales]] as const) join(principalId, groupId)
  playground.memberships.set(outsider, new Set())
  playground.owners.set(company, new Set([olive, otto]))
  playground.owners.set(sales, new Set([sam]))

  const correlationId = randomUUID()
  const subject = (principalId: string): AuthorisationSubject => ({ principalId, authenticatedAt: new Date(Date.now() + playground.offsetMs).toISOString(), assurance: { level: 'aal2', phishingResistant: true } })
  const justification = { reasonCode: 'playground', reference: null }
  const changes = getAuthorisationChanges()
  const approve = async (approver: string, changeId: string) => {
    const change = await changes.get({ subject: subject(approver), changeId })
    return changes.decide({ subject: subject(approver), changeId, changeDigest: change.changeDigest, decision: 'approve', correlationId })
  }

  playground.offsetMs = -40 * 86_400_000
  try {
    for (const owner of [olive, otto]) await assignAuthorisationRole({ principalId: owner, groupId: company, roleId: 'owner', actorPrincipalId: owner, correlationId })
    await assignAuthorisationRole({ principalId: sam, groupId: sales, roleId: 'owner', actorPrincipalId: sam, correlationId })
    for (const admin of [adam, amy]) await assignAuthorisationRole({ principalId: admin, groupId: sales, roleId: 'administrator', actorPrincipalId: sam, correlationId })
    await assignAuthorisationRole({ principalId: mia, groupId: sales, roleId: 'member', actorPrincipalId: sam, correlationId })
    const interval = await changes.request({ subject: subject(sam), request: { type: 'group.change-review-interval', target: { groupId: sales, intervalDays: 30 }, justification }, correlationId })
    await approve(olive, interval.changeId)
    const role = await changes.request({ subject: subject(olive), request: { type: 'role.define', target: { tenantId, role: { id: 'refund-clerk', name: 'Refund clerk', permissions: [{ pattern: 'orders:view' }, { pattern: 'orders:process_refund' }] } }, justification }, correlationId })
    await approve(otto, role.changeId)
    await createAuthorisationGrant({ grant: { resource: { type: 'orders', id: id('order'), owningGroupId: sales }, subject: { kind: 'principal', principalId: mia }, permissions: ['orders:view'], expiresAt: null }, actorPrincipalId: sam, correlationId })
  }
  finally {
    playground.offsetMs = 0
  }
  const pending = await changes.request({ subject: subject(adam), request: { type: 'role.assign', target: { principalId: mia, groupId: sales, roleId: 'administrator' }, justification }, correlationId })
  return { tenantId, company, sales, olive, otto, sam, adam, amy, mia, outsider, changeId: pending.changeId }
})

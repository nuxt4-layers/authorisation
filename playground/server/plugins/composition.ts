/**
 * Playground composition root: supplies the authorisation ports the way a host
 * application would. The directory here is a fixed development fixture standing
 * in for the host's Identity adapter; the database port is added in phase 2.
 */
const groups = {
  'company-a': { groupId: 'company-a', lineage: ['company-a'], tenantId: 'tenant-a' },
  'company-a-sales': { groupId: 'company-a-sales', lineage: ['company-a', 'company-a-sales'], tenantId: 'tenant-a' },
  'personal-alice': { groupId: 'personal-alice', lineage: ['personal-alice'], tenantId: 'personal-alice' },
} as const

export default defineNitroPlugin(() => {
  provideAuthorisationDirectory({
    async resolveActor(principalId) {
      if (principalId !== 'alice') return null
      return {
        principalId,
        status: 'active',
        personalGroup: groups['personal-alice'],
        memberships: [{ group: groups['company-a-sales'], status: 'active' }],
      }
    },
    async describeGroup(groupId) {
      return groups[groupId as keyof typeof groups] ?? null
    },
  })

  provideAuthorisationPermissions([
    { name: 'orders:view', description: 'See orders', risk: 'low', effect: 'view' },
    { name: 'orders:create', description: 'Place orders', risk: 'medium' },
    { name: 'orders:process_refund', description: 'Refund an order', risk: 'high' },
  ])

  provideAuthorisationEventSink({
    emit(event) {
      console.info(`[playground events] ${event.type}`, { actorPrincipalId: event.actorPrincipalId, reason: event.reason })
    },
  })
})

/**
 * Playground composition root: supplies the authorisation ports the way a host
 * application would. The directory here is a fixed development fixture standing
 * in for the host's Identity adapter; the database port is added in phase 2.
 */
const lineage: Record<string, string[]> = {
  'company-a': ['company-a'],
  'company-a-sales': ['company-a', 'company-a-sales'],
  'personal-alice': ['personal-alice'],
}

export default defineNitroPlugin(() => {
  provideAuthorisationDirectory({
    async resolveActor(principalId) {
      if (principalId !== 'alice') return null
      return {
        principalId,
        personalGroupId: 'personal-alice',
        memberships: [{ groupId: 'company-a-sales', lineage: lineage['company-a-sales']! }],
      }
    },
    async getGroupLineage(groupId) {
      return lineage[groupId] ?? null
    },
  })

  provideAuthorisationPermissions([
    { name: 'orders:view', description: 'See orders', risk: 'low' },
    { name: 'orders:create', description: 'Place orders', risk: 'medium' },
    { name: 'orders:process_refund', description: 'Refund an order', risk: 'high' },
  ])

  provideAuthorisationEventSink({
    emit(event) {
      console.info(`[playground events] ${event.type}`, { actorPrincipalId: event.actorPrincipalId, reason: event.reason })
    },
  })
})

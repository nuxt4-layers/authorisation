/**
 * Playground composition root: supplies the authorisation ports the way a
 * host application would. Not published.
 *
 * By default nobody is ever signed in and there is no database: the
 * playground only proves the layer composes.
 *
 * With AUTHORISATION_PLAYGROUND_TEST=1 (browser tests only), it migrates
 * and uses a disposable database (AUTHORISATION_DATABASE_URL), answers the
 * directory and governance ports from the seeded scenario standing in for
 * Identity, takes the signed-in principal from the
 * `authorisation_playground_principal` cookie standing in for
 * Authentication, and uses a clock the seed may set back while it builds
 * history (a movable clock: test mode only).
 */
import pg from 'pg'
import { getCookie } from 'h3'
import type { H3Event } from 'h3'
import type { AuthorisationGovernedGroup, AuthorisationGroup } from '../../../contracts'
import { IDENTIFIER_PATTERN } from '../../../contracts'

const testMode = process.env.AUTHORISATION_PLAYGROUND_TEST === '1'

export interface PlaygroundState {
  ready: Promise<void>
  groups: Map<string, AuthorisationGroup>
  /** principal → groups it is an active member of */
  memberships: Map<string, Set<string>>
  /** group → its owners, as Identity records them */
  owners: Map<string, Set<string>>
  /** Milliseconds added to the system time: the seed sets history in the past. */
  offsetMs: number
}

export const playground: PlaygroundState = { ready: Promise.resolve(), groups: new Map(), memberships: new Map(), owners: new Map(), offsetMs: 0 }

const PERIODS = { publishedDelayHighHours: 72, publishedDelayCriticalHours: 168, approvalExpiryDays: 7, recoveryHoldHours: 72 }

export default defineNitroPlugin(() => {
  provideAuthorisationPermissions([
    { name: 'orders:view', description: 'See orders', risk: 'low', effect: 'view' },
    { name: 'orders:create', description: 'Place orders', risk: 'medium' },
    { name: 'orders:process_refund', description: 'Refund an order', risk: 'high' },
  ])

  // A host adapts Identity's directory here (iam-integration's authorisationDirectoryFromIdentity).
  provideAuthorisationDirectory({
    async resolveActor(principalId) {
      const groups = playground.memberships.get(principalId)
      if (!groups) return null
      return { principalId, status: 'active', personalGroup: null, memberships: [...groups].map(groupId => ({ group: playground.groups.get(groupId)!, status: 'active' as const })) }
    },
    async describeGroup(groupId) {
      return playground.groups.get(groupId) ?? null
    },
  })

  // A host adapts Identity's access governance here (iam-integration's authorisationGovernanceFromIdentity).
  provideAuthorisationGovernance({
    async describeGroup({ groupId }): Promise<AuthorisationGovernedGroup | null> {
      const group = playground.groups.get(groupId)
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
        safetyPeriods: PERIODS,
        requester: { recoveryHoldUntil: null, controls: [] },
      }
    },
    async isOwner({ principalId, groupId }) {
      return playground.owners.get(groupId)?.has(principalId) ?? false
    },
    async countOwners({ groupId, excluding }) {
      return [...(playground.owners.get(groupId) ?? [])].filter(owner => !excluding.includes(owner)).length
    },
  })

  provideAuthorisationEventSink({
    emit(event) {
      console.info(`[playground denials] ${event.type}`, { actorPrincipalId: event.actorPrincipalId, reason: event.reason })
    },
  })

  // A host adapts Authentication's getAuthenticatedPrincipal(event) here.
  provideAuthorisationSubjectResolver({
    async resolve(event) {
      if (!testMode) return null
      const principalId = getCookie(event as H3Event, 'authorisation_playground_principal')
      if (!principalId || !IDENTIFIER_PATTERN.test(principalId)) return null
      return { principalId, authenticatedAt: new Date(Date.now() + playground.offsetMs).toISOString(), assurance: { level: 'aal2', phishingResistant: true } }
    },
  })

  if (testMode) {
    provideAuthorisationClock({ now: () => new Date(Date.now() + playground.offsetMs) })
    provideAuthorisationDatabase({ dialect: 'postgres', pool: new pg.Pool({ connectionString: process.env.AUTHORISATION_DATABASE_URL }) })
    playground.ready = migrateAuthorisationDatabase().then(() => {})
  }
})

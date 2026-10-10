import type {
  AuthorisationAccessReview,
  AuthorisationAssignmentView,
  AuthorisationChangeRequest,
  AuthorisationGrantView,
  AuthorisationGroupAccess,
  AuthorisationJustification,
  AuthorisationPendingChange,
  AuthorisationSelfView,
  AuthorisationTenantRoles,
} from '../../contracts'
import { AUTHORISATION_API_PREFIX } from '../../contracts'

/** What a domain capability shares through `share()`: a resource it owns, with exact permissions of its type. */
export interface AuthorisationShareInput {
  resource: { type: string, id: string, owningGroupId: string }
  with: { kind: 'principal', principalId: string } | { kind: 'group', groupId: string }
  permissions: string[]
  expiresAt?: string | null
}

/**
 * The client side of Authorisation's administration API (docs/contracts.md
 * §16).
 *
 * For the user experience only: what to show, which buttons to offer. It
 * decides nothing. Every request is decided again on the server, which
 * answers with a contract error (`AuthorisationErrorBody`) when it refuses.
 * Uses `useRequestFetch()` so that the session cookie is forwarded during
 * server-side rendering.
 */
export function useAuthorisation() {
  // Untyped by route on purpose, as Identity's and Authentication's: Nitro's
  // typed-route inference over a host's whole route table exceeds
  // TypeScript's depth limit in larger compositions.
  const request = useRequestFetch() as unknown as (url: string, options: { method?: string, body?: object }) => Promise<unknown>
  const at = (path: string) => `${AUTHORISATION_API_PREFIX}${path}`
  const get = <T>(path: string) => request(at(path), {}) as Promise<T>
  const send = <T>(path: string, body: object = {}) => request(at(path), { method: 'POST', body }) as Promise<T>
  const id = (value: string) => encodeURIComponent(value)
  const requestChange = (change: AuthorisationChangeRequest) => send<AuthorisationPendingChange>('/changes', { request: change })

  return {
    me: () => get<AuthorisationSelfView>('/me'),
    assignments: (groupId: string) => get<AuthorisationAssignmentView[]>(`/groups/${id(groupId)}/assignments`),
    accessReview: (groupId: string) => get<AuthorisationAccessReview>(`/groups/${id(groupId)}/access-review`),
    groupAccess: (groupId: string) => get<AuthorisationGroupAccess>(`/groups/${id(groupId)}/access`),
    grants: (groupId: string) => get<AuthorisationGrantView[]>(`/groups/${id(groupId)}/grants`),
    changes: (groupId: string) => get<AuthorisationPendingChange[]>(`/groups/${id(groupId)}/changes`),
    tenantRoles: (tenantId: string) => get<AuthorisationTenantRoles>(`/tenants/${id(tenantId)}/roles`),

    requestChange,
    change: (changeId: string) => get<AuthorisationPendingChange>(`/changes/${id(changeId)}`),
    decideChange: (change: Pick<AuthorisationPendingChange, 'changeId' | 'changeDigest'>, decision: 'approve' | 'reject') =>
      send<AuthorisationPendingChange>(`/changes/${id(change.changeId)}/decision`, { decision, changeDigest: change.changeDigest }),
    cancelChange: (changeId: string) => send<AuthorisationPendingChange>(`/changes/${id(changeId)}/cancel`),

    /**
     * Shares a resource the calling domain capability owns: a `grant.create`
     * change. It applies at once from one's own personal group after
     * step-up, and otherwise waits for an approver.
     */
    share: (input: AuthorisationShareInput, justification: AuthorisationJustification) => requestChange({
      type: 'grant.create',
      target: { grant: { resource: input.resource, subject: input.with, permissions: input.permissions, expiresAt: input.expiresAt ?? null } },
      justification,
    }),
  }
}

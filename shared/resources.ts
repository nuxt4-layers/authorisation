/**
 * Resources, groups and tenants as Authorisation sees them. Re-exported from
 * the public contract.
 *
 * Authorisation stores no domain data and no groups. The domain capability
 * that owns a resource describes it with `AuthorisationResource`; Identity
 * (through the host's `AuthorisationDirectory` adapter) describes groups,
 * tenants and memberships.
 */

/** A value a condition can compare. */
export type AuthorisationAttributeValue = string | number | boolean | null

/**
 * A resource as described by the domain capability that owns it, at the
 * moment of the decision. The domain capability reads it from its own store;
 * a resource identifier supplied by a client is never trusted on its own.
 */
export interface AuthorisationResource {
  /** The resource part of the permission names that apply to it, e.g. `orders`. */
  type: string
  /** Opaque identifier, unique within `type`. */
  id: string
  /**
   * The group that owns the resource and its information. Every resource has
   * one: a resource a user keeps for themselves is owned by their personal group.
   */
  owningGroupId: string
  /**
   * Creator provenance: who created the resource. It never grants access by
   * itself; a role may test it in a condition (e.g. "members may edit what
   * they created"), and that role still needs a current membership.
   */
  creatorPrincipalId?: string | null
  /** Attributes that role conditions may test, e.g. `{ status: 'draft' }`. */
  attributes?: Readonly<Record<string, AuthorisationAttributeValue>>
}

/** A reference to a resource, for grants and events. */
export interface AuthorisationResourceRef {
  type: string
  id: string
}

/**
 * Where a group sits in its tree: its ancestors from the root down to the
 * group itself, e.g. `['company-a', 'london-office', 'sales']`. Every group
 * has at most one parent, so this is a single chain. Authorisation does not
 * limit depth: that is Identity's rule.
 *
 * The hierarchy records organisational structure only. It confers no
 * privilege unless a role assignment explicitly asks for it.
 */
export type AuthorisationGroupLineage = readonly string[]

/**
 * A group as the directory describes it. The tenant is the isolation
 * boundary; it is supplied explicitly and is not assumed to be the root of
 * the lineage.
 */
export interface AuthorisationGroup {
  groupId: string
  lineage: AuthorisationGroupLineage
  tenantId: string
}

export const AUTHORISATION_MEMBERSHIP_STATUSES = ['active', 'paused', 'suspended', 'ended'] as const

/**
 * - `active` — confers what the principal's roles and grants allow.
 * - `paused` — paused by the member (or their whole identity is paused):
 *   confers only permissions whose effect is `view`, at `low` or `medium`
 *   risk. A paused member is hidden from the group, so their reading of
 *   sensitive material would go unnoticed.
 * - `suspended`, `ended` — confer nothing.
 */
export type AuthorisationMembershipStatus = typeof AUTHORISATION_MEMBERSHIP_STATUSES[number]

/** A direct membership of the principal in a group, with what it confers now. */
export interface AuthorisationMembership {
  group: AuthorisationGroup
  status: AuthorisationMembershipStatus
}

export const AUTHORISATION_PRINCIPAL_STATUSES = ['active', 'paused', 'suspended'] as const

/**
 * The principal's own standing, whatever their memberships: `paused` when
 * the person has paused their whole account, `suspended` when it is
 * suspended or on its way to closure. It governs the personal group and
 * caps every membership, with the same meanings as a membership's status.
 */
export type AuthorisationPrincipalStatus = typeof AUTHORISATION_PRINCIPAL_STATUSES[number]

/**
 * The principal's group context, resolved by the host's directory adapter
 * for each decision.
 */
export interface AuthorisationActorContext {
  principalId: string
  /** The principal's own standing (contract 3). Anything but a known status confers nothing. */
  status: AuthorisationPrincipalStatus
  /**
   * The principal's own unary group, created with a human identity. Null for
   * identities that have none, such as non-human service identities.
   */
  personalGroup: AuthorisationGroup | null
  memberships: readonly AuthorisationMembership[]
}

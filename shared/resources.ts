/**
 * Resources and groups as Authorisation sees them. Re-exported from the
 * public contract.
 *
 * Authorisation stores no domain data and no groups. The domain capability
 * that owns a resource describes it with `AuthorisationResource`; Identity
 * (through the host's `AuthorisationDirectory` adapter) describes groups and
 * memberships.
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
   * The principal who created or is responsible for the resource, if any.
   * They receive the resource-owner role only while they remain a member of
   * the owning group (or its tenant), so leaving a group ends their access.
   */
  ownerPrincipalId?: string | null
  /** Attributes that role conditions may test, e.g. `{ status: 'draft' }`. */
  attributes?: Readonly<Record<string, AuthorisationAttributeValue>>
}

/** A reference to a resource, for grants and events. */
export interface AuthorisationResourceRef {
  type: string
  id: string
}

/**
 * Where a group sits: its ancestors from the tenant root down to the group
 * itself, e.g. `['company-a', 'london-office', 'sales']`. The first entry is
 * the tenant root, the isolation boundary. A personal group is its own root.
 *
 * Authorisation does not limit depth: that is Identity's rule.
 */
export type AuthorisationGroupLineage = readonly string[]

/** A group the principal currently belongs to, with its lineage. */
export interface AuthorisationMembership {
  groupId: string
  lineage: AuthorisationGroupLineage
}

/**
 * The principal's group context, resolved by the host's directory adapter
 * for each decision. Only current memberships appear: a principal who has
 * left a group is simply absent from it.
 */
export interface AuthorisationActorContext {
  principalId: string
  /** The principal's own unary group, created with their identity. */
  personalGroupId: string
  memberships: readonly AuthorisationMembership[]
}

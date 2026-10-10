import { z } from 'zod'
import type { AuthorisationDefaultRoles } from './changes'
import { identifierSchema, sha256DigestSchema } from './identifiers'
import type { AuthorisationRiskLevel } from './permissions'
import { roleDefinitionSchema } from './roles'
import type { AuthorisationGrantSubject, AuthorisationRoleAssignmentScope, AuthorisationRolePermission } from './roles'

/**
 * Administration views and documents (docs/contracts.md §16–§18): what the
 * `/api/authorisation/*` endpoints answer, and the versioned role document
 * an operator exports and imports. Opaque identifiers, role and permission
 * names, codes and instants only.
 */

/** Where the layer's endpoints are mounted. */
export const AUTHORISATION_API_PREFIX = '/api/authorisation'

/** Request header a client may send to carry its correlation identifier (a UUID). Otherwise the endpoint issues one. */
export const AUTHORISATION_CORRELATION_HEADER = 'x-correlation-id'

/** One assignment, with its provenance and review record. */
export interface AuthorisationAssignmentView {
  principalId: string
  groupId: string
  roleId: string
  scope: AuthorisationRoleAssignmentScope
  expiresAt: string | null
  assignedAt: string
  /** Who made it: a principal, or null when the host's own server code did (owners and default roles follow Identity). */
  assignedBy: string | null
  confirmedAt: string | null
  confirmedBy: string | null
}

/** One line of a group's access review. */
export interface AuthorisationAccessReviewEntry extends AuthorisationAssignmentView {
  /** When it was last confirmed, or made when never confirmed. */
  lastConfirmedAt: string
  /** When the next confirmation is due, or null without a review interval. */
  reviewDueAt: string | null
  /** Not confirmed within the interval. It keeps working until someone removes it. */
  overdue: boolean
}

export interface AuthorisationAccessReview {
  groupId: string
  reviewIntervalDays: number | null
  entries: AuthorisationAccessReviewEntry[]
}

/** A group's access settings. */
export interface AuthorisationGroupAccess {
  groupId: string
  tenantId: string
  defaultRoles: AuthorisationDefaultRoles
  reviewIntervalDays: number | null
}

/** A grant on a group's resources, as its managers see it. */
export interface AuthorisationGrantView {
  grantId: string
  resource: { type: string, id: string, owningGroupId: string }
  subject: AuthorisationGrantSubject
  permissions: string[]
  expiresAt: string | null
  grantedBy: string | null
  createdAt: string
}

/** A role a tenant's groups may assign: built-in or the tenant's own. */
export interface AuthorisationRoleView {
  id: string
  name: string
  description: string | null
  builtIn: boolean
  /** The highest risk among its permissions, wildcards resolved against the catalogue. */
  risk: AuthorisationRiskLevel
  permissions: AuthorisationRolePermission[]
}

export interface AuthorisationTenantRoles {
  tenantId: string
  roles: AuthorisationRoleView[]
}

/** The signed-in principal's own assignments: hints for the user experience only. */
export interface AuthorisationSelfView {
  principalId: string
  assignments: AuthorisationAssignmentView[]
}

// ---------------------------------------------------------------------------
// Role documents
// ---------------------------------------------------------------------------

export const AUTHORISATION_ROLE_DOCUMENT_FORMAT = 'nuxt4-layers.authorisation.roles'
export const AUTHORISATION_ROLE_DOCUMENT_VERSION = 1

/**
 * A tenant's custom roles as a versioned document (`exportAuthorisationRoles`,
 * `importAuthorisationRoles`). `digest` is the SHA-256 of the canonical JSON
 * of every other member (`canonicalJson`); roles are sorted by identifier
 * and identifiers are unique.
 */
export const roleDocumentSchema = z.strictObject({
  format: z.literal(AUTHORISATION_ROLE_DOCUMENT_FORMAT),
  formatVersion: z.literal(AUTHORISATION_ROLE_DOCUMENT_VERSION),
  tenantId: identifierSchema,
  roles: z.array(roleDefinitionSchema).max(500),
  digest: sha256DigestSchema,
}).superRefine((document, context) => {
  const ids = document.roles.map(role => role.id)
  if (new Set(ids).size !== ids.length) context.addIssue({ code: 'custom', path: ['roles'], message: 'Role identifiers must be unique' })
})

export type AuthorisationRoleDocument = z.infer<typeof roleDocumentSchema>

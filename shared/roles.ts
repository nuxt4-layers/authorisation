import { z } from 'zod'
import { isPermissionPattern } from './permissions'

/**
 * Roles, role assignments, grants and conditions. Re-exported from the public
 * contract.
 *
 * A role is a named set of permission patterns. A role assignment gives a
 * principal a role in a group; it takes effect only while the principal is an
 * active member of that group, and only in that group's tenant. By default it
 * covers resources owned by that group alone: the group hierarchy confers no
 * privilege unless the assignment explicitly asks for its descendants. A grant
 * gives a principal or a group permissions on one resource.
 */

const IDENTIFIER = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/

export const BUILT_IN_ROLE_IDS = ['owner', 'administrator', 'member', 'viewer'] as const
export type BuiltInRoleId = typeof BUILT_IN_ROLE_IDS[number]

export const CONDITION_OPERATORS = ['equals', 'not-equals', 'in', 'not-in'] as const
export type AuthorisationConditionOperator = typeof CONDITION_OPERATORS[number]

const scalar = z.union([z.string().max(256), z.number().finite(), z.boolean(), z.null()])

/**
 * A test on the resource, evaluated at decision time. `attribute` names a key
 * of `resource.attributes`, or `resource.creatorPrincipalId`.
 *
 * `value` is a literal, or `{ ref: 'subject.principalId' }` to compare with
 * the asking principal. A missing attribute never satisfies a condition.
 */
export const conditionSchema = z.object({
  attribute: z.string().regex(/^(?:resource\.creatorPrincipalId|resource\.attributes\.[a-zA-Z][a-zA-Z0-9_]{0,63})$/),
  operator: z.enum(CONDITION_OPERATORS),
  value: z.union([
    scalar,
    z.array(scalar).min(1).max(100),
    z.object({ ref: z.literal('subject.principalId') }).strict(),
  ]),
}).strict().superRefine((condition, context) => {
  const list = Array.isArray(condition.value)
  if ((condition.operator === 'in' || condition.operator === 'not-in') !== list) {
    context.addIssue({ code: 'custom', message: `'${condition.operator}' ${list ? 'does not take' : 'takes'} a list` })
  }
})

export type AuthorisationCondition = z.infer<typeof conditionSchema>

/** One entry of a role: a permission pattern and the conditions that must all hold. */
export const rolePermissionSchema = z.object({
  pattern: z.string().refine(isPermissionPattern, 'Expected a permission, <resource>:*, *:<action> or *'),
  when: z.array(conditionSchema).max(10).optional(),
}).strict()

export type AuthorisationRolePermission = z.infer<typeof rolePermissionSchema>

export const roleDefinitionSchema = z.object({
  id: z.string().regex(IDENTIFIER).max(64),
  name: z.string().trim().min(1).max(100),
  description: z.string().max(500).optional(),
  permissions: z.array(rolePermissionSchema).max(200),
}).strict()

export type AuthorisationRoleDefinition = z.infer<typeof roleDefinitionSchema>

/**
 * How far a role assignment reaches down the group hierarchy.
 *
 * - `group` — resources owned by the group itself. The default.
 * - `group-and-descendants` — also resources owned by groups below it, as an
 *   explicit, auditable choice. Moving a group elsewhere in the tree changes
 *   what such an assignment covers, so assigning this scope is a critical
 *   operation.
 */
export const ROLE_ASSIGNMENT_SCOPES = ['group', 'group-and-descendants'] as const
export type AuthorisationRoleAssignmentScope = typeof ROLE_ASSIGNMENT_SCOPES[number]

/** A role held by a principal in a group. */
export interface AuthorisationRoleAssignment {
  principalId: string
  groupId: string
  roleId: string
  scope: AuthorisationRoleAssignmentScope
}

export type AuthorisationGrantSubject =
  | { kind: 'principal', principalId: string }
  | { kind: 'group', groupId: string }

/** Permissions on one resource, given to a principal or to a group's members. */
export interface AuthorisationGrant {
  resource: { type: string, id: string }
  subject: AuthorisationGrantSubject
  /** Exact permission names; grants never use wildcards. */
  permissions: readonly string[]
  /** ISO 8601 expiry, or null for a grant that lasts until it is revoked. */
  expiresAt: string | null
}

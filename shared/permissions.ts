import { z } from 'zod'

/**
 * The permission catalogue. Each domain capability declares the permissions
 * it enforces; the host supplies the combined catalogue at composition. A
 * permission that is not in the catalogue is never granted, so a typo fails
 * closed instead of silently matching nothing (or everything).
 *
 * A permission names one business capability as `<resource>:<action>`:
 *
 * - `<resource>` is a plural noun, optionally namespaced with dots
 *   (`orders`, `blog.comments`, `authorisation.roles`);
 * - `<action>` is a verb or verb phrase in snake case
 *   (`view`, `create`, `process_refund`).
 *
 * Scope never appears in the name (`orders:view`, not `orders:view_own`):
 * where a permission applies is decided by group membership, ownership and
 * grants.
 */

export const AUTHORISATION_RISK_LEVELS = ['low', 'medium', 'high', 'critical'] as const

/**
 * - `low` — reads non-sensitive data.
 * - `medium` — changes data reversibly.
 * - `high` — financial, legal, personal-data or hard-to-reverse operations.
 * - `critical` — destructive operations, or changes to who may do what.
 */
export type AuthorisationRiskLevel = typeof AUTHORISATION_RISK_LEVELS[number]

const SEGMENT = '[a-z][a-z0-9]*(?:-[a-z0-9]+)*'
const RESOURCE = `${SEGMENT}(?:\\.${SEGMENT})*`
const ACTION = '[a-z][a-z0-9]*(?:_[a-z0-9]+)*'

const PERMISSION_NAME = new RegExp(`^${RESOURCE}:${ACTION}$`)

/**
 * A permission pattern used in role definitions:
 * an exact name, `<resource>:*`, `*:<action>` or `*`.
 */
const PERMISSION_PATTERN = new RegExp(`^(?:\\*|${RESOURCE}:\\*|\\*:${ACTION}|${RESOURCE}:${ACTION})$`)

export function isPermissionName(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 128 && PERMISSION_NAME.test(value)
}

export function isPermissionPattern(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 128 && PERMISSION_PATTERN.test(value)
}

/** True when `pattern` covers `permission`. Patterns never span a `:`. */
export function permissionPatternMatches(pattern: string, permission: string): boolean {
  if (pattern === '*' || pattern === permission) return true
  const [patternResource, patternAction] = pattern.split(':')
  const [resource, action] = permission.split(':')
  if (patternAction === '*') return patternResource === resource
  if (patternResource === '*') return patternAction === action
  return false
}

/** True when the pattern is a wildcard rather than an exact permission name. */
export function isWildcardPattern(pattern: string): boolean {
  return pattern.includes('*')
}

export const permissionDefinitionSchema = z.object({
  name: z.string().refine(isPermissionName, 'Expected <resource>:<action>, e.g. orders:view'),
  /** Human-readable business capability, for administrators choosing roles. */
  description: z.string().trim().min(1).max(500),
  risk: z.enum(AUTHORISATION_RISK_LEVELS),
}).strict()

export type AuthorisationPermissionDefinition = z.infer<typeof permissionDefinitionSchema>

/** A validated catalogue, keyed by permission name. */
export type AuthorisationPermissionCatalogue = ReadonlyMap<string, AuthorisationPermissionDefinition>

/**
 * The permissions this capability enforces on its own administration. They are
 * always part of the catalogue; the host does not supply them.
 */
export const AUTHORISATION_PERMISSIONS: readonly AuthorisationPermissionDefinition[] = [
  { name: 'authorisation.roles:view', description: 'See the roles defined in a group and who holds them', risk: 'low' },
  { name: 'authorisation.grants:manage', description: 'Share or stop sharing a resource with a user or group', risk: 'high' },
  { name: 'authorisation.role-assignments:manage', description: 'Give members roles in a group, or take them away', risk: 'critical' },
  { name: 'authorisation.roles:manage', description: 'Define, change or delete a group\'s custom roles', risk: 'critical' },
]

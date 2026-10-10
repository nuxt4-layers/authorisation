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

export const AUTHORISATION_PERMISSION_EFFECTS = ['view', 'change'] as const

/**
 * What a permission does, declared by the capability that defines it:
 *
 * - `view` — only reads.
 * - `change` — anything else. A definition without an effect is `change`, so
 *   an undeclared permission fails closed for paused members.
 *
 * The action's name decides nothing: `orders:view` is a view only if its
 * definition says so.
 */
export type AuthorisationPermissionEffect = typeof AUTHORISATION_PERMISSION_EFFECTS[number]

export const permissionDefinitionSchema = z.object({
  name: z.string().refine(isPermissionName, 'Expected <resource>:<action>, e.g. orders:view'),
  /** Human-readable business capability, for administrators choosing roles. */
  description: z.string().trim().min(1).max(500),
  risk: z.enum(AUTHORISATION_RISK_LEVELS),
  effect: z.enum(AUTHORISATION_PERMISSION_EFFECTS).default('change'),
}).strict()

/** A permission as the catalogue holds it, with its effect resolved. */
export type AuthorisationPermissionDefinition = z.output<typeof permissionDefinitionSchema>

/** A permission as a capability declares it: `effect` may be left out, meaning `change`. */
export type AuthorisationPermissionDefinitionInput = z.input<typeof permissionDefinitionSchema>

/** A validated catalogue, keyed by permission name. */
export type AuthorisationPermissionCatalogue = ReadonlyMap<string, AuthorisationPermissionDefinition>

/**
 * The permissions this capability enforces on its own administration. They are
 * always part of the catalogue; the host does not supply them.
 */
export const AUTHORISATION_PERMISSIONS: readonly AuthorisationPermissionDefinition[] = [
  { name: 'authorisation.roles:view', description: 'See the roles defined in a group and who holds them', risk: 'low', effect: 'view' },
  { name: 'authorisation.grants:manage', description: 'Share or stop sharing a resource with a user or group', risk: 'high', effect: 'change' },
  // The floor for any assignment (contract 4): each change's own risk, from the role it assigns, sets its approval and step-up.
  { name: 'authorisation.role-assignments:manage', description: 'Give members roles in a group, take them away, and confirm them in an access review', risk: 'medium', effect: 'change' },
  { name: 'authorisation.roles:manage', description: 'Define, change or delete a tenant\'s custom roles', risk: 'critical', effect: 'change' },
  { name: 'authorisation.group-access:manage', description: 'Set a group\'s default roles and its access review interval', risk: 'high', effect: 'change' },
]

/** The permission each of Authorisation's own administration permissions is called by. */
export type AuthorisationAdministrationPermission =
  | 'authorisation.roles:view'
  | 'authorisation.grants:manage'
  | 'authorisation.role-assignments:manage'
  | 'authorisation.roles:manage'
  | 'authorisation.group-access:manage'

/** The higher of two risk levels. */
export function higherRisk(a: AuthorisationRiskLevel, b: AuthorisationRiskLevel): AuthorisationRiskLevel {
  return AUTHORISATION_RISK_LEVELS.indexOf(a) >= AUTHORISATION_RISK_LEVELS.indexOf(b) ? a : b
}

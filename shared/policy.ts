import { z } from 'zod'
import { AUTHORISATION_RISK_LEVELS } from './permissions'
import type { AuthorisationRiskLevel } from './permissions'
import { BUILT_IN_ROLE_IDS, rolePermissionSchema } from './roles'
import type { AuthorisationRolePermission, BuiltInRoleId } from './roles'
import type { AuthorisationAssuranceRequirement } from './subject'

/**
 * Authorisation policy. The defaults are secure; a host may tighten them, and
 * may loosen them only above the floors enforced here. Any loosening needs a
 * documented risk treatment (docs/threat-model.md).
 */
export interface AuthorisationPolicy {
  /** What each risk level demands of the session before a permission is allowed. */
  assurance: Readonly<Record<AuthorisationRiskLevel, AuthorisationAssuranceRequirement>>
  /** Permissions of the built-in roles. */
  roles: Readonly<Record<BuiltInRoleId, readonly AuthorisationRolePermission[]>>
  /** The built-in role a resource's owner holds on that resource. */
  resourceOwnerRole: BuiltInRoleId
  /**
   * Whether a grant takes effect outside the resource's tenant: to a principal
   * who is not a member of it, or to a group in another tenant (including a
   * personal group). Off by default: information stays inside its tenant.
   */
  externalGrants: boolean
}

const requirement = (minimumLevel: 'aal1' | 'aal2', phishingResistant = false, maxAuthenticationAgeSeconds: number | null = null) =>
  ({ minimumLevel, phishingResistant, maxAuthenticationAgeSeconds })

export const DEFAULT_AUTHORISATION_POLICY: AuthorisationPolicy = Object.freeze({
  assurance: Object.freeze({
    low: requirement('aal1'),
    medium: requirement('aal1'),
    high: requirement('aal2'),
    critical: requirement('aal2', true, 900),
  }),
  roles: Object.freeze({
    // Wildcards never cover high or critical permissions: those are listed by name.
    owner: [
      { pattern: '*' },
      { pattern: 'authorisation.grants:manage' },
      { pattern: 'authorisation.role-assignments:manage' },
      { pattern: 'authorisation.roles:manage' },
    ],
    administrator: [
      { pattern: '*' },
      { pattern: 'authorisation.grants:manage' },
    ],
    member: [{ pattern: '*:view' }, { pattern: '*:create' }],
    viewer: [{ pattern: '*:view' }],
  }),
  resourceOwnerRole: 'owner',
  externalGrants: false,
})

const levelRank = { aal1: 1, aal2: 2 } as const

const requirementSchema = z.object({
  minimumLevel: z.enum(['aal1', 'aal2']),
  phishingResistant: z.boolean(),
  maxAuthenticationAgeSeconds: z.number().int().min(60).max(86_400).nullable(),
}).strict()

const requirementOverride = requirementSchema.partial().optional()
const rolePermissions = z.array(rolePermissionSchema).max(200).optional()

const policyInputSchema = z.object({
  assurance: z.object({
    low: requirementOverride,
    medium: requirementOverride,
    high: requirementOverride,
    critical: requirementOverride,
  }).strict().optional(),
  roles: z.object({
    owner: rolePermissions,
    administrator: rolePermissions,
    member: rolePermissions,
    viewer: rolePermissions,
  }).strict().optional(),
  resourceOwnerRole: z.enum(BUILT_IN_ROLE_IDS).optional(),
  externalGrants: z.boolean().optional(),
}).strict()

export type AuthorisationPolicyInput = z.input<typeof policyInputSchema>

/**
 * Merges host overrides onto the defaults and enforces the floors:
 *
 * - `high` and `critical` permissions need at least `aal2`;
 * - `critical` permissions need a session authenticated within the last hour;
 * - no risk level demands less than the level below it.
 *
 * Throws a `ZodError` or `TypeError` for invalid input, so a bad policy fails
 * at startup rather than at the first decision.
 */
export function resolveAuthorisationPolicy(input: AuthorisationPolicyInput = {}): AuthorisationPolicy {
  const parsed = policyInputSchema.parse(input)
  const defaults = DEFAULT_AUTHORISATION_POLICY

  const assurance = Object.fromEntries(AUTHORISATION_RISK_LEVELS.map(level =>
    [level, { ...defaults.assurance[level], ...parsed.assurance?.[level] }])) as Record<AuthorisationRiskLevel, AuthorisationAssuranceRequirement>

  for (const level of ['high', 'critical'] as const) {
    if (assurance[level].minimumLevel !== 'aal2') {
      throw new TypeError(`Authorisation policy: '${level}' permissions must require aal2.`)
    }
  }
  const criticalAge = assurance.critical.maxAuthenticationAgeSeconds
  if (criticalAge === null || criticalAge > 3600) {
    throw new TypeError('Authorisation policy: \'critical\' permissions must require authentication within the last 3600 seconds.')
  }
  for (let index = 1; index < AUTHORISATION_RISK_LEVELS.length; index++) {
    const lower = assurance[AUTHORISATION_RISK_LEVELS[index - 1]!]
    const higher = assurance[AUTHORISATION_RISK_LEVELS[index]!]
    const weaker = levelRank[higher.minimumLevel] < levelRank[lower.minimumLevel]
      || (lower.phishingResistant && !higher.phishingResistant)
      || (lower.maxAuthenticationAgeSeconds !== null
        && (higher.maxAuthenticationAgeSeconds === null || higher.maxAuthenticationAgeSeconds > lower.maxAuthenticationAgeSeconds))
    if (weaker) {
      throw new TypeError(`Authorisation policy: '${AUTHORISATION_RISK_LEVELS[index]}' must not demand less than '${AUTHORISATION_RISK_LEVELS[index - 1]}'.`)
    }
  }

  return Object.freeze({
    assurance: Object.freeze(assurance),
    roles: Object.freeze({ ...defaults.roles, ...parsed.roles }),
    resourceOwnerRole: parsed.resourceOwnerRole ?? defaults.resourceOwnerRole,
    externalGrants: parsed.externalGrants ?? defaults.externalGrants,
  })
}

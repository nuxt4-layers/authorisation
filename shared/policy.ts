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
  /**
   * The built-in role every principal holds in their own personal group, or
   * null for none. A personal group has exactly one member, so this decides
   * what users may do with the resources they keep for themselves.
   */
  personalGroupRole: BuiltInRoleId | null
  /**
   * Whether a grant takes effect outside the resource's tenant: to a principal
   * who is not a member of it, or to a group in another tenant (including a
   * personal group). Off by default: information stays inside its tenant.
   */
  externalGrants: boolean
  /**
   * How long records are kept once their purpose is over (iam-integration
   * retention), in days: delivered outbox events and decided changes.
   * Shorter than the default needs `riskTreatment`.
   */
  retention: Readonly<{ outboxDays: number, changeDays: number }>
  /** Reference to the documented risk treatment for a shorter retention, or null. */
  riskTreatment: string | null
}

/** Retention periods in days: default and hard bounds. */
export const AUTHORISATION_RETENTION_BOUNDS = Object.freeze({
  outboxDays: { default: 30, min: 7, max: 365 },
  changeDays: { default: 730, min: 365, max: 2555 },
} as const)

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
      { pattern: 'authorisation.group-access:manage' },
    ],
    // `*` covers `authorisation.role-assignments:manage` (medium): administrators
    // request assignments, and each assignment's own risk sets its approval.
    administrator: [
      { pattern: '*' },
      { pattern: 'authorisation.grants:manage' },
    ],
    member: [{ pattern: '*:view' }, { pattern: '*:create' }],
    viewer: [{ pattern: '*:view' }],
  }),
  personalGroupRole: 'owner',
  externalGrants: false,
  retention: Object.freeze({ outboxDays: AUTHORISATION_RETENTION_BOUNDS.outboxDays.default, changeDays: AUTHORISATION_RETENTION_BOUNDS.changeDays.default }),
  riskTreatment: null,
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
  personalGroupRole: z.enum(BUILT_IN_ROLE_IDS).nullable().optional(),
  externalGrants: z.boolean().optional(),
  retention: z.object({
    outboxDays: z.number().int().min(AUTHORISATION_RETENTION_BOUNDS.outboxDays.min).max(AUTHORISATION_RETENTION_BOUNDS.outboxDays.max).optional(),
    changeDays: z.number().int().min(AUTHORISATION_RETENTION_BOUNDS.changeDays.min).max(AUTHORISATION_RETENTION_BOUNDS.changeDays.max).optional(),
  }).strict().optional(),
  riskTreatment: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,63}$/).nullable().optional(),
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

  const retention = { ...defaults.retention, ...parsed.retention }
  const riskTreatment = parsed.riskTreatment ?? null
  for (const key of ['outboxDays', 'changeDays'] as const) {
    if (retention[key] < AUTHORISATION_RETENTION_BOUNDS[key].default && !riskTreatment) {
      throw new TypeError(`Authorisation policy: retention.${key} below its default needs a riskTreatment reference.`)
    }
  }

  return Object.freeze({
    assurance: Object.freeze(assurance),
    roles: Object.freeze({ ...defaults.roles, ...parsed.roles }),
    personalGroupRole: parsed.personalGroupRole === undefined ? defaults.personalGroupRole : parsed.personalGroupRole,
    externalGrants: parsed.externalGrants ?? defaults.externalGrants,
    retention: Object.freeze(retention),
    riskTreatment,
  })
}

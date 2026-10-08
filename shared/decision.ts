import type { AuthorisationAssuranceRequirement } from './subject'

/**
 * The outcome of one authorisation check: may this subject perform this
 * permission on this resource, now?
 *
 * Reasons are for the server and for audit. Only the coarse error codes in
 * `errors.ts` cross the HTTP boundary.
 */

/** What allowed the permission. */
export type AuthorisationGrantSource =
  | 'role'
  | 'personal-group'
  | 'grant'

/**
 * Why a permission was refused.
 *
 * - `unknown-permission` — not in the catalogue (fails closed).
 * - `unknown-subject` — the directory does not know the principal.
 * - `unknown-group` — the directory does not know the resource's owning group.
 * - `tenant-mismatch` — the resource belongs to a different tenant from the
 *   request's tenant context.
 * - `not-permitted` — no role, personal-group role or grant covers it.
 * - `insufficient-assurance` — permitted, but the session must step up or
 *   re-authenticate first; `requirement` says how.
 */
export type AuthorisationDenialReason =
  | 'unknown-permission'
  | 'unknown-subject'
  | 'unknown-group'
  | 'tenant-mismatch'
  | 'not-permitted'
  | 'insufficient-assurance'

export type AuthorisationDecision =
  | {
    allowed: true
    permission: string
    via: AuthorisationGrantSource
  }
  | {
    allowed: false
    permission: string
    reason: AuthorisationDenialReason
    /** Present when `reason` is `insufficient-assurance`. */
    requirement: AuthorisationAssuranceRequirement | null
  }

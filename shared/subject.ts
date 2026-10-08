/**
 * Who is asking. Re-exported from the public contract.
 *
 * `AuthorisationSubject` is a structural subset of the Authentication
 * capability's `AuthenticatedPrincipal`, so a host passes that principal
 * straight through without either capability importing the other.
 */

/** Authentication assurance level, aligned with NIST SP 800-63-4 terminology. */
export type AuthorisationAssuranceLevel = 'aal1' | 'aal2'

export interface AuthorisationSubjectAssurance {
  level: AuthorisationAssuranceLevel
  /** True when the session used a phishing-resistant method (e.g. a passkey). */
  phishingResistant: boolean
}

export interface AuthorisationSubject {
  /** Stable, opaque principal identifier issued by Authentication. */
  principalId: string
  /** ISO 8601 timestamp of the most recent primary or step-up authentication. */
  authenticatedAt: string
  assurance: AuthorisationSubjectAssurance
}

/**
 * What a permission's risk level demands of the session. Returned in a
 * decision so the host can send the user to step up or re-authenticate.
 */
export interface AuthorisationAssuranceRequirement {
  minimumLevel: AuthorisationAssuranceLevel
  phishingResistant: boolean
  /** Maximum seconds since `authenticatedAt`, or null for no limit. */
  maxAuthenticationAgeSeconds: number | null
}

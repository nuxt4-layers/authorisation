/**
 * Documented failure categories at the authorisation boundary.
 *
 * `forbidden` is deliberately coarse: it never says whether the resource
 * exists, which group owns it, or which rule refused. A domain capability that
 * must hide a resource's existence answers `not found` from its own contract
 * instead.
 */
export const AUTHORISATION_ERROR_CODES = [
  'unauthenticated',
  'forbidden',
  'insufficient-assurance',
  'validation-failed',
  'unavailable',
] as const

export type AuthorisationErrorCode = typeof AUTHORISATION_ERROR_CODES[number]

/** HTTP status used when an error code crosses the HTTP boundary. */
export const AUTHORISATION_ERROR_STATUS: Readonly<Record<AuthorisationErrorCode, number>> = {
  'unauthenticated': 401,
  'forbidden': 403,
  'insufficient-assurance': 403,
  'validation-failed': 400,
  'unavailable': 503,
}

/** JSON body returned by the layer's HTTP endpoints on failure. */
export interface AuthorisationErrorBody {
  code: AuthorisationErrorCode
  /** Localisation key for the user-facing message, e.g. `authorisation.error.forbidden`. */
  messageKey: string
}

export function isAuthorisationErrorCode(value: unknown): value is AuthorisationErrorCode {
  return typeof value === 'string' && (AUTHORISATION_ERROR_CODES as readonly string[]).includes(value)
}

/**
 * Raised when the host application has not supplied a required port. The
 * layer fails closed: it never falls back to an implicit store or directory.
 */
export class AuthorisationCompositionError extends Error {
  readonly port: string

  constructor(port: string) {
    super(`Authorisation port '${port}' has not been supplied by the host application. See docs/composition-contract.md.`)
    this.name = 'AuthorisationCompositionError'
    this.port = port
  }
}

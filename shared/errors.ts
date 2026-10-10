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
  'conflict',
  'unavailable',
] as const

export type AuthorisationErrorCode = typeof AUTHORISATION_ERROR_CODES[number]

/** HTTP status used when an error code crosses the HTTP boundary. */
export const AUTHORISATION_ERROR_STATUS: Readonly<Record<AuthorisationErrorCode, number>> = {
  'unauthenticated': 401,
  'forbidden': 403,
  'insufficient-assurance': 403,
  'validation-failed': 400,
  'conflict': 409,
  'unavailable': 503,
}

/** JSON body returned by the layer's HTTP endpoints on failure. */
export interface AuthorisationErrorBody {
  code: AuthorisationErrorCode
  /** Localisation key for the user-facing message, e.g. `authorisation.error.forbidden`. */
  messageKey: string
  /**
   * For `conflict` and `validation-failed` only: the rule that refused, as a
   * code (`self-grant`, `owner-role`, `change-differs`). A conflict is only
   * ever reported to a caller entitled to see what it is about; anyone else
   * is answered `forbidden` (contract 4).
   */
  reason?: string
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

const REASON = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/

/**
 * A server function's failure, carrying a contract code. `unavailable` means
 * the directory, the governance port, the database or the clock failed, and
 * the operation failed closed. `reason` is the rule behind a `conflict` or
 * `validation-failed`, when `detail` is a rule code.
 */
export class AuthorisationFailure extends Error {
  readonly code: AuthorisationErrorCode
  readonly reason: string | null

  constructor(code: AuthorisationErrorCode, detail?: string) {
    super(detail ? `${code}: ${detail}` : code)
    this.name = 'AuthorisationFailure'
    this.code = code
    this.reason = detail && (code === 'conflict' || code === 'validation-failed') && REASON.test(detail) && detail.length <= 64 ? detail : null
  }
}

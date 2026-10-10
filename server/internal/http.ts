import { randomUUID } from 'node:crypto'
import type { H3Event } from 'h3'
import { createError, defineEventHandler, getRequestHeader, getRequestURL, getRouterParam, isError, readBody, setResponseStatus } from 'h3'
import { z } from 'zod'
import type { AuthorisationErrorBody, AuthorisationErrorCode, AuthorisationSubject } from '../../contracts'
import {
  AUTHORISATION_API_PREFIX,
  AUTHORISATION_CORRELATION_HEADER,
  AUTHORISATION_ERROR_STATUS,
  AuthorisationCompositionError,
  AuthorisationFailure,
  IDENTIFIER_PATTERN,
  identifierSchema,
  instantSchema,
  UUID_PATTERN,
} from '../../contracts'
import { useAuthorisationSubjectResolver } from '../utils/authorisation-composition'

/**
 * PRIVATE. The HTTP boundary of the layer's `/api/authorisation/*`
 * endpoints (docs/contracts.md §16).
 *
 * - Errors cross as `AuthorisationErrorBody`: the contract code, a
 *   localisation key, and, for `conflict` and `validation-failed` only, the
 *   rule as a code. `forbidden` never says why. Unexpected failures are
 *   logged without detail and answered `unavailable`.
 * - Bodies are JSON objects parsed with strict schemas.
 * - The subject comes only from the host's subject resolver
 *   (Authentication), never from the request.
 */

export function authorisationHttpError(code: AuthorisationErrorCode, reason?: string | null) {
  const data: AuthorisationErrorBody = { code, messageKey: `authorisation.error.${code}` }
  if (reason && (code === 'conflict' || code === 'validation-failed')) data.reason = reason
  return createError({ statusCode: AUTHORISATION_ERROR_STATUS[code], statusMessage: code, data })
}

/** Translates anything thrown inside a handler into a contract error. */
export function toHttpError(error: unknown) {
  if (isError(error)) return error
  if (error instanceof AuthorisationFailure) {
    if (error.code === 'unavailable') console.error('[authorisation] request failed:', error.message)
    return authorisationHttpError(error.code, error.reason)
  }
  if (error instanceof AuthorisationCompositionError) {
    console.error(`[authorisation] ${error.message}`)
    return authorisationHttpError('unavailable')
  }
  console.error('[authorisation] unexpected failure:', error instanceof Error ? error.message : error)
  return authorisationHttpError('unavailable')
}

/** Wraps a handler so that every failure leaves as a contract error. */
export function authorisationHandler<T>(run: (event: H3Event) => Promise<T>) {
  return defineEventHandler(async (event) => {
    try {
      return await run(event)
    }
    catch (error) {
      throw toHttpError(error)
    }
  })
}

/** The request's correlation identifier: the client's, when it sent a valid one, otherwise a new one. */
export function correlationOf(event: H3Event): string {
  const sent = getRequestHeader(event, AUTHORISATION_CORRELATION_HEADER)?.toLowerCase()
  return sent && UUID_PATTERN.test(sent) ? sent : randomUUID()
}

const subjectSchema = z.object({
  principalId: identifierSchema,
  authenticatedAt: instantSchema,
  assurance: z.object({ level: z.enum(['aal1', 'aal2']), phishingResistant: z.boolean() }),
})

/** The signed-in subject, from the host's resolver. `unauthenticated` without one; `unavailable` if the resolver fails. */
export async function requireSubject(event: H3Event): Promise<AuthorisationSubject> {
  const resolver = useAuthorisationSubjectResolver()
  let subject: unknown
  try {
    subject = await resolver.resolve(event)
  }
  catch {
    throw new AuthorisationFailure('unavailable', 'subject resolver failed')
  }
  if (subject == null) throw new AuthorisationFailure('unauthenticated')
  const parsed = subjectSchema.safeParse(subject)
  if (!parsed.success) throw new AuthorisationFailure('unavailable', 'subject resolver returned a malformed subject')
  return { principalId: parsed.data.principalId, authenticatedAt: parsed.data.authenticatedAt, assurance: parsed.data.assurance }
}

/** A route parameter that must be an opaque identifier. */
export function identifierParam(event: H3Event, name: string): string {
  const value = getRouterParam(event, name, { decode: true })
  if (!value || !IDENTIFIER_PATTERN.test(value)) throw new AuthorisationFailure('validation-failed')
  return value
}

/** A route parameter that must be a UUID (a change). */
export function uuidParam(event: H3Event, name: string): string {
  const value = getRouterParam(event, name)?.toLowerCase()
  if (!value || !UUID_PATTERN.test(value)) throw new AuthorisationFailure('validation-failed')
  return value
}

/** The JSON body, parsed with a strict schema. A missing body is an empty object. */
export async function readJson<T>(event: H3Event, schema: z.ZodType<T>): Promise<T> {
  let body: unknown
  try {
    body = await readBody(event)
  }
  catch {
    throw new AuthorisationFailure('validation-failed')
  }
  const parsed = schema.safeParse(body ?? {})
  if (!parsed.success) throw new AuthorisationFailure('validation-failed')
  return parsed.data
}

export function created(event: H3Event): void {
  setResponseStatus(event, 201)
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

/**
 * CSRF defence for the layer's state-changing endpoints, as Identity's and
 * Authentication's: the request must carry an Origin (or, failing that, a
 * Referer) matching the configured base URL. Without a configured base URL,
 * every state-changing request is refused.
 */
export function originRejected(event: H3Event, baseUrl: string | undefined): boolean {
  if (!getRequestURL(event).pathname.startsWith(`${AUTHORISATION_API_PREFIX}/`)) return false
  if (SAFE_METHODS.has(event.method)) return false
  let expected: string
  try {
    expected = new URL(baseUrl ?? '').origin
  }
  catch {
    return true
  }
  const origin = getRequestHeader(event, 'origin')
  const referer = getRequestHeader(event, 'referer')
  try {
    const actual = origin ? new URL(origin).origin : referer ? new URL(referer).origin : null
    return actual !== expected
  }
  catch {
    return true
  }
}

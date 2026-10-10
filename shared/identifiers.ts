import { z } from 'zod'

/**
 * Identifiers, codes, instants and digests: the only kinds of value
 * Authorisation keeps about people, changes and events besides role and
 * permission names. Each is constrained by a pattern, so none can carry a
 * name, an email address or other free text (docs/contracts.md §14).
 */

/**
 * An opaque identifier of a principal, group, tenant, role or resource, as
 * the directory and the domain capabilities issue it. Authorisation does not
 * assume any format beyond this: no `@`, no spaces.
 */
export const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
export const identifierSchema = z.string().regex(IDENTIFIER_PATTERN, 'Expected an opaque identifier')

/** Any RFC 9562 UUID, lower case: change, grant, event and correlation identifiers. */
export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
export const uuidSchema = z.string().regex(UUID_PATTERN, 'Expected a lower-case UUID')

/** The correlation identifier of the request that started a process (iam-integration architecture §5). */
export const correlationIdSchema = uuidSchema

/** ISO 8601 instant in UTC, e.g. `2026-10-10T12:00:00.000Z`. */
export const instantSchema = z.iso.datetime()

/** A reason code, never free text: `left-organisation`, `audit-finding`. */
export const REASON_CODE_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/
export const reasonCodeSchema = z.string().max(64).regex(REASON_CODE_PATTERN, 'Expected a reason code such as audit-finding')

/** A reference that justifies a change where the group requires one, such as a ticket number (`CHG-1042`). Never a sentence. */
export const justificationReferenceSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,63}$/, 'Expected a reference such as CHG-1042')

/** Lower-case hexadecimal SHA-256 digest. */
export const sha256DigestSchema = z.string().regex(/^[0-9a-f]{64}$/, 'Expected a SHA-256 digest')

/** Aggregate version: starts at 1 and increases by one with every change. */
export const versionSchema = z.number().int().min(1)

/**
 * Canonical JSON (docs/contracts.md §15): object keys sorted by code point,
 * no whitespace, arrays in order, `undefined` members left out. The digest
 * of a pending change and of a role document is the SHA-256 of this text,
 * in UTF-8, so the same content always has the same digest.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) throw new TypeError('canonicalJson: numbers must be finite')
    if (value === undefined || typeof value === 'function' || typeof value === 'symbol' || typeof value === 'bigint') {
      throw new TypeError('canonicalJson: unsupported value')
    }
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(item => canonicalJson(item === undefined ? null : item)).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, item]) => item !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(',')}}`
}

import { createHash } from 'node:crypto'
import { canonicalJson } from '../../contracts'

/** PRIVATE. SHA-256 of the canonical JSON of a value (docs/contracts.md §15), lower-case hexadecimal. */
export function digestOf(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')
}

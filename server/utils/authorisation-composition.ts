import type {
  AuthorisationDatabase,
  AuthorisationDirectory,
  AuthorisationEvent,
  AuthorisationEventSink,
  AuthorisationPermissionCatalogue,
  AuthorisationPermissionDefinition,
  AuthorisationPolicy,
  AuthorisationPolicyInput,
} from '../../contracts'
import {
  AUTHORISATION_PERMISSIONS,
  AuthorisationCompositionError,
  isPermissionPattern,
  permissionDefinitionSchema,
  resolveAuthorisationPolicy,
} from '../../contracts'

/**
 * Composition registry. The host application calls the `provide*` functions
 * from a Nitro plugin; the layer's server code calls the `use*` functions.
 *
 * Required ports fail closed: using one before it is supplied throws
 * `AuthorisationCompositionError` instead of falling back to an implicit
 * store or directory.
 */

let database: (AuthorisationDatabase & { schema: string }) | null = null
let directory: AuthorisationDirectory | null = null
let eventSink: AuthorisationEventSink | null = null
let policy: AuthorisationPolicy | null = null
const catalogue = new Map<string, AuthorisationPermissionDefinition>(
  AUTHORISATION_PERMISSIONS.map(definition => [definition.name, definition]),
)

export function provideAuthorisationDatabase(next: AuthorisationDatabase): void {
  if (next?.dialect !== 'postgres' || typeof next.pool?.query !== 'function') {
    throw new TypeError('provideAuthorisationDatabase expects { dialect: \'postgres\', pool } with a pg-compatible pool.')
  }
  const schema = next.schema ?? 'authorisation'
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(schema)) {
    throw new TypeError(`Invalid authorisation schema name '${schema}'.`)
  }
  database = { ...next, schema }
}

export function provideAuthorisationDirectory(next: AuthorisationDirectory): void {
  if (typeof next?.resolveActor !== 'function' || typeof next.getGroupLineage !== 'function') {
    throw new TypeError('provideAuthorisationDirectory expects an object with resolveActor(principalId) and getGroupLineage(groupId) functions.')
  }
  directory = next
}

export function provideAuthorisationEventSink(next: AuthorisationEventSink): void {
  if (typeof next?.emit !== 'function') {
    throw new TypeError('provideAuthorisationEventSink expects an object with an emit(event) function.')
  }
  eventSink = next
}

/**
 * Adds domain capabilities' permissions to the catalogue. May be called once
 * per capability. Every definition is validated, and redefining a name with a
 * different description or risk is refused, so two capabilities cannot
 * silently disagree about what a permission means.
 */
export function provideAuthorisationPermissions(definitions: readonly AuthorisationPermissionDefinition[]): void {
  if (!Array.isArray(definitions)) {
    throw new TypeError('provideAuthorisationPermissions expects an array of permission definitions.')
  }
  const parsed = definitions.map(definition => permissionDefinitionSchema.parse(definition))
  for (const definition of parsed) {
    const existing = catalogue.get(definition.name)
    if (existing && (existing.risk !== definition.risk || existing.description !== definition.description)) {
      throw new TypeError(`Permission '${definition.name}' is already defined differently.`)
    }
  }
  for (const definition of parsed) catalogue.set(definition.name, Object.freeze(definition))
  if (policy) assertRolesNameKnownPermissions(policy)
}

/** Validates and stores the host's policy overrides. Invalid policy throws at startup. */
export function provideAuthorisationPolicy(input: AuthorisationPolicyInput): void {
  const next = resolveAuthorisationPolicy(input)
  assertRolesNameKnownPermissions(next)
  policy = next
}

/**
 * A role that names an exact permission the catalogue does not contain is a
 * typo or a missing capability. Refuse it at composition rather than let it
 * grant nothing silently. Wildcard patterns may match nothing yet.
 */
function assertRolesNameKnownPermissions(candidate: AuthorisationPolicy): void {
  for (const [roleId, permissions] of Object.entries(candidate.roles)) {
    for (const { pattern } of permissions) {
      if (isPermissionPattern(pattern) && !pattern.includes('*') && !catalogue.has(pattern)) {
        throw new TypeError(`Role '${roleId}' names permission '${pattern}', which is not in the catalogue.`)
      }
    }
  }
}

export function useAuthorisationDatabase(): AuthorisationDatabase & { schema: string } {
  if (!database) throw new AuthorisationCompositionError('AuthorisationDatabase')
  return database
}

export function useAuthorisationDirectory(): AuthorisationDirectory {
  if (!directory) throw new AuthorisationCompositionError('AuthorisationDirectory')
  return directory
}

/** The permission catalogue: this layer's own permissions plus those the host supplied. */
export function useAuthorisationCatalogue(): AuthorisationPermissionCatalogue {
  return catalogue
}

/** The effective policy: host overrides when supplied, otherwise the secure defaults. */
export function useAuthorisationPolicy(): AuthorisationPolicy {
  if (!policy) policy = resolveAuthorisationPolicy()
  return policy
}

/**
 * Emits an event to the host's sink, if one is supplied. Never throws: audit
 * delivery must not change the outcome of the operation that produced it.
 */
export async function emitAuthorisationEvent(event: AuthorisationEvent): Promise<void> {
  if (!eventSink) return
  try {
    await eventSink.emit(event)
  }
  catch (error) {
    console.error(`[authorisation] event sink failed for '${event.type}':`, error instanceof Error ? error.message : error)
  }
}

/** Test helper: removes every supplied port and resets the catalogue. */
export function clearAuthorisationComposition(): void {
  database = null
  directory = null
  eventSink = null
  policy = null
  catalogue.clear()
  for (const definition of AUTHORISATION_PERMISSIONS) catalogue.set(definition.name, definition)
}

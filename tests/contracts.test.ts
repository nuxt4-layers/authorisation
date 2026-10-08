import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join, normalize, relative } from 'node:path'
import { describe, expect, it } from 'vitest'
import * as contracts from '../contracts'

const root = normalize(join(import.meta.dirname, '..'))

function files(dir: string): string[] {
  return readdirSync(join(root, dir), { recursive: true, encoding: 'utf8' })
    .filter(file => file.endsWith('.ts'))
    .map(file => join(dir, file))
}

/** Import specifiers, with relative ones resolved to repository paths. */
function imports(file: string): string[] {
  const source = readFileSync(join(root, file), 'utf8')
  return [...source.matchAll(/(?:from|import)\s*\(?\s*'([^']+)'/g)].map(([, specifier]) =>
    specifier!.startsWith('.') ? relative(root, join(root, dirname(file), specifier!)) : specifier!)
}

const contractFiles = [...files('contracts'), ...files('shared')]

describe('Authorisation public contract', () => {
  it('exports the documented runtime values', () => {
    expect(Object.keys(contracts).sort()).toEqual([
      'AUTHORISATION_ERROR_CODES',
      'AUTHORISATION_ERROR_STATUS',
      'AUTHORISATION_EVENT_TYPES',
      'AUTHORISATION_MAX_STALENESS_SECONDS',
      'AUTHORISATION_MEMBERSHIP_STATUSES',
      'AUTHORISATION_PERMISSIONS',
      'AUTHORISATION_RISK_LEVELS',
      'AuthorisationCompositionError',
      'BUILT_IN_ROLE_IDS',
      'CONDITION_OPERATORS',
      'DEFAULT_AUTHORISATION_POLICY',
      'ROLE_ASSIGNMENT_SCOPES',
      'conditionSchema',
      'isAuthorisationErrorCode',
      'isPermissionName',
      'isPermissionPattern',
      'permissionDefinitionSchema',
      'permissionPatternMatches',
      'resolveAuthorisationPolicy',
      'roleDefinitionSchema',
      'rolePermissionSchema',
    ])
  })

  it('imports nothing but zod and its own modules', () => {
    for (const file of contractFiles) {
      for (const target of imports(file)) {
        expect(target === 'zod' || /^(contracts|shared)\//.test(target), `${file} imports ${target}`).toBe(true)
      }
    }
  })

  it('does not leak driver, vendor or other capabilities\' package names', () => {
    const forbidden = /kysely|drizzle|supabase|^pg$|^@nuxt4-layers\//i
    for (const file of contractFiles) {
      for (const target of imports(file)) expect(target, file).not.toMatch(forbidden)
    }
  })

  it('maps every error code to an HTTP status', () => {
    for (const code of contracts.AUTHORISATION_ERROR_CODES) {
      expect(contracts.AUTHORISATION_ERROR_STATUS[code]).toBeGreaterThanOrEqual(400)
    }
    expect(Object.keys(contracts.AUTHORISATION_ERROR_STATUS).sort())
      .toEqual([...contracts.AUTHORISATION_ERROR_CODES].sort())
  })

  it('has no error code that would reveal whether a resource or group exists', () => {
    for (const code of contracts.AUTHORISATION_ERROR_CODES) {
      expect(code).not.toMatch(/not-found|unknown|exists|group|member/)
    }
    expect(contracts.isAuthorisationErrorCode('forbidden')).toBe(true)
    expect(contracts.isAuthorisationErrorCode('unknown-group')).toBe(false)
  })

  it('namespaces every event type', () => {
    for (const type of contracts.AUTHORISATION_EVENT_TYPES) {
      expect(type).toMatch(/^authorisation\.[a-z-]+$/)
    }
  })

  it('does not grant platform-wide bypasses: no superuser role', () => {
    expect(contracts.BUILT_IN_ROLE_IDS).not.toContain('superuser')
    expect(JSON.stringify(contracts.DEFAULT_AUTHORISATION_POLICY)).not.toMatch(/superuser/)
  })

  it('makes hierarchy inheritance opt-in: the default assignment scope is the group alone', () => {
    expect(contracts.ROLE_ASSIGNMENT_SCOPES[0]).toBe('group')
    expect(contracts.ROLE_ASSIGNMENT_SCOPES).toEqual(['group', 'group-and-descendants'])
  })

  it('bounds directory staleness for revocation', () => {
    expect(contracts.AUTHORISATION_MAX_STALENESS_SECONDS).toBeLessThanOrEqual(30)
    expect(contracts.AUTHORISATION_MEMBERSHIP_STATUSES).toEqual(['active', 'suspended', 'ended'])
  })
})

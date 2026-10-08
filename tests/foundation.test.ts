import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const root = resolve(import.meta.dirname, '..')
const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'))
const manifest = JSON.parse(readFileSync(resolve(root, 'capability.json'), 'utf8'))

describe('Authorisation repository foundation', () => {
  it('keeps package and capability manifest identity/version aligned', () => {
    expect(manifest.name).toBe(pkg.name)
    expect(manifest.version).toBe(pkg.version)
    expect(manifest.classification).toBe('foundation')
  })

  it('publishes deliberate root, contracts and capability entry points', () => {
    expect(pkg.exports).toEqual({
      '.': './nuxt.config.ts',
      './contracts': './contracts/index.ts',
      './capability': './capability.json',
    })
    expect(manifest.publicExports).toEqual(Object.keys(pkg.exports))
  })

  it('provides the Authorisation contract and requires Authentication and Identity by contract only', () => {
    expect(manifest.provides).toEqual([{ capability: 'Authorisation', contractVersion: '2' }])
    expect(manifest.requires.map((r: { capability: string }) => r.capability)).toEqual(['Authentication', 'Identity'])
    expect(Object.keys(pkg.dependencies ?? {}).filter(name => name.startsWith('@nuxt4-layers/'))).toEqual([])
  })

  it('declares database, directory and permissions as required ports and the rest as optional', () => {
    const required = manifest.ports.filter((p: { optional: boolean }) => !p.optional).map((p: { port: string }) => p.port)
    expect(required).toEqual(['AuthorisationDatabase', 'AuthorisationDirectory', 'AuthorisationPermissions'])
  })

  it('declares every runtime import as a dependency rather than relying on the host', () => {
    expect(pkg.dependencies).toHaveProperty('zod')
    expect(pkg.peerDependencies).toHaveProperty('nuxt')
  })

  it('runs no install-time scripts, so Git installs pull no devDependencies', () => {
    expect(pkg.scripts).not.toHaveProperty('prepare')
    expect(pkg.scripts).not.toHaveProperty('postinstall')
    expect(pkg.scripts).not.toHaveProperty('install')
  })
})

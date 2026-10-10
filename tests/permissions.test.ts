import { describe, expect, it } from 'vitest'
import { AUTHORISATION_PERMISSIONS, isPermissionName, isPermissionPattern, permissionDefinitionSchema, permissionPatternMatches } from '../contracts'

describe('Permission names', () => {
  it.each(['orders:view', 'blog.comments:moderate', 'authorisation.role-assignments:manage', 'orders:process_refund'])('accepts %s', (name) => {
    expect(isPermissionName(name)).toBe(true)
  })

  it.each(['view_orders', 'Orders:view', 'orders:View', 'orders:*', 'orders:view:own', 'orders: view', '', 'orders.:view', `${'a'.repeat(130)}:view`])('refuses %s', (name) => {
    expect(isPermissionName(name)).toBe(false)
  })
})

describe('Permission patterns', () => {
  it.each(['*', 'orders:*', '*:view', 'orders:view'])('accepts %s', (pattern) => {
    expect(isPermissionPattern(pattern)).toBe(true)
  })

  it.each(['*:*', 'ord*:view', 'orders:vi*', '**'])('refuses %s', (pattern) => {
    expect(isPermissionPattern(pattern)).toBe(false)
  })

  it('matches within one resource or one action only', () => {
    expect(permissionPatternMatches('orders:*', 'orders:view')).toBe(true)
    expect(permissionPatternMatches('orders:*', 'orders.items:view')).toBe(false)
    expect(permissionPatternMatches('*:view', 'notes:view')).toBe(true)
    expect(permissionPatternMatches('*:view', 'notes:view_history')).toBe(false)
    expect(permissionPatternMatches('orders:view', 'orders:view')).toBe(true)
    expect(permissionPatternMatches('orders:view', 'orders:create')).toBe(false)
  })
})

describe('Permission definitions', () => {
  it('requires a description and a risk level', () => {
    expect(() => permissionDefinitionSchema.parse({ name: 'orders:view', description: '', risk: 'low' })).toThrow()
    expect(() => permissionDefinitionSchema.parse({ name: 'orders:view', description: 'x', risk: 'extreme' })).toThrow()
    expect(() => permissionDefinitionSchema.parse({ name: 'orders:view', description: 'x', risk: 'low', requiresMfa: true })).toThrow()
  })

  it('declares the layer\'s own administration permissions, never as low risk except viewing', () => {
    for (const { name, risk, effect } of AUTHORISATION_PERMISSIONS) {
      expect(name).toMatch(/^authorisation\./)
      expect(permissionDefinitionSchema.parse({ name, description: 'x', risk, effect })).toBeTruthy()
      // Assignments are the one medium floor: each assignment's own risk, from its role, sets its approval and step-up.
      if (!name.endsWith(':view')) expect(name === 'authorisation.role-assignments:manage' ? ['medium'] : ['high', 'critical']).toContain(risk)
      expect(effect).toBe(name.endsWith(':view') ? 'view' : 'change')
    }
    expect(Object.fromEntries(AUTHORISATION_PERMISSIONS.map(p => [p.name, p.risk]))).toEqual({
      'authorisation.roles:view': 'low',
      'authorisation.grants:manage': 'high',
      'authorisation.role-assignments:manage': 'medium',
      'authorisation.roles:manage': 'critical',
      'authorisation.group-access:manage': 'high',
    })
  })

  it('takes an effect of view or change, and change when none is declared', () => {
    expect(permissionDefinitionSchema.parse({ name: 'orders:view', description: 'x', risk: 'low' }).effect).toBe('change')
    expect(permissionDefinitionSchema.parse({ name: 'orders:view', description: 'x', risk: 'low', effect: 'view' }).effect).toBe('view')
    expect(() => permissionDefinitionSchema.parse({ name: 'orders:view', description: 'x', risk: 'low', effect: 'read' })).toThrow()
  })
})

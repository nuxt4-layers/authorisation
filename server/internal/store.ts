import { randomUUID } from 'node:crypto'
import type {
  AuthorisationGrant,
  AuthorisationRoleAssignment,
  AuthorisationRoleAssignmentScope,
  AuthorisationRoleDefinition,
  PostgresPoolLike,
} from '../../contracts'
import { roleDefinitionSchema } from '../../contracts'
import { quoteSchema } from '../database/migrations'

/**
 * PRIVATE. Roles, role assignments and grants in the capability's schema.
 * Plain parameterised SQL over the host's pool; every row read back is
 * checked before it reaches a decision, so malformed data fails closed.
 */

type Rows<T> = Promise<{ rows: T[] }>

export interface StoredGrant extends AuthorisationGrant {
  grantId: string
}

export function createStore(pool: PostgresPoolLike, schema: string) {
  const s = quoteSchema(schema)
  const query = <T>(text: string, values: unknown[] = []) => pool.query(text, values) as Rows<T>

  const toAssignment = (row: { principal_id: string, group_id: string, role_id: string, scope: AuthorisationRoleAssignmentScope }): AuthorisationRoleAssignment =>
    ({ principalId: row.principal_id, groupId: row.group_id, roleId: row.role_id, scope: row.scope })

  return {
    /** The principal's role assignments, in every group. */
    async assignmentsOf(principalId: string): Promise<AuthorisationRoleAssignment[]> {
      const { rows } = await query<Parameters<typeof toAssignment>[0]>(`select principal_id, group_id, role_id, scope from ${s}."role_assignment" where principal_id = $1`, [principalId])
      return rows.map(toAssignment)
    },

    /** Role assignments made in any of the groups. */
    async assignmentsIn(groupIds: readonly string[]): Promise<AuthorisationRoleAssignment[]> {
      if (groupIds.length === 0) return []
      const { rows } = await query<Parameters<typeof toAssignment>[0]>(
        `select principal_id, group_id, role_id, scope from ${s}."role_assignment" where group_id = any ($1::text[]) order by principal_id, group_id, role_id`,
        [groupIds],
      )
      return rows.map(toAssignment)
    },

    /** Adds an assignment, or changes its scope. Returns whether anything changed. */
    async assign(assignment: AuthorisationRoleAssignment, assignedBy: string | null): Promise<boolean> {
      const { rows } = await query<{ changed: boolean }>(
        `insert into ${s}."role_assignment" (principal_id, group_id, role_id, scope, assigned_by) values ($1, $2, $3, $4, $5)
         on conflict (principal_id, group_id, role_id) do update set scope = excluded.scope, assigned_by = excluded.assigned_by
         where ${s}."role_assignment".scope <> excluded.scope
         returning true as changed`,
        [assignment.principalId, assignment.groupId, assignment.roleId, assignment.scope, assignedBy],
      )
      return rows.length > 0
    },

    /** Removes an assignment; `roleId` null removes every role the principal holds in the group. Returns the roles removed. */
    async unassign(input: { principalId: string, groupId: string, roleId: string | null }): Promise<string[]> {
      const { rows } = await query<{ role_id: string }>(
        `delete from ${s}."role_assignment" where principal_id = $1 and group_id = $2 and ($3::text is null or role_id = $3) returning role_id`,
        [input.principalId, input.groupId, input.roleId],
      )
      return rows.map(row => row.role_id).sort()
    },

    /** Custom roles, keyed by tenant, then role. Rows that fail validation are left out. */
    async customRoles(tenantIds: readonly string[]): Promise<Map<string, Map<string, AuthorisationRoleDefinition>>> {
      const roles = new Map<string, Map<string, AuthorisationRoleDefinition>>()
      if (tenantIds.length === 0) return roles
      const { rows } = await query<{ tenant_id: string, definition: unknown }>(`select tenant_id, definition from ${s}."custom_role" where tenant_id = any ($1::text[])`, [tenantIds])
      for (const row of rows) {
        const parsed = roleDefinitionSchema.safeParse(row.definition)
        if (!parsed.success) continue
        if (!roles.has(row.tenant_id)) roles.set(row.tenant_id, new Map())
        roles.get(row.tenant_id)!.set(parsed.data.id, parsed.data)
      }
      return roles
    },

    async defineRole(tenantId: string, role: AuthorisationRoleDefinition): Promise<'defined' | 'changed'> {
      const { rows } = await query<{ inserted: boolean }>(
        `insert into ${s}."custom_role" (tenant_id, role_id, definition) values ($1, $2, $3::jsonb)
         on conflict (tenant_id, role_id) do update set definition = excluded.definition, updated_at = now()
         returning (xmax = 0) as inserted`,
        [tenantId, role.id, JSON.stringify(role)],
      )
      return rows[0]?.inserted ? 'defined' : 'changed'
    },

    async deleteRole(tenantId: string, roleId: string): Promise<boolean> {
      const { rows } = await query(`delete from ${s}."custom_role" where tenant_id = $1 and role_id = $2 returning 1`, [tenantId, roleId])
      return rows.length > 0
    },

    /** Grants on one resource. */
    async grantsOn(resource: { type: string, id: string }): Promise<StoredGrant[]> {
      const { rows } = await query<{ grant_id: string, resource_type: string, resource_id: string, subject_kind: 'principal' | 'group', subject_id: string, permissions: string[], expires_at: Date | null }>(
        `select grant_id, resource_type, resource_id, subject_kind, subject_id, permissions, expires_at from ${s}."grant" where resource_type = $1 and resource_id = $2`,
        [resource.type, resource.id],
      )
      return rows.map(row => ({
        grantId: row.grant_id,
        resource: { type: row.resource_type, id: row.resource_id },
        subject: row.subject_kind === 'group' ? { kind: 'group', groupId: row.subject_id } : { kind: 'principal', principalId: row.subject_id },
        permissions: row.permissions,
        expiresAt: row.expires_at ? new Date(row.expires_at).toISOString() : null,
      }))
    },

    async createGrant(grant: AuthorisationGrant, grantedBy: string | null): Promise<string> {
      const grantId = randomUUID()
      await query(
        `insert into ${s}."grant" (grant_id, resource_type, resource_id, subject_kind, subject_id, permissions, expires_at, granted_by) values ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [grantId, grant.resource.type, grant.resource.id, grant.subject.kind, grant.subject.kind === 'group' ? grant.subject.groupId : grant.subject.principalId, [...grant.permissions], grant.expiresAt, grantedBy],
      )
      return grantId
    },

    async revokeGrant(grantId: string): Promise<StoredGrant | null> {
      const { rows } = await query<{ resource_type: string, resource_id: string, subject_kind: 'principal' | 'group', subject_id: string, permissions: string[], expires_at: Date | null }>(
        `delete from ${s}."grant" where grant_id = $1 returning resource_type, resource_id, subject_kind, subject_id, permissions, expires_at`,
        [grantId],
      )
      const row = rows[0]
      if (!row) return null
      return {
        grantId,
        resource: { type: row.resource_type, id: row.resource_id },
        subject: row.subject_kind === 'group' ? { kind: 'group', groupId: row.subject_id } : { kind: 'principal', principalId: row.subject_id },
        permissions: row.permissions,
        expiresAt: row.expires_at ? new Date(row.expires_at).toISOString() : null,
      }
    },
  }
}

export type AuthorisationStore = ReturnType<typeof createStore>

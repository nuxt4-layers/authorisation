import { randomUUID } from 'node:crypto'
import type {
  AuthorisationAssignmentView,
  AuthorisationDefaultRoles,
  AuthorisationGrant,
  AuthorisationGrantView,
  AuthorisationPendingChange,
  AuthorisationRoleAssignment,
  AuthorisationRoleAssignmentScope,
  AuthorisationRoleDefinition,
} from '../../contracts'
import { DEFAULT_GROUP_DEFAULT_ROLES, pendingChangeSchema, roleDefinitionSchema } from '../../contracts'
import { quoteSchema } from '../database/migrations'
import type { Queryable } from './database'

/**
 * PRIVATE. Roles, role assignments, grants, group access settings and
 * pending changes in the capability's schema. Plain parameterised SQL over
 * a pool or a transaction's connection; every row read back is checked
 * before it reaches a decision or a caller, so malformed data fails closed.
 * Every time stored is given by the caller, from the host's clock.
 */

export interface StoredGrant extends AuthorisationGrant {
  grantId: string
}

export interface StoredGroupAccess {
  groupId: string
  tenantId: string
  defaultRoles: AuthorisationDefaultRoles
  reviewIntervalDays: number | null
  version: number
}

/** A pending change with the fields only the server sees. */
export interface StoredChange extends AuthorisationPendingChange {
  basis: Record<string, unknown>
  failure: string | null
}

const iso = (value: Date | string | null | undefined): string | null => (value ? new Date(value).toISOString() : null)

interface AssignmentRow {
  principal_id: string
  group_id: string
  role_id: string
  scope: AuthorisationRoleAssignmentScope
  expires_at: Date | null
  created_at: Date
  assigned_by: string | null
  confirmed_at: Date | null
  confirmed_by: string | null
}

interface GrantRow {
  grant_id: string
  resource_type: string
  resource_id: string
  owning_group_id: string | null
  subject_kind: 'principal' | 'group'
  subject_id: string
  permissions: string[]
  expires_at: Date | null
  granted_by: string | null
  created_at: Date
}

const ASSIGNMENT_COLUMNS = 'principal_id, group_id, role_id, scope, expires_at, created_at, assigned_by, confirmed_at, confirmed_by'
const GRANT_COLUMNS = 'grant_id, resource_type, resource_id, owning_group_id, subject_kind, subject_id, permissions, expires_at, granted_by, created_at'

const toAssignment = (row: AssignmentRow): AuthorisationRoleAssignment =>
  ({ principalId: row.principal_id, groupId: row.group_id, roleId: row.role_id, scope: row.scope, expiresAt: iso(row.expires_at) })

const toAssignmentView = (row: AssignmentRow): AuthorisationAssignmentView => ({
  ...toAssignment(row),
  assignedAt: iso(row.created_at)!,
  assignedBy: row.assigned_by,
  confirmedAt: iso(row.confirmed_at),
  confirmedBy: row.confirmed_by,
})

const toGrant = (row: GrantRow): StoredGrant => ({
  grantId: row.grant_id,
  resource: { type: row.resource_type, id: row.resource_id, owningGroupId: row.owning_group_id },
  subject: row.subject_kind === 'group' ? { kind: 'group', groupId: row.subject_id } : { kind: 'principal', principalId: row.subject_id },
  permissions: row.permissions,
  expiresAt: iso(row.expires_at),
})

interface ChangeRow {
  change_id: string
  type: string
  tenant_id: string
  group_id: string
  requester_id: string
  beneficiary_id: string | null
  risk: string
  justification: unknown
  target: unknown
  basis: Record<string, unknown>
  required_approvals: number
  route: string
  approvals: unknown
  change_digest: string
  delay_ends_at: Date | null
  expires_at: Date | null
  held_until: Date | null
  state: string
  failure: string | null
  correlation_id: string
  created_at: Date
  decided_at: Date | null
  version: number
}

function toChange(row: ChangeRow): StoredChange {
  const change = pendingChangeSchema.parse({
    changeId: row.change_id,
    type: row.type,
    tenantId: row.tenant_id,
    groupId: row.group_id,
    requesterId: row.requester_id,
    beneficiaryId: row.beneficiary_id,
    risk: row.risk,
    justification: row.justification,
    target: row.target,
    requiredApprovals: row.required_approvals,
    route: row.route,
    approvals: row.approvals,
    changeDigest: row.change_digest,
    delayEndsAt: iso(row.delay_ends_at),
    expiresAt: iso(row.expires_at),
    heldUntil: iso(row.held_until),
    state: row.state,
    correlationId: row.correlation_id,
    createdAt: iso(row.created_at),
    decidedAt: iso(row.decided_at),
    version: row.version,
  }) as AuthorisationPendingChange
  return { ...change, basis: row.basis, failure: row.failure }
}

/** The fields of a pending change other than its target's parsing: what `insertChange` records. */
export type NewChange = Omit<StoredChange, 'version' | 'approvals' | 'decidedAt' | 'failure'>

export function createStore(db: Queryable, schema: string) {
  const s = quoteSchema(schema)
  const query = <T>(text: string, values: unknown[] = []) => db.query<T>(text, values)

  return {
    // -----------------------------------------------------------------------
    // Role assignments
    // -----------------------------------------------------------------------

    /** The principal's role assignments, in every group, expired ones included (decisions judge expiry by the clock). */
    async assignmentsOf(principalId: string): Promise<AuthorisationRoleAssignment[]> {
      const { rows } = await query<AssignmentRow>(`select ${ASSIGNMENT_COLUMNS} from ${s}."role_assignment" where principal_id = $1 order by group_id, role_id`, [principalId])
      return rows.map(toAssignment)
    },

    /** Role assignments made in any of the groups. */
    async assignmentsIn(groupIds: readonly string[]): Promise<AuthorisationRoleAssignment[]> {
      if (groupIds.length === 0) return []
      const { rows } = await query<AssignmentRow>(
        `select ${ASSIGNMENT_COLUMNS} from ${s}."role_assignment" where group_id = any ($1::text[]) order by principal_id, group_id, role_id`,
        [groupIds],
      )
      return rows.map(toAssignment)
    },

    /** A group's assignments, or a principal's, with provenance and review record. */
    async assignmentViews(filter: { groupId?: string, principalId?: string }): Promise<AuthorisationAssignmentView[]> {
      const { rows } = await query<AssignmentRow>(
        `select ${ASSIGNMENT_COLUMNS} from ${s}."role_assignment" where ($1::text is null or group_id = $1) and ($2::text is null or principal_id = $2) order by group_id, principal_id, role_id`,
        [filter.groupId ?? null, filter.principalId ?? null],
      )
      return rows.map(toAssignmentView)
    },

    /** One assignment, locked for the transaction when `lock` is set. */
    async assignment(key: { principalId: string, groupId: string, roleId: string }, lock = false): Promise<AuthorisationAssignmentView | null> {
      const { rows } = await query<AssignmentRow>(
        `select ${ASSIGNMENT_COLUMNS} from ${s}."role_assignment" where principal_id = $1 and group_id = $2 and role_id = $3${lock ? ' for update' : ''}`,
        [key.principalId, key.groupId, key.roleId],
      )
      return rows[0] ? toAssignmentView(rows[0]) : null
    },

    /** Groups in which the role is assigned to anyone. */
    async groupsAssigning(roleId: string): Promise<string[]> {
      const { rows } = await query<{ group_id: string }>(`select distinct group_id from ${s}."role_assignment" where role_id = $1 order by group_id`, [roleId])
      return rows.map(row => row.group_id)
    },

    /**
     * Adds an assignment at `at` (the clock's time), or changes its scope or
     * end date (a renewed assignment counts as made anew). Returns whether
     * anything changed.
     */
    async assign(assignment: AuthorisationRoleAssignment, assignedBy: string | null, at: Date): Promise<boolean> {
      const { rows } = await query<{ changed: boolean }>(
        `insert into ${s}."role_assignment" (principal_id, group_id, role_id, scope, assigned_by, created_at, expires_at) values ($1, $2, $3, $4, $5, $6, $7)
         on conflict (principal_id, group_id, role_id) do update set scope = excluded.scope, assigned_by = excluded.assigned_by,
           expires_at = excluded.expires_at, created_at = excluded.created_at, confirmed_at = null, confirmed_by = null, overdue_announced_at = null
         where ${s}."role_assignment".scope <> excluded.scope or ${s}."role_assignment".expires_at is distinct from excluded.expires_at
         returning true as changed`,
        [assignment.principalId, assignment.groupId, assignment.roleId, assignment.scope, assignedBy, at.toISOString(), assignment.expiresAt],
      )
      return rows.length > 0
    },

    /** Removes an assignment; `roleId` null removes every role the principal holds in the group. Returns those removed. */
    async unassign(input: { principalId: string, groupId: string, roleId: string | null }): Promise<AuthorisationRoleAssignment[]> {
      const { rows } = await query<AssignmentRow>(
        `delete from ${s}."role_assignment" where principal_id = $1 and group_id = $2 and ($3::text is null or role_id = $3) returning ${ASSIGNMENT_COLUMNS}`,
        [input.principalId, input.groupId, input.roleId],
      )
      return rows.map(toAssignment).sort((a, b) => a.roleId.localeCompare(b.roleId))
    },

    /** Removes assignments past their end at `at`. Returns those removed. */
    async removeExpired(at: Date, limit: number): Promise<AuthorisationRoleAssignment[]> {
      const { rows } = await query<AssignmentRow>(
        `delete from ${s}."role_assignment" where ctid in (
           select ctid from ${s}."role_assignment" where expires_at is not null and expires_at <= $1 order by expires_at limit $2 for update skip locked)
         returning ${ASSIGNMENT_COLUMNS}`,
        [at.toISOString(), limit],
      )
      return rows.map(toAssignment)
    },

    /** Records a confirmation in an access review. Returns false when the assignment is gone. */
    async confirm(key: { principalId: string, groupId: string, roleId: string }, by: string, at: Date): Promise<boolean> {
      const { rows } = await query(
        `update ${s}."role_assignment" set confirmed_at = $4, confirmed_by = $5, overdue_announced_at = null
         where principal_id = $1 and group_id = $2 and role_id = $3 returning 1`,
        [key.principalId, key.groupId, key.roleId, at.toISOString(), by],
      )
      return rows.length > 0
    },

    /** Assignments not confirmed within their group's review interval, not yet announced. */
    async overdueUnannounced(at: Date, limit: number): Promise<(AuthorisationAssignmentView & { lastConfirmedAt: string, reviewDueAt: string })[]> {
      const { rows } = await query<AssignmentRow & { last_confirmed_at: Date, review_due_at: Date }>(
        `select a.principal_id, a.group_id, a.role_id, a.scope, a.expires_at, a.created_at, a.assigned_by, a.confirmed_at, a.confirmed_by,
                coalesce(a.confirmed_at, a.created_at) as last_confirmed_at,
                coalesce(a.confirmed_at, a.created_at) + make_interval(days => g.review_interval_days) as review_due_at
         from ${s}."role_assignment" a join ${s}."group_access" g on g.group_id = a.group_id
         where g.review_interval_days is not null and a.overdue_announced_at is null
           and coalesce(a.confirmed_at, a.created_at) + make_interval(days => g.review_interval_days) <= $1
           and (a.expires_at is null or a.expires_at > $1)
         order by review_due_at limit $2 for update of a skip locked`,
        [at.toISOString(), limit],
      )
      return rows.map(row => ({ ...toAssignmentView(row), lastConfirmedAt: iso(row.last_confirmed_at)!, reviewDueAt: iso(row.review_due_at)! }))
    },

    async markOverdueAnnounced(key: { principalId: string, groupId: string, roleId: string }, at: Date): Promise<void> {
      await query(`update ${s}."role_assignment" set overdue_announced_at = $4 where principal_id = $1 and group_id = $2 and role_id = $3`, [key.principalId, key.groupId, key.roleId, at.toISOString()])
    },

    // -----------------------------------------------------------------------
    // Custom roles
    // -----------------------------------------------------------------------

    /** Custom roles, keyed by tenant, then role. Rows that fail validation are left out. */
    async customRoles(tenantIds: readonly string[]): Promise<Map<string, Map<string, AuthorisationRoleDefinition>>> {
      const roles = new Map<string, Map<string, AuthorisationRoleDefinition>>()
      if (tenantIds.length === 0) return roles
      const { rows } = await query<{ tenant_id: string, definition: unknown }>(`select tenant_id, definition from ${s}."custom_role" where tenant_id = any ($1::text[]) order by tenant_id, role_id`, [tenantIds])
      for (const row of rows) {
        const parsed = roleDefinitionSchema.safeParse(row.definition)
        if (!parsed.success) continue
        if (!roles.has(row.tenant_id)) roles.set(row.tenant_id, new Map())
        roles.get(row.tenant_id)!.set(parsed.data.id, parsed.data)
      }
      return roles
    },

    /** Serialises changes to one tenant's custom roles within a transaction. */
    async lockTenantRoles(tenantId: string): Promise<void> {
      await query('select pg_advisory_xact_lock(hashtext($1))', [`authorisation-roles:${schema}:${tenantId}`])
    },

    /** Defines or changes a tenant's custom role at `at` (the clock's time). Null when the stored definition is already the same. */
    async defineRole(tenantId: string, role: AuthorisationRoleDefinition, at: Date): Promise<'defined' | 'changed' | null> {
      const { rows } = await query<{ inserted: boolean }>(
        `insert into ${s}."custom_role" (tenant_id, role_id, definition, created_at, updated_at) values ($1, $2, $3::jsonb, $4, $4)
         on conflict (tenant_id, role_id) do update set definition = excluded.definition, updated_at = excluded.updated_at
         where ${s}."custom_role".definition is distinct from excluded.definition
         returning (xmax = 0) as inserted`,
        [tenantId, role.id, JSON.stringify(role), at.toISOString()],
      )
      if (rows.length === 0) return null
      return rows[0]!.inserted ? 'defined' : 'changed'
    },

    async deleteRole(tenantId: string, roleId: string): Promise<boolean> {
      const { rows } = await query(`delete from ${s}."custom_role" where tenant_id = $1 and role_id = $2 returning 1`, [tenantId, roleId])
      return rows.length > 0
    },

    // -----------------------------------------------------------------------
    // Grants
    // -----------------------------------------------------------------------

    /** Grants on one resource. */
    async grantsOn(resource: { type: string, id: string }): Promise<StoredGrant[]> {
      const { rows } = await query<GrantRow>(`select ${GRANT_COLUMNS} from ${s}."grant" where resource_type = $1 and resource_id = $2 order by grant_id`, [resource.type, resource.id])
      return rows.map(toGrant)
    },

    /** Grants to one principal, on any resource. */
    async grantsHeldBy(principalId: string): Promise<StoredGrant[]> {
      const { rows } = await query<GrantRow>(
        `select ${GRANT_COLUMNS} from ${s}."grant" where subject_kind = 'principal' and subject_id = $1 order by resource_type, resource_id, grant_id`,
        [principalId],
      )
      return rows.map(toGrant)
    },

    /** Grants on resources a group owned when they were shared. */
    async grantViewsOwnedBy(groupId: string): Promise<AuthorisationGrantView[]> {
      const { rows } = await query<GrantRow>(`select ${GRANT_COLUMNS} from ${s}."grant" where owning_group_id = $1 order by created_at, grant_id`, [groupId])
      return rows.map(row => ({
        grantId: row.grant_id,
        resource: { type: row.resource_type, id: row.resource_id, owningGroupId: row.owning_group_id! },
        subject: row.subject_kind === 'group' ? { kind: 'group' as const, groupId: row.subject_id } : { kind: 'principal' as const, principalId: row.subject_id },
        permissions: row.permissions,
        expiresAt: iso(row.expires_at),
        grantedBy: row.granted_by,
        createdAt: iso(row.created_at)!,
      }))
    },

    async grant(grantId: string, lock = false): Promise<StoredGrant | null> {
      const { rows } = await query<GrantRow>(`select ${GRANT_COLUMNS} from ${s}."grant" where grant_id = $1${lock ? ' for update' : ''}`, [grantId])
      return rows[0] ? toGrant(rows[0]) : null
    },

    /** Records a grant made at `at` (the clock's time). Its expiry is judged against the clock at each decision, never by SQL. */
    async createGrant(grant: AuthorisationGrant, grantedBy: string | null, at: Date): Promise<string> {
      const grantId = randomUUID()
      await query(
        `insert into ${s}."grant" (grant_id, resource_type, resource_id, owning_group_id, subject_kind, subject_id, permissions, expires_at, granted_by, created_at) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [grantId, grant.resource.type, grant.resource.id, grant.resource.owningGroupId ?? null, grant.subject.kind, grant.subject.kind === 'group' ? grant.subject.groupId : grant.subject.principalId, [...grant.permissions], grant.expiresAt, grantedBy, at.toISOString()],
      )
      return grantId
    },

    async revokeGrant(grantId: string): Promise<StoredGrant | null> {
      const { rows } = await query<GrantRow>(`delete from ${s}."grant" where grant_id = $1 returning ${GRANT_COLUMNS}`, [grantId])
      return rows[0] ? toGrant(rows[0]) : null
    },

    // -----------------------------------------------------------------------
    // Group access settings
    // -----------------------------------------------------------------------

    /** A group's settings; the defaults when it has set none. */
    async groupAccess(groupId: string, tenantId: string, lock = false): Promise<StoredGroupAccess> {
      const { rows } = await query<{ tenant_id: string, default_member_role: string | null, default_guest_role: string | null, default_member_role_set: boolean, default_guest_role_set: boolean, review_interval_days: number | null, version: number }>(
        `select tenant_id, default_member_role, default_guest_role, default_member_role_set, default_guest_role_set, review_interval_days, version from ${s}."group_access" where group_id = $1${lock ? ' for update' : ''}`,
        [groupId],
      )
      const row = rows[0]
      if (!row) return { groupId, tenantId, defaultRoles: { ...DEFAULT_GROUP_DEFAULT_ROLES }, reviewIntervalDays: null, version: 0 }
      return {
        groupId,
        tenantId: row.tenant_id,
        defaultRoles: {
          member: row.default_member_role_set ? row.default_member_role : DEFAULT_GROUP_DEFAULT_ROLES.member,
          guest: row.default_guest_role_set ? row.default_guest_role : DEFAULT_GROUP_DEFAULT_ROLES.guest,
        },
        reviewIntervalDays: row.review_interval_days,
        version: row.version,
      }
    },

    async setDefaultRoles(groupId: string, tenantId: string, roles: AuthorisationDefaultRoles, by: string, at: Date): Promise<void> {
      await query(
        `insert into ${s}."group_access" (group_id, tenant_id, default_member_role, default_guest_role, default_member_role_set, default_guest_role_set, updated_at, updated_by)
         values ($1, $2, $3, $4, true, true, $5, $6)
         on conflict (group_id) do update set default_member_role = excluded.default_member_role, default_guest_role = excluded.default_guest_role,
           default_member_role_set = true, default_guest_role_set = true, updated_at = excluded.updated_at, updated_by = excluded.updated_by,
           version = ${s}."group_access".version + 1`,
        [groupId, tenantId, roles.member, roles.guest, at.toISOString(), by],
      )
    },

    async setReviewInterval(groupId: string, tenantId: string, days: number | null, by: string, at: Date): Promise<void> {
      await query(
        `insert into ${s}."group_access" (group_id, tenant_id, review_interval_days, updated_at, updated_by) values ($1, $2, $3, $4, $5)
         on conflict (group_id) do update set review_interval_days = excluded.review_interval_days, updated_at = excluded.updated_at,
           updated_by = excluded.updated_by, version = ${s}."group_access".version + 1`,
        [groupId, tenantId, days, at.toISOString(), by],
      )
    },

    /** Groups of the tenant that name the role as a default role. */
    async groupsDefaulting(tenantId: string, roleId: string): Promise<{ groupId: string, as: ('member' | 'guest')[] }[]> {
      const { rows } = await query<{ group_id: string, member: boolean, guest: boolean }>(
        `select group_id, (default_member_role_set and default_member_role = $2) as member, (default_guest_role_set and default_guest_role = $2) as guest
         from ${s}."group_access" where tenant_id = $1 and ((default_member_role_set and default_member_role = $2) or (default_guest_role_set and default_guest_role = $2))`,
        [tenantId, roleId],
      )
      return rows.map(row => ({ groupId: row.group_id, as: [...(row.member ? ['member' as const] : []), ...(row.guest ? ['guest' as const] : [])] }))
    },

    // -----------------------------------------------------------------------
    // Pending changes
    // -----------------------------------------------------------------------

    async insertChange(change: NewChange): Promise<StoredChange> {
      const { rows } = await query<ChangeRow>(
        `insert into ${s}."pending_change" (change_id, type, tenant_id, group_id, requester_id, beneficiary_id, risk, justification, target, basis,
           required_approvals, route, change_digest, delay_ends_at, expires_at, held_until, state, correlation_id, created_at)
         values ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10::jsonb, $11, $12, $13, $14, $15, $16, $17, $18, $19) returning *`,
        [change.changeId, change.type, change.tenantId, change.groupId, change.requesterId, change.beneficiaryId, change.risk, JSON.stringify(change.justification),
          JSON.stringify(change.target), JSON.stringify(change.basis), change.requiredApprovals, change.route, change.changeDigest, change.delayEndsAt,
          change.expiresAt, change.heldUntil, change.state, change.correlationId, change.createdAt],
      )
      return toChange(rows[0]!)
    },

    async change(changeId: string, lock = false): Promise<StoredChange | null> {
      const { rows } = await query<ChangeRow>(`select * from ${s}."pending_change" where change_id = $1${lock ? ' for update' : ''}`, [changeId])
      return rows[0] ? toChange(rows[0]) : null
    },

    /** Records an outcome or an approval, advancing the version. */
    async updateChange(changeId: string, fields: { state?: StoredChange['state'], approvals?: StoredChange['approvals'], decidedAt?: string | null, delayEndsAt?: string | null, failure?: string | null }): Promise<StoredChange> {
      const { rows } = await query<ChangeRow>(
        `update ${s}."pending_change" set
           state = coalesce($2, state),
           approvals = coalesce($3::jsonb, approvals),
           decided_at = case when $4::boolean then $5::timestamptz else decided_at end,
           delay_ends_at = case when $6::boolean then $7::timestamptz else delay_ends_at end,
           failure = case when $8::boolean then $9 else failure end,
           version = version + 1
         where change_id = $1 returning *`,
        [changeId, fields.state ?? null, fields.approvals ? JSON.stringify(fields.approvals) : null,
          fields.decidedAt !== undefined, fields.decidedAt ?? null, fields.delayEndsAt !== undefined, fields.delayEndsAt ?? null,
          fields.failure !== undefined, fields.failure ?? null],
      )
      return toChange(rows[0]!)
    },

    /** A group's changes that have not yet taken effect, oldest first. */
    async openChangesIn(groupId: string): Promise<StoredChange[]> {
      const { rows } = await query<ChangeRow>(
        `select * from ${s}."pending_change" where group_id = $1 and state in ('awaiting-approval', 'delayed') order by created_at, change_id limit 200`,
        [groupId],
      )
      return rows.map(toChange)
    },

    /** Changes awaiting an approver past their expiry, locked. */
    async expiredAwaiting(at: Date, limit: number): Promise<StoredChange[]> {
      const { rows } = await query<ChangeRow>(
        `select * from ${s}."pending_change" where state = 'awaiting-approval' and expires_at is not null and expires_at <= $1 order by expires_at limit $2 for update skip locked`,
        [at.toISOString(), limit],
      )
      return rows.map(toChange)
    },

    /** Identifiers of delayed changes whose delay or hold has ended. */
    async dueDelayed(at: Date, limit: number): Promise<string[]> {
      const { rows } = await query<{ change_id: string }>(
        `select change_id from ${s}."pending_change" where state = 'delayed' and delay_ends_at is not null and delay_ends_at <= $1 order by delay_ends_at limit $2`,
        [at.toISOString(), limit],
      )
      return rows.map(row => row.change_id)
    },

    /** Changes the principal requested, benefits from, or decided. */
    async changesInvolving(principalId: string): Promise<StoredChange[]> {
      const { rows } = await query<ChangeRow>(
        `select * from ${s}."pending_change" where requester_id = $1 or beneficiary_id = $1 or approvals @> jsonb_build_array(jsonb_build_object('approverId', $1::text))
         order by created_at, change_id`,
        [principalId],
      )
      return rows.map(toChange)
    },

    /** Open changes the principal requested or benefits from, locked. */
    async openChangesInvolving(principalId: string): Promise<StoredChange[]> {
      const { rows } = await query<ChangeRow>(
        `select * from ${s}."pending_change" where (requester_id = $1 or beneficiary_id = $1) and state in ('awaiting-approval', 'delayed') order by created_at for update`,
        [principalId],
      )
      return rows.map(toChange)
    },

    // -----------------------------------------------------------------------
    // Erasure
    // -----------------------------------------------------------------------

    /**
     * Removes every role assignment and every grant a principal holds.
     * Records the principal made for others keep the opaque identifier in
     * `assigned_by`, `granted_by` and pending changes (anonymisation by
     * unlinking).
     */
    async erasePrincipal(principalId: string): Promise<{ assignments: number, grants: number }> {
      const { rows } = await query<{ assignments: string, grants: string }>(
        `with assignments as (delete from ${s}."role_assignment" where principal_id = $1 returning 1),
              grants as (delete from ${s}."grant" where subject_kind = 'principal' and subject_id = $1 returning 1)
         select (select count(*) from assignments) as assignments, (select count(*) from grants) as grants`,
        [principalId],
      )
      return { assignments: Number(rows[0]?.assignments ?? 0), grants: Number(rows[0]?.grants ?? 0) }
    },
  }
}

export type AuthorisationStore = ReturnType<typeof createStore>

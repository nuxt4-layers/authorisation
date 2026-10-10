# Authorisation Contract (version 4)

`@nuxt4-layers/authorisation/contracts` is the only supported import path for this capability's types and pure helpers. It imports nothing but `zod`, and no driver or other capability's package.

Version 2 follows the [Group Model Definition v0.1](https://github.com/nuxt4-layers/platform-architecture/blob/master/docs/identity/group-model-definition-v01.md) (proposed); version 3 adds paused memberships and principals, and the `effect` of each permission; version 4 adds access administration as iam-integration's [access administration](https://github.com/nuxt4-layers/iam-integration/blob/35e86ab288fed79848b513a98cfbd98304a3cb26/docs/processes/access-administration.md) and [approvals](https://github.com/nuxt4-layers/iam-integration/blob/35e86ab288fed79848b513a98cfbd98304a3cb26/docs/processes/approvals.md) processes set out: pending changes with approvals, a transactional outbox, default roles, time-limited assignments, access reviews, role documents, endpoints and default pages. Changes are listed in §11.

Authorisation answers one question: **may this subject perform this permission on this resource, now?**

```text
subject + permission + resource + tenant + group context + roles + grants -> decision
```

## 1. Boundaries

| Concern | Owner | How Authorisation sees it |
|---|---|---|
| Who is signed in, and how strongly | Authentication | `AuthorisationSubject`, a structural subset of `AuthenticatedPrincipal` that the host passes in |
| Users, groups, group types, hierarchy, tenants, memberships and their status, personal groups | Identity (tenant lifecycle may later move to a tenancy capability) | The `AuthorisationDirectory` port, adapted by the host |
| Resources and their data | The domain capability that owns them | `AuthorisationResource`, described by that capability at decision time |
| Permissions | Each domain capability declares its own | The catalogue, supplied by the host |
| Roles, role assignments, grants, decisions, pending changes about them, a group's default roles and review interval | **Authorisation** | Its own schema (§12) |
| Owners, approval requirements, safety periods, recovery holds, identities a requester controls | Identity | The `AuthorisationGovernance` port (§15), adapted by the host |

Authorisation stores no domain data, no groups and no memberships.

## 2. Groups own information

Every resource has exactly one **owning group**. A group is any collection of people for a purpose: an organisation, company, club, committee, event, department or office. Identity decides which kinds exist and how deep they nest. Each group has at most one parent, so Authorisation sees a group's **lineage** as a single chain from its root down to itself:

```text
['company-a', 'london-office', 'sales']
```

The hierarchy records organisational structure only. **It confers no privilege by default** (§5).

A **tenant** is the isolation boundary. It is supplied for each group by the directory and is not assumed to be the root of the lineage: one tenant may hold several trees. Tenant isolation is checked separately from roles and grants (§6).

Every human identity has a **personal group**: a unary group whose only member is that principal, like a Unix user's own group. A resource a user keeps for themselves belongs to their personal group. Identities without one, such as service identities, are supported.

Because information belongs to groups, **leaving a group ends the access derived from that membership**, including to resources the leaver created: a company-owned report stays the company's. Joining a group gives access up to the roles held there. An `active` membership counts in full; a `paused` one only to view (§6a); `suspended` and `ended` ones grant nothing.

**Creator provenance is not access.** A resource may record its `creatorPrincipalId`; that alone grants nothing. A role can use it in a condition ("members may edit what they created"), and that role still needs an active membership.

## 3. Permissions

A permission names one business capability: `<resource>:<action>`.

- `<resource>` is a plural noun, optionally namespaced: `orders`, `blog.comments`.
- `<action>` is a snake-case verb: `view`, `create`, `process_refund`.
- Scope never appears in the name: `orders:view`, never `orders:view_own`.

Each permission has a description, a risk level and an **effect**: `view` if it only reads, `change` otherwise. A definition without an effect is `change`, so an undeclared permission fails closed for paused members (§6a). The action's name decides nothing: `orders:export` may be a `change` though it alters no order.

Risk levels:

| Risk | Meaning | Default assurance |
|---|---|---|
| `low` | Reads non-sensitive data | Any authenticated session |
| `medium` | Changes data reversibly | Any authenticated session |
| `high` | Financial, legal, personal-data or hard-to-reverse | `aal2` |
| `critical` | Destructive, or changes who may do what | `aal2`, phishing resistant, authenticated in the last 15 minutes |

Domain capabilities export their definitions from their own contracts; the host passes them to `provideAuthorisationPermissions`. A name defined twice with a different description or risk is refused. Authorisation adds its own:

| Permission | Risk | Effect | Guards |
|---|---|---|---|
| `authorisation.roles:view` | low | view | Seeing a group's roles, assignments, access settings and open changes; a tenant's roles |
| `authorisation.grants:manage` | high | change | `grant.create`, `grant.revoke` and a group's grants |
| `authorisation.role-assignments:manage` | medium | change | `role.assign`, `role.unassign`, `assignment.confirm` and the access review |
| `authorisation.roles:manage` | critical | change | `role.define`, `role.delete`, on the tenant's root group |
| `authorisation.group-access:manage` | high | change | `group.change-default-roles`, `group.change-review-interval` |

`authorisation.role-assignments:manage` is `medium` from contract 4: it is the floor of any assignment, and each assignment's own risk, from the role it assigns (§15), sets its approval and step-up. This is a design decision that keeps every powerful assignment as strict as when the permission itself was `critical` (assigning `administrator` needs an approver at `aal2`; an `owner`-level custom role or the descendants scope one at phishing-resistant `aal2` within 15 minutes), not a loosening: what became possible without an approver is giving roles whose permissions are themselves `low` or `medium`. Because `*` covers `medium` permissions, a group's administrators may now request assignments; owners always could.

A permission missing from the catalogue is never granted. A name defined twice with a different description, risk or effect is refused.

## 4. Roles

A role is a named list of permission patterns: an exact name, `<resource>:*`, `*:<action>` or `*`. **Wildcards never cover `high` or `critical` permissions**; a role must name those explicitly.

Each pattern may carry conditions (`when`), all of which must hold:

```json
{ "pattern": "orders:update", "when": [
  { "attribute": "resource.attributes.status", "operator": "in", "value": ["draft", "open"] },
  { "attribute": "resource.creatorPrincipalId", "operator": "equals", "value": { "ref": "subject.principalId" } }
] }
```

Operators are `equals`, `not-equals`, `in` and `not-in`. An attribute the resource does not supply fails every condition, including negative ones.

Built-in roles, configurable through the policy:

| Role | Default permissions |
|---|---|
| `owner` | `*`, plus every `authorisation.*:manage` permission by name |
| `administrator` | `*` (which covers `authorisation.role-assignments:manage`), plus `authorisation.grants:manage` |
| `member` | `*:view`, `*:create` |
| `viewer` | `*:view` |

Tenants may define **custom roles**. A custom role belongs to one tenant and cannot reuse a built-in ID; only an owner of the tenant's root group defines, changes or deletes one, as a `critical` change with an approval (§15), and the platform operator may export and import them as a document (§18). There is no superuser: platform administration is a group whose powers come from its roles.

## 5. Role assignments and grants

A **role assignment** gives a principal a role in a group. It counts only while the principal is an **active member of that group**, and only for resources in that group's tenant. Its **scope** says how far it reaches:

| Scope | Covers |
|---|---|
| `group` (default) | Resources owned by the group itself |
| `group-and-descendants` | Also resources owned by groups below it in the current hierarchy |

Inheritance therefore exists only where an assignment explicitly asks for it. It never reaches ancestors, siblings, other trees or other tenants. Because it follows the current hierarchy, moving a group changes what such assignments cover, so assigning the descendants scope and reparenting groups are both critical operations.

An assignment may carry an end date (`expiresAt`, contract 4). Past it, the assignment confers nothing at once, whether or not maintenance has removed it yet (§18).

A principal holds the policy's `personalGroupRole` (`owner` by default, or none) in their own personal group.

A **grant** gives a principal or a group exact permissions (never wildcards) on one resource, optionally until an expiry. A grant to a group applies to its active members. Grants stay inside the resource's tenant: a grant to a principal applies only while that principal has an active membership in the tenant, and a grant to a group only if the group is in the same tenant. Sharing across tenants, including with someone's personal group, needs the host to enable `externalGrants`. This is deliberately stricter than the group model's minimum: by default a direct share ends when its holder leaves the tenant.

A grant is independent of unrelated memberships: ending one membership never removes access that a grant gives through another.

A grant made through a change records the resource's **owning group** as the requester named it (`resource.owningGroupId`, contract 4), and counts only for a resource whose owning group, as its domain capability describes it at decision time, is that group. A requester who claims someone else's resource for a group they manage therefore shares nothing. A grant made by the host's own server code may leave it out, and then counts as before.

## 6. How a decision is made

1. Refuse if the permission is not in the catalogue or does not belong to the resource's type (`unknown-permission`).
2. Refuse if the directory does not know the principal (`unknown-subject`), or does not know the owning group or describes it inconsistently (`unknown-group`).
3. **Tenant isolation:** if the request has a tenant context, resolved on the server and never taken from the client, refuse a resource in any other tenant (`tenant-mismatch`).
4. Find every route that covers the permission, each with the **standing** of the membership it rests on (§6a):
   - a **role** held in the owning group, or in an ancestor by an assignment scoped `group-and-descendants`, while a member of that group, in the resource's tenant, and before the assignment's end;
   - the **personal-group role**, if the resource belongs to the subject's own personal group;
   - an unexpired **grant** that stays inside the tenant, bound to the resource's owning group when it records one (§5).
5. If none, refuse (`not-permitted`).
6. Take the route with the fullest standing. If every route is paused and the permission is not a `view` at `low` or `medium` risk, refuse (`paused`).
7. If allowed, check the session against the permission's risk level. If it falls short, refuse with `insufficient-assurance` and the requirement, so the host can send the user to step up or re-authenticate.

The decision is `{ allowed: true, permission, via }` (`via` is `role`, `personal-group` or `grant`) or `{ allowed: false, permission, reason, requirement }`. Reasons are for the server and audit. Only the coarse error codes below cross HTTP.

## 6a. Paused members and principals

A person may pause a membership, or their whole account (iam-integration's pausing process). A paused member is hidden from the group and receives nothing from it, so their reading of sensitive material would go unnoticed. Paused standing therefore confers only permissions whose effect is `view`, at `low` or `medium` risk, whatever the roles or grants say.

The directory reports each membership's status and the principal's own `status` (`active`, `paused` or `suspended`). A route's standing is:

| Route | Standing |
|---|---|
| Role assignment | The membership in the group it was made in |
| Personal-group role | The principal's own status |
| Grant to a group | The membership in that group |
| Grant to the principal | Their fullest membership in the resource's tenant; with `externalGrants`, at least their own status |

Each is capped by the principal's own status: a paused principal is view-only everywhere, including their own personal group, and a suspended one has nothing. Anything but `active` or `paused` confers nothing. A route with active standing always wins, so a paused membership never hides access the principal holds in full through another.

Approvals (`authorisationQualifies`) use the same decision, so a paused member never qualifies to approve a change.

## 7. Errors

| Code | HTTP | Meaning |
|---|---|---|
| `unauthenticated` | 401 | No signed-in subject |
| `forbidden` | 403 | Refused. Never says why, or whether the resource or group exists |
| `insufficient-assurance` | 403 | Permitted after step-up or re-authentication |
| `validation-failed` | 400 | Malformed input |
| `conflict` | 409 | A rule refused a change (contract 4); `reason` names it, such as `self-grant` or `owner-role`. Only ever answered to a caller entitled to see what it is about |
| `unavailable` | 503 | Directory, governance port, database or clock failure (§13). Fails closed |

The body is `{ code, messageKey, reason? }`; `reason` appears only with `conflict` and `validation-failed`. A `paused` refusal is `forbidden` over HTTP like any other; the host may tell the signed-in person, from their own state, that resuming lets them act.

A domain capability that must hide whether a resource exists answers *not found* from its own contract.

## 8. Events

Every change to roles, assignments, grants, a group's access settings and pending changes writes its event to Authorisation's **transactional outbox**, in the same transaction as the change, so the event exists if and only if the change committed. The host relays them with `relayAuthorisationOutbox({ publish, limit })`: in order, at least once; an event is marked relayed only when `publish` resolves, and a failure stops the run and is retried on the next. Consumers are idempotent by `eventId`.

Every event is `{ eventId, type, occurredAt, correlationId, actorPrincipalId, data }` with a strict schema per type (`authorisationEventSchema`, `AUTHORISATION_EVENT_PAYLOADS`). `actorPrincipalId` is null for the system (maintenance, an import). The pending change's `version` is its aggregate version; other aggregates carry none.

| Event | Data |
|---|---|
| `authorisation.change-requested` | Change, type, tenant, group, requester, beneficiary, risk, route, state, required approvals, delay end, expiry |
| `authorisation.change-decided` | As above, with the outcome: `applied`, `rejected`, `expired` or `cancelled` |
| `authorisation.change-held` | As above, with `heldUntil` |
| `authorisation.role-assigned`, `authorisation.role-unassigned`, `authorisation.role-expired` | Principal, group, role, scope, end date, the change (or null) |
| `authorisation.assignment-confirmed` | Principal, group, role, when, the change |
| `authorisation.grant-created`, `authorisation.grant-revoked` | Grant, resource type and identifier, owning group, holder, permissions, expiry, the change |
| `authorisation.role-defined`, `authorisation.role-changed`, `authorisation.role-deleted` | Tenant, role, SHA-256 of the role's canonical JSON (null on deletion), the change |
| `authorisation.roles-imported` | Tenant, the document's digest, the roles defined, changed and deleted |
| `authorisation.group-access-changed` | Group, tenant, the settings changed (`default-roles`, `review-interval`), the change |
| `authorisation.review-overdue` | Principal, group, role, when it was last confirmed, when the review was due |
| `authorisation.principal-erased` | Principal, how many assignments and grants were removed |

All carry opaque identifiers, codes, role and permission names and instants only: never names, email addresses, resource attributes or free text.

A decision changes nothing, so a refusal is not an outbox event: `authorisation.denied` (`AuthorisationDenialEvent`: the principal, group, resource reference, permission and reason) goes to the optional `AuthorisationEventSink`, best effort, and a sink failure never changes the decision.

## 9. Policy

`resolveAuthorisationPolicy(input)` merges host overrides onto `DEFAULT_AUTHORISATION_POLICY` and refuses anything below the floors:

- `high` and `critical` need `aal2`;
- `critical` needs authentication within the last hour;
- no risk level may demand less than the one below it.

Dropping the phishing-resistant requirement for `critical`, for hosts without passkeys, is allowed but needs a documented risk treatment.

## 10. Revocation

Ending a membership must end the access derived from it promptly. The directory port carries the guarantee:

| Permission risk | Directory read | Maximum staleness |
|---|---|---|
| `high`, `critical` | `strong`: from the source of truth, never cached | None |
| `low`, `medium` | `bounded`: may be cached | `AUTHORISATION_MAX_STALENESS_SECONDS` (30 s) |

A directory or database failure refuses the request (`unavailable`). Decisions themselves are never cached across requests, and no decision is embedded in a session or token. Data already exported or copied before revocation cannot be retracted; retention of business records stays with their owning capability.

## 11. Versioning

This is contract version 4, provided by package 0.4. Before 1.0, breaking changes are listed here and in the release notes.

| Version 1 | Version 2 |
|---|---|
| A role assignment reached every descendant group | `scope` on each assignment; `group` (default) covers only the group itself |
| Tenant = root of the lineage | `tenantId` supplied by the directory for every group; separate tenant check and `tenant-mismatch` reason |
| `AuthorisationResource.ownerPrincipalId` granted the `resourceOwnerRole` | `creatorPrincipalId` is provenance only; `resourceOwnerRole` removed; use a role condition |
| Implicit `owner` role in the personal group | `personalGroupRole` policy setting (`owner` by default, or `null`) |
| `personalGroupId: string` | `personalGroup: AuthorisationGroup \| null` |
| Memberships were assumed current | Each membership has `status`; only `active` counts |
| `getGroupLineage(groupId)` | `describeGroup(groupId, options)`; both directory methods take `{ consistency }` |
| Decision source `resource-owner` | `personal-group` |
| — | Phase 2 adds storage, server functions and `AuthorisationFailure` (§12); no change to version 2's types |

| Version 2 | Version 3 |
|---|---|
| Membership status `active`, `suspended` or `ended` | Adds `paused`: view-only (§6a) |
| `AuthorisationActorContext` without a status | `status: 'active' \| 'paused' \| 'suspended'` is required; it governs the personal group and caps every membership. A directory that omits it confers nothing |
| Permission definitions: name, description, risk | Adds `effect: 'view' \| 'change'` (default `change`); `AuthorisationPermissionDefinitionInput` is the declared shape, `AuthorisationPermissionDefinition` the catalogue's |
| Denial reasons | Adds `paused` |
| — | Adds `exportAuthorisationData`, `eraseAuthorisationPrincipal`, `AuthorisationDataExport` and the `authorisation.principal-erased` event, for data-subject requests and account closure; no change to version 3's types |
| — | Adds the optional clock port (`AuthorisationClock`, `provideAuthorisationClock`, §13); without it, the system clock as before. No change to version 3's types |

| Version 3 | Version 4 |
|---|---|
| `authorisation.role-assignments:manage` `critical` | `medium`, the floor of any assignment; each assignment's risk comes from its role (§3, §15) |
| — | `authorisation.group-access:manage` (`high`), in the built-in `owner` role |
| Changes made only by the host's server code | Pending changes with approvals (§15), the governance port (`AuthorisationGovernance`, required for changes), the subject resolver (`AuthorisationSubjectResolver`, required for the endpoints), endpoints (§16) and default pages (§17) |
| Events through the best-effort sink, flat `AuthorisationEvent` | Outbox events with an envelope and strict schemas (`AuthorisationEvent` is now the outbox event); the sink receives only `authorisation.denied` (`AuthorisationDenialEvent`) |
| Error codes | Adds `conflict` (409) and the optional `reason` of `AuthorisationErrorBody`; `AuthorisationFailure.reason` |
| `AuthorisationRoleAssignment` | Adds `expiresAt` |
| Grant resources `{ type, id }` | Adds the optional `owningGroupId` the grant is bound to |
| — | A group's default roles and review interval, access reviews, time-limited assignments, maintenance, role documents (§18); `exportAuthorisationData` adds the changes a principal is part of |

## 12. Storage and server functions

Authorisation keeps custom roles (per tenant), role assignments (principal, group, role, scope, end date, provenance and last confirmation), grants (with the owning group they are bound to), a group's default roles and review interval, pending changes and the outbox in its own schema, through append-only migrations (`migrateAuthorisationDatabase()`), over the host's pool. Identifiers are opaque text: nothing else about a person is stored.

| Function | Does |
|---|---|
| `authorise({ subject, permission, resource, requestTenantId? })` | The decision (§6). Gathers the actor and the owning group from the directory (`strong` for `high` and `critical` permissions, `bounded` otherwise) and the subject's assignments, the tenant's custom roles and the resource's grants from the store. A refusal is announced as `authorisation.denied` |
| `requireAuthorisation(input)` | As `authorise`, but throws a coarse HTTP error (`forbidden`, `insufficient-assurance` or `unavailable`) unless allowed |
| `authorisationQualifies({ principalId, permission, resource })` | Whether the principal holds the permission on the resource now, whatever their session: for approvals, where the approver steps up when deciding. `strong` reads |
| `countAuthorisationQualifying({ permission, resource, excludingPrincipalIds, limit })` | How many principals other than those excluded qualify, up to `limit` (at most 100). Candidates are holders of assignments that can reach the resource's group and of grants on the resource to a principal; grants to a group are not counted, since Authorisation cannot list a group's members, so the count errs low |
| `listAuthorisationRoleAssignments({ principalId?, groupId? })` | A principal's assignments, or a group's |
| `assignAuthorisationRole({ principalId, groupId, roleId, scope?, expiresAt?, actorPrincipalId, correlationId? })`, `unassignAuthorisationRole({ principalId, groupId, roleId \| null, actorPrincipalId, correlationId? })` | Change assignments: a built-in role, or a custom role of the group's tenant, in a group the directory knows. `authorisation.role-assigned` and `role-unassigned` |
| `defineAuthorisationRole`, `deleteAuthorisationRole` | A tenant's custom roles: never a built-in ID, never an exact permission missing from the catalogue. `authorisation.role-defined`, `role-changed`, `role-deleted` |
| `createAuthorisationGrant`, `revokeAuthorisationGrant` | Grants of exact, catalogued permissions of the resource's type. `authorisation.grant-created` and `grant-revoked` |
| `exportAuthorisationData({ principalId, correlationId })` | Authorisation's part of a data-subject access request (`AuthorisationDataExport`): the principal's role assignments and the grants made to it; null when it holds none. Server-only, called through iam-integration's coordination adapter for Profile |
| `eraseAuthorisationPrincipal({ principalId, actorPrincipalId, correlationId? })` | Removes every assignment and grant the principal holds, on Identity's `identity.closed` unless a legal hold covers Authorisation's part (iam-integration's account closure), and rejects the open changes it requested or would benefit from. Records the principal made for others keep its opaque identifier as their provenance. Idempotent; `authorisation.principal-erased` when something was removed |
| `getAuthorisationChanges()` | `request`, `decide`, `cancel`, `get` and `listForGroup` (§15) |
| `getAuthorisationAdministration()`, `listAuthorisationAccessReview({ subject, groupId })` | What the endpoints read (§16) |
| `authorisationDefaultRoles(groupId)` | The group's default roles (§18) |
| `runAuthorisationMaintenance({ limit? })` | Maintenance (§18). Server-only |
| `relayAuthorisationOutbox({ publish, limit? })` | The outbox relay (§8). Server-only |
| `exportAuthorisationRoles({ tenantId })`, `importAuthorisationRoles({ tenantId, document, correlationId })` | Role documents (§18). Server-only, never an endpoint |

The server functions that change roles, assignments and grants directly (`assignAuthorisationRole` and the like) **decide nothing**: their caller has authorised the change. They are for the host applying Identity's events through iam-integration's adapters (owners hold the `owner` role, members the group's default role). People change access only through pending changes (§15), which decide everything. Every change, either way, is written with its outbox events in one transaction; a correlation identifier left out is issued.

Every function fails closed: a directory, database or clock failure (§13) throws `AuthorisationFailure` with code `unavailable`, and invalid input `validation-failed`.

## 13. Time

Authorisation reads the current time from the clock the host supplies (`provideAuthorisationClock({ now })`), as [iam-integration's architecture §7](https://github.com/nuxt4-layers/iam-integration/blob/e986245d746507bf7093ca203e346ab1b571e3a8/docs/architecture.md#7-time) asks of every member; without one, it uses the system clock. A host supplies the same clock to every member, or none.

- Every time Authorisation keeps or judges comes from the clock: whether a grant has expired (`expiresAt`, at each decision and when a grant is made), whether an authentication is recent enough for the permission's risk (`maxAuthenticationAgeSeconds`), the times it records (`created_at` of assignments, custom roles and grants; a custom role's `updated_at`), events' `occurredAt` and an export's `exportedAt`. The database judges no time of its own: each such time is passed to it from the clock.
- The clock is read once per decision, before anything else, and that one time decides the whole decision.
- A clock that throws, or answers anything but a valid `Date`, fails the operation as `unavailable`: the decision is refused, and nothing is read, written or announced. Authorisation never falls back to another time.
- From contract 4 the clock also decides when an assignment ends, when a change expires unapproved, when a published delay or a hold ends, and when a review is due; each such time is recorded from it and judged against it, never against the database's own time.
- The clock is trusted like a key: whoever supplies it can keep an expired grant alive or make an old sign-in look recent. Only the host composes it, from server code; no request can set or move it. A clock that can be moved is for tests only.

## 14. Identifiers and personal data

Authorisation keeps opaque identifiers (principals, groups, tenants, roles, resources: `IDENTIFIER_PATTERN`, no `@`, no spaces), UUIDs (changes, grants, events, correlations), role and permission names, codes (reason codes, rule codes), references such as `CHG-1042` (never a sentence), SHA-256 digests and instants. It stores no names, email addresses or other personal data; a justification is a reason code and an optional reference, never free text. The pages name people only through the host's `AuthorisationPersonName` (§17).

## 15. Access administration: changes and approvals

Every change to who may do what is requested as a **pending change**, whatever its risk, as iam-integration's [access administration](https://github.com/nuxt4-layers/iam-integration/blob/35e86ab288fed79848b513a98cfbd98304a3cb26/docs/processes/access-administration.md) and [approvals](https://github.com/nuxt4-layers/iam-integration/blob/35e86ab288fed79848b513a98cfbd98304a3cb26/docs/processes/approvals.md) set out. `getAuthorisationChanges()` requests, decides, cancels and reads them; the endpoints (§16) and pages (§17) call it.

| Change | Target | Permission (on) | Risk |
|---|---|---|---|
| `role.assign` | `principalId`, `groupId`, `roleId`, `scope?`, `expiresAt?` | `authorisation.role-assignments:manage` (the group) | The highest risk among the role's permissions (wildcards resolved against the catalogue, covering only `low` and `medium`), at least `medium`; `critical` for `group-and-descendants` |
| `role.unassign` | `principalId`, `groupId`, `roleId` | `authorisation.role-assignments:manage` (the group) | `medium` |
| `grant.create` | `grant` (resource with its owning group, holder, exact permissions, expiry) | `authorisation.grants:manage` (the owning group) | The highest among the permissions, at least `high`; `critical` beyond the tenant |
| `grant.revoke` | `grantId` | `authorisation.grants:manage` (the grant's owning group) | `medium` |
| `role.define`, `role.delete` | `tenantId`, `role` / `roleId` | `authorisation.roles:manage` (the tenant's root group) | `critical` |
| `group.change-default-roles` | `groupId`, `defaultRoles: { member, guest }` | `authorisation.group-access:manage` (the group) | The highest among the roles chosen, at least `high` |
| `group.change-review-interval` | `groupId`, `intervalDays` (1 to 3650, or null) | `authorisation.group-access:manage` (the group) | `high` |
| `assignment.confirm` | `principalId`, `groupId`, `roleId` | `authorisation.role-assignments:manage` (the group) | `low` |

Every request carries a justification: a reason code and, where the group requires one, a reference.

**Requesting** (`request({ subject, request, correlationId })`):

1. The request is parsed strictly; the group it is governed by is found (for `grant.revoke`, the grant's owning group; for `role.define` and `role.delete`, the root of a group of the tenant the requester is an active member of, on which they hold `authorisation.roles:manage`). Anything unknown is `forbidden`.
2. The requester must hold the permission on that group through Authorisation's own decision, at `strong` consistency, at the assurance the permission's risk requires.
3. Identity's facts come from the governance port: the group's approval requirement and reference rule, the safety periods in force, its parent and root groups, whether it is the requester's personal group, the requester's recovery hold and the identities the requester controls. A port failure is `unavailable`, an unknown group `forbidden`; nothing is recorded.
4. Refused as `conflict`: a **self-grant** (outside their own personal group, nobody assigns a role to themselves, confirms their own assignment or grants themselves access); a change to **`owner`** (owners follow Identity: `role.assign` and `role.unassign` refuse it, and it is never a default role); and a change whose target no longer holds (`unknown-role`, `not-a-member`, `not-assigned`, `role-in-use`, `guest-role-too-risky`, `grant-gone`, `unknown-holder`, `expiry-in-the-past`, `built-in-role`, `unknown-permission`). A missing required reference is `validation-failed` (`reference-missing`).
5. The requester steps up to the change's risk (`STEP_UP_REQUIREMENTS`: `high` `aal2`; `critical` `aal2`, phishing resistant, within 15 minutes), else `insufficient-assurance`.
6. **Requirement and route**: no approver in the requester's own personal group (step-up only); otherwise the group's requirement, never below one approver for `high` and `critical`. The route is chosen as Identity chooses it: qualifying approvers in the group (principals who hold the permission now, by Authorisation's own qualification, excluding the requester, the beneficiary and the identities the requester controls); else one owner of the parent group; else one owner of the tenant's root group (owners from the governance port); else the **published delay** (`publishedDelayHighHours`, or `publishedDelayCriticalHours` for `critical`), which the requester cannot shorten but may cancel.
7. A change requested within the requester's **recovery hold**, and a change of default roles to riskier ones (held for `recoveryHoldHours`), records `heldUntil` and is announced with `authorisation.change-held`; it cannot apply before then.
8. The change is recorded with its **digest**: SHA-256 of the canonical JSON (`canonicalJson`) of its type, tenant, group, requester, beneficiary, risk, justification, target, required approvals, route, and the group's requirement and owners' groups as read. With no approver needed it applies at once in the same transaction; `authorisation.change-requested` is written either way.

**Deciding** (`decide({ subject, changeId, changeDigest, decision, correlationId })`): only someone who may decide it now (a qualifying approver for `approvers`; an owner, by the governance port, of the parent or root group recorded for the owner routes) or its requester or beneficiary may reach it; anyone else is `forbidden`. Refused as `conflict`: the requester (`own-request`), the beneficiary, an identity the requester controls, a second decision by the same approver, a change no longer awaiting approval, and a digest that differs from the recorded one or from the change as stored (`change-differs`); a session short of the risk's step-up is `insufficient-assurance`. A rejection ends it. When enough approvals are recorded, the change applies **in the same transaction** as the decision and its outbox events, after every rule is checked again: the digest, the group still active and in the tenant, the group's requirement unchanged since the digest was taken, no self-grant, the requester still holding the permission, the target still holding, and a risk no higher than recorded. A rule that no longer holds `rejects` the change (the rule is kept as a code for the server); a port or database failure records nothing.

**Expiry, delays and cancelling**: a change awaiting an approver expires unapplied after `approvalExpiryDays`; one under a published delay does not expire, and applies when the delay ends; a held, approved change waits as `delayed` until its hold ends. Maintenance (§18) does each. The requester may cancel an open change (`cancel`); nobody else may.

**Reading**: `get` answers the requester, the beneficiary, whoever may decide, and whoever holds `authorisation.roles:view` on the group; `listForGroup` the group's open changes, under `authorisation.roles:view`.

## 16. Endpoints and client composable

Every endpoint takes the subject only from the host's subject resolver (`provideAuthorisationSubjectResolver`, adapting Authentication's `getAuthenticatedPrincipal(event)`), never from the request; parses bodies with strict schemas; calls the server functions, never SQL; and answers only the coarse contract errors (§7). State-changing requests must carry an `Origin` (or `Referer`) matching `NUXT_AUTHORISATION_BASE_URL`; without it configured, every one is refused. A client may send `x-correlation-id` (a UUID).

| Endpoint | Does | Needs |
|---|---|---|
| `POST /api/authorisation/changes` `{ request }` | Requests a change; 201 with the change | As §15 |
| `GET /api/authorisation/changes/:changeId` | One change | Requester, beneficiary, a decider, or `authorisation.roles:view` |
| `POST /api/authorisation/changes/:changeId/decision` `{ decision, changeDigest }` | Approves or rejects | A decider (§15) |
| `POST /api/authorisation/changes/:changeId/cancel` | Withdraws | The requester |
| `GET /api/authorisation/groups/:groupId/changes` | The group's open changes | `authorisation.roles:view` |
| `GET /api/authorisation/groups/:groupId/assignments` | Live assignments with provenance | `authorisation.roles:view` |
| `GET /api/authorisation/groups/:groupId/access` | Default roles and review interval | `authorisation.roles:view` |
| `GET /api/authorisation/groups/:groupId/access-review` | The access review (§18) | `authorisation.role-assignments:manage` |
| `GET /api/authorisation/groups/:groupId/grants` | Grants bound to the group | `authorisation.grants:manage` |
| `GET /api/authorisation/tenants/:tenantId/roles` | Built-in and custom roles, with their risk | `authorisation.roles:view` in a group of the tenant the caller belongs to |
| `GET /api/authorisation/me` | The caller's own live assignments | Signed in |

There is no endpoint for role documents, maintenance, the outbox relay, erasure or the data export: they are server-only. `useAuthorisation()` is the client composable: for the user experience only, it decides nothing; it uses `useRequestFetch()` so the session cookie is forwarded during server-side rendering. Its `share(input, justification)` lets a domain capability request a `grant.create` for a resource it owns.

## 17. Presentation

`modules/presentation.ts` registers four default pages, which a host moves (`authorisation.pages.paths`) or disables (`authorisation.pages.enabled: false`, keeping the components), or the whole presentation (`authorisation.presentation: false`):

| Page | Default path | Shows |
|---|---|---|
| Group access | `/groups/:groupId/access` | Who holds which role, with requests to give and take away roles (never `owner`); default roles and review interval, with requests to change them; the access review, with confirmations and overdue marks; changes waiting |
| Sharing | `/groups/:groupId/sharing` | The group's grants, with requests to stop each. Sharing starts from the item, in the domain capability that owns it (`useAuthorisation().share(...)`) |
| Tenant roles | `/tenants/:tenantId/roles` | Built-in and custom roles with their risk; requests to define, change and delete custom roles |
| Change | `/access-changes/:changeId` | What a change does, why and how it is approved; approve, reject (with the digest shown), or withdraw |

They are never framed, cached or leaked in a `Referer`. They reach the server only through `useAuthorisation()` and decide nothing. Text comes from `presentation/messages.ts` through `useAuthorisationText()` (hosts override it in `app.config.ts` under `authorisation.messages`, and set `NUXT_PUBLIC_AUTHORISATION_LOCALE`). People are named only through `AuthorisationPersonName`, which by default shows an opaque placeholder made from the end of the identifier; a host replaces it with a component of the same name that asks Profile, as Identity's `IdentityPersonName`. Hosts import `@nuxt4-layers/authorisation/tailwind.css` after Theme Manager's `presentation.css`.

The default pages style only through the SemanticPresentationTheme vocabulary (`authorisationClasses`). Fill, Pen and Edge of one surface share a role and a state; the deliberate cross-role pairings a host's theme must keep legible (`DELIBERATE_PAIRINGS`, `presentation/pairings.ts`) are:

- `pen-muted-default` on `fill-base-default` (hints, notes and definition terms on the card);
- `edge-error-default` on `fill-input-default` (an invalid field's border);
- `edge-base-active` on `fill-base-default` (the focus indicator around controls on the card).

The pages meet WCAG 2.2 AA in light and dark mode; `tests/e2e` checks them with axe, keyboard use, non-text contrast and reflow to 320 CSS pixels.

## 18. Default roles, time-limited assignments, access reviews, maintenance and role documents

**Default roles.** Each group says which role a new member and a new guest receive: `member` and `viewer` until it chooses others (`DEFAULT_GROUP_DEFAULT_ROLES`); either may be none. `authorisationDefaultRoles(groupId)` answers `{ member, guest }` for the host's Identity event handler on `membership.added` (iam-integration's `defaultRoles`). A guest's default role may never hold a `high` or `critical` permission: the change is refused, a role used as a guest default cannot be redefined to hold one, and should one slip through, `authorisationDefaultRoles` answers none for it; it also answers none for `owner` or a role that no longer exists. A role that is a default role cannot be deleted.

**Time-limited assignments.** `role.assign` may carry `expiresAt`. Past it, the assignment confers nothing at once (§6); maintenance removes it with `authorisation.role-expired`. Extending one is a new `role.assign`, with its own approval.

**Access reviews.** A group may set a review interval (`group.change-review-interval`; none by default). The access review (`listAuthorisationAccessReview`, `authorisation.role-assignments:manage`) lists every live assignment with when it was made, by whom, its end date, when it was last confirmed (`assignment.confirm`), when it is due and whether it is **overdue**. An overdue assignment keeps working until someone removes it; maintenance announces it once (`authorisation.review-overdue`), and again only after a new confirmation falls due. Nobody confirms their own assignment.

**Maintenance.** `runAuthorisationMaintenance({ limit? })`, which the host schedules, removes assignments past their end, expires changes nobody decided in time, applies delayed changes whose delay or hold has ended (checking every rule again; a port failure leaves one for the next run), and announces overdue reviews. It is idempotent.

**Role documents.** `exportAuthorisationRoles({ tenantId })` returns the tenant's custom roles as `{ format: 'nuxt4-layers.authorisation.roles', formatVersion: 1, tenantId, roles, digest }`, roles sorted by identifier, `digest` the SHA-256 of the canonical JSON of every other member. `importAuthorisationRoles({ tenantId, document, correlationId })` applies one after the operator's own review, in one transaction: it defines and changes the roles in the document and deletes the tenant's roles not in it. It refuses a document for another tenant (`tenant-mismatch`), a digest that does not match (`digest-mismatch`), a built-in identifier, an exact permission missing from the catalogue, deleting a role still assigned or used as a default (`role-in-use`), and a guest default that would become `high` or `critical`. It writes `authorisation.roles-imported` with the digest. Both are server-only.

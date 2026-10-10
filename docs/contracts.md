# Authorisation Contract (version 4)

`@nuxt4-layers/authorisation/contracts` is the only supported import path for this capability's types and pure helpers. It imports nothing but `zod`, and no driver or other capability's package.

Version 2 follows the [Group Model Definition v0.1](https://github.com/nuxt4-layers/platform-architecture/blob/master/docs/identity/group-model-definition-v01.md) (proposed); version 3 adds paused memberships and principals, and the `effect` of each permission. Changes are listed in §11.

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
| Roles, role assignments, grants, decisions | **Authorisation** | Its own schema (§12) |

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

| Permission | Risk | Effect |
|---|---|---|
| `authorisation.roles:view` | low | view |
| `authorisation.grants:manage` | high | change |
| `authorisation.role-assignments:manage` | critical | change |
| `authorisation.roles:manage` | critical | change |

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
| `owner` | `*`, plus all three `authorisation.*:manage` permissions |
| `administrator` | `*`, plus `authorisation.grants:manage` |
| `member` | `*:view`, `*:create` |
| `viewer` | `*:view` |

Tenants may define **custom roles** (phase 2). A custom role belongs to one tenant and cannot reuse a built-in ID. There is no superuser: platform administration is a group whose powers come from its roles.

## 5. Role assignments and grants

A **role assignment** gives a principal a role in a group. It counts only while the principal is an **active member of that group**, and only for resources in that group's tenant. Its **scope** says how far it reaches:

| Scope | Covers |
|---|---|
| `group` (default) | Resources owned by the group itself |
| `group-and-descendants` | Also resources owned by groups below it in the current hierarchy |

Inheritance therefore exists only where an assignment explicitly asks for it. It never reaches ancestors, siblings, other trees or other tenants. Because it follows the current hierarchy, moving a group changes what such assignments cover, so assigning the descendants scope and reparenting groups are both critical operations.

A principal holds the policy's `personalGroupRole` (`owner` by default, or none) in their own personal group.

A **grant** gives a principal or a group exact permissions (never wildcards) on one resource, optionally until an expiry. A grant to a group applies to its active members. Grants stay inside the resource's tenant: a grant to a principal applies only while that principal has an active membership in the tenant, and a grant to a group only if the group is in the same tenant. Sharing across tenants, including with someone's personal group, needs the host to enable `externalGrants`. This is deliberately stricter than the group model's minimum: by default a direct share ends when its holder leaves the tenant.

A grant is independent of unrelated memberships: ending one membership never removes access that a grant gives through another.

## 6. How a decision is made

1. Refuse if the permission is not in the catalogue or does not belong to the resource's type (`unknown-permission`).
2. Refuse if the directory does not know the principal (`unknown-subject`), or does not know the owning group or describes it inconsistently (`unknown-group`).
3. **Tenant isolation:** if the request has a tenant context, resolved on the server and never taken from the client, refuse a resource in any other tenant (`tenant-mismatch`).
4. Find every route that covers the permission, each with the **standing** of the membership it rests on (§6a):
   - a **role** held in the owning group, or in an ancestor by an assignment scoped `group-and-descendants`, while a member of that group and in the resource's tenant;
   - the **personal-group role**, if the resource belongs to the subject's own personal group;
   - an unexpired **grant** that stays inside the tenant (§5).
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
| `unavailable` | 503 | Directory, database or clock failure (§13). Fails closed |

A `paused` refusal is `forbidden` over HTTP like any other; the host may tell the signed-in person, from their own state, that resuming lets them act.

A domain capability that must hide whether a resource exists answers *not found* from its own contract.

## 8. Events

`authorisation.denied`, `authorisation.role-defined`, `authorisation.role-changed`, `authorisation.role-deleted`, `authorisation.role-assigned`, `authorisation.role-unassigned`, `authorisation.grant-created`, `authorisation.grant-revoked` and `authorisation.principal-erased`. Events carry opaque IDs, the permission, role and reason only: never names, email addresses or resource attributes. Delivery is best effort and never changes an outcome.

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

This is contract version 3, provided by package 0.3. Before 1.0, breaking changes are listed here and in the release notes.

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

Version 4 (access administration) is being built in stages; its full description follows when the stages are complete. So far: `authorisation.role-assignments:manage` is `medium` (the floor of any assignment), `authorisation.group-access:manage` (`high`) is new, the `conflict` error code, pending-change, event-outbox, governance-port and subject-resolver types, `expiresAt` on assignments and `owningGroupId` on grants.

## 12. Storage and server functions

Authorisation keeps custom roles (per tenant), role assignments (principal, group, role, scope) and grants in its own schema, through append-only migrations (`migrateAuthorisationDatabase()`), over the host's pool. Identifiers are opaque text: nothing else about a person is stored.

| Function | Does |
|---|---|
| `authorise({ subject, permission, resource, requestTenantId? })` | The decision (§6). Gathers the actor and the owning group from the directory (`strong` for `high` and `critical` permissions, `bounded` otherwise) and the subject's assignments, the tenant's custom roles and the resource's grants from the store. A refusal is announced as `authorisation.denied` |
| `requireAuthorisation(input)` | As `authorise`, but throws a coarse HTTP error (`forbidden`, `insufficient-assurance` or `unavailable`) unless allowed |
| `authorisationQualifies({ principalId, permission, resource })` | Whether the principal holds the permission on the resource now, whatever their session: for approvals, where the approver steps up when deciding. `strong` reads |
| `countAuthorisationQualifying({ permission, resource, excludingPrincipalIds, limit })` | How many principals other than those excluded qualify, up to `limit` (at most 100). Candidates are holders of assignments that can reach the resource's group and of grants on the resource to a principal; grants to a group are not counted, since Authorisation cannot list a group's members, so the count errs low |
| `listAuthorisationRoleAssignments({ principalId?, groupId? })` | A principal's assignments, or a group's |
| `assignAuthorisationRole({ principalId, groupId, roleId, scope?, actorPrincipalId })`, `unassignAuthorisationRole({ principalId, groupId, roleId \| null, actorPrincipalId })` | Change assignments: a built-in role, or a custom role of the group's tenant, in a group the directory knows. `authorisation.role-assigned` and `role-unassigned` |
| `defineAuthorisationRole`, `deleteAuthorisationRole` | A tenant's custom roles: never a built-in ID, never an exact permission missing from the catalogue. `authorisation.role-defined`, `role-changed`, `role-deleted` |
| `createAuthorisationGrant`, `revokeAuthorisationGrant` | Grants of exact, catalogued permissions of the resource's type. `authorisation.grant-created` and `grant-revoked` |
| `exportAuthorisationData({ principalId, correlationId })` | Authorisation's part of a data-subject access request (`AuthorisationDataExport`): the principal's role assignments and the grants made to it; null when it holds none. Server-only, called through iam-integration's coordination adapter for Profile |
| `eraseAuthorisationPrincipal({ principalId, actorPrincipalId })` | Removes every assignment and grant the principal holds, on Identity's `identity.closed` unless a legal hold covers Authorisation's part (iam-integration's account closure). Records the principal made for others keep its opaque identifier as their provenance. Idempotent; `authorisation.principal-erased` when something was removed |

The functions that change roles, assignments and grants **decide nothing**: their caller has authorised the change. Today that is the host applying Identity's events through iam-integration's adapters (owners hold the `owner` role, members the group's default role); the layer's own administration endpoints, guarded by its `authorisation.*` permissions, are phase 3.

Every function fails closed: a directory, database or clock failure (§13) throws `AuthorisationFailure` with code `unavailable`, and invalid input `validation-failed`.

## 13. Time

Authorisation reads the current time from the clock the host supplies (`provideAuthorisationClock({ now })`), as [iam-integration's architecture §7](https://github.com/nuxt4-layers/iam-integration/blob/e986245d746507bf7093ca203e346ab1b571e3a8/docs/architecture.md#7-time) asks of every member; without one, it uses the system clock. A host supplies the same clock to every member, or none.

- Every time Authorisation keeps or judges comes from the clock: whether a grant has expired (`expiresAt`, at each decision and when a grant is made), whether an authentication is recent enough for the permission's risk (`maxAuthenticationAgeSeconds`), the times it records (`created_at` of assignments, custom roles and grants; a custom role's `updated_at`), events' `occurredAt` and an export's `exportedAt`. The database judges no time of its own: each such time is passed to it from the clock.
- The clock is read once per decision, before anything else, and that one time decides the whole decision.
- A clock that throws, or answers anything but a valid `Date`, fails the operation as `unavailable`: the decision is refused, and nothing is read, written or announced. Authorisation never falls back to another time.
- The clock is trusted like a key: whoever supplies it can keep an expired grant alive or make an old sign-in look recent. Only the host composes it, from server code; no request can set or move it. A clock that can be moved is for tests only.

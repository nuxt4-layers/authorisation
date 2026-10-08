# Authorisation Contract (version 2)

`@nuxt4-layers/authorisation/contracts` is the only supported import path for this capability's types and pure helpers. It imports nothing but `zod`, and no driver or other capability's package.

Version 2 follows the [Group Model Definition v0.1](https://github.com/nuxt4-layers/platform-architecture/blob/master/docs/identity/group-model-definition-v01.md) (proposed). Changes from version 1 are listed in §11.

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
| Roles, role assignments, grants, decisions | **Authorisation** | Its own schema (phase 2) |

Authorisation stores no domain data, no groups and no memberships.

## 2. Groups own information

Every resource has exactly one **owning group**. A group is any collection of people for a purpose: an organisation, company, club, committee, event, department or office. Identity decides which kinds exist and how deep they nest. Each group has at most one parent, so Authorisation sees a group's **lineage** as a single chain from its root down to itself:

```text
['company-a', 'london-office', 'sales']
```

The hierarchy records organisational structure only. **It confers no privilege by default** (§5).

A **tenant** is the isolation boundary. It is supplied for each group by the directory and is not assumed to be the root of the lineage: one tenant may hold several trees. Tenant isolation is checked separately from roles and grants (§6).

Every human identity has a **personal group**: a unary group whose only member is that principal, like a Unix user's own group. A resource a user keeps for themselves belongs to their personal group. Identities without one, such as service identities, are supported.

Because information belongs to groups, **leaving a group ends the access derived from that membership**, including to resources the leaver created: a company-owned report stays the company's. Joining a group gives access up to the roles held there. Only `active` memberships count; `suspended` and `ended` ones grant nothing.

**Creator provenance is not access.** A resource may record its `creatorPrincipalId`; that alone grants nothing. A role can use it in a condition ("members may edit what they created"), and that role still needs an active membership.

## 3. Permissions

A permission names one business capability: `<resource>:<action>`.

- `<resource>` is a plural noun, optionally namespaced: `orders`, `blog.comments`.
- `<action>` is a snake-case verb: `view`, `create`, `process_refund`.
- Scope never appears in the name: `orders:view`, never `orders:view_own`.

Each permission has a description and a risk level:

| Risk | Meaning | Default assurance |
|---|---|---|
| `low` | Reads non-sensitive data | Any authenticated session |
| `medium` | Changes data reversibly | Any authenticated session |
| `high` | Financial, legal, personal-data or hard-to-reverse | `aal2` |
| `critical` | Destructive, or changes who may do what | `aal2`, phishing resistant, authenticated in the last 15 minutes |

Domain capabilities export their definitions from their own contracts; the host passes them to `provideAuthorisationPermissions`. A name defined twice with a different description or risk is refused. Authorisation adds its own:

| Permission | Risk |
|---|---|
| `authorisation.roles:view` | low |
| `authorisation.grants:manage` | high |
| `authorisation.role-assignments:manage` | critical |
| `authorisation.roles:manage` | critical |

A permission missing from the catalogue is never granted.

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
4. Allow through a **role** held in the owning group, or in an ancestor by an assignment scoped `group-and-descendants`, while an active member of that group and in the resource's tenant.
5. Otherwise allow through the **personal-group role**, if the resource belongs to the subject's own personal group.
6. Otherwise allow through an unexpired **grant** that stays inside the tenant (§5).
7. Otherwise refuse (`not-permitted`).
8. If allowed, check the session against the permission's risk level. If it falls short, refuse with `insufficient-assurance` and the requirement, so the host can send the user to step up or re-authenticate.

The decision is `{ allowed: true, permission, via }` (`via` is `role`, `personal-group` or `grant`) or `{ allowed: false, permission, reason, requirement }`. Reasons are for the server and audit. Only the coarse error codes below cross HTTP.

## 7. Errors

| Code | HTTP | Meaning |
|---|---|---|
| `unauthenticated` | 401 | No signed-in subject |
| `forbidden` | 403 | Refused. Never says why, or whether the resource or group exists |
| `insufficient-assurance` | 403 | Permitted after step-up or re-authentication |
| `validation-failed` | 400 | Malformed input |
| `unavailable` | 503 | Directory or database failure. Fails closed |

A domain capability that must hide whether a resource exists answers *not found* from its own contract.

## 8. Events

`authorisation.denied`, `authorisation.role-defined`, `authorisation.role-changed`, `authorisation.role-deleted`, `authorisation.role-assigned`, `authorisation.role-unassigned`, `authorisation.grant-created` and `authorisation.grant-revoked`. Events carry opaque IDs, the permission, role and reason only: never names, email addresses or resource attributes. Delivery is best effort and never changes an outcome.

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

This is contract version 2, provided by package 0.2. Before 1.0, breaking changes are listed here and in the release notes.

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

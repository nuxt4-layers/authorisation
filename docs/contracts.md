# Authorisation Contract (version 1)

`@nuxt4-layers/authorisation/contracts` is the only supported import path for this capability's types and pure helpers. It imports nothing but `zod`, and no driver or other capability's package.

Authorisation answers one question: **may this subject perform this permission on this resource, now?**

```text
subject + permission + resource + group context + roles + grants -> decision
```

## 1. Boundaries

| Concern | Owner | How Authorisation sees it |
|---|---|---|
| Who is signed in, and how strongly | Authentication | `AuthorisationSubject`, a structural subset of `AuthenticatedPrincipal` that the host passes in |
| Users, groups, group types, lineage, memberships, personal groups | Identity | The `AuthorisationDirectory` port, adapted by the host |
| Resources and their data | The domain capability that owns them | `AuthorisationResource`, described by that capability at decision time |
| Permissions | Each domain capability declares its own | The catalogue, supplied by the host |
| Roles, role assignments, grants, decisions | **Authorisation** | Its own schema (phase 2) |

Authorisation stores no domain data, no groups and no memberships.

## 2. Groups own information

Every resource has exactly one **owning group**. A group is any collection of people for a purpose: an organisation, company, club, committee, event, department or office. Identity decides which kinds exist and how deep they nest; Authorisation sees only each group's **lineage**, from its tenant root down to itself:

```text
['company-a', 'london-office', 'sales']
```

The first entry is the **tenant root**, the isolation boundary.

Every identity is created with a **personal group**: a unary group whose only member is that principal, like a Unix user's own group. A resource a user keeps for themselves belongs to their personal group, whose lineage is just `[personalGroupId]`.

Because information belongs to groups, **leaving a group ends access to everything in it**, including resources the leaver created. Joining a group gives access up to the roles held there. Nothing has to be revoked by hand: the directory stops listing the membership, and every decision after that refuses.

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
  { "attribute": "resource.ownerPrincipalId", "operator": "equals", "value": { "ref": "subject.principalId" } }
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

Tenants may define **custom roles** (phase 2). A custom role belongs to one tenant root and cannot reuse a built-in ID. There is no superuser: platform administration is a group whose powers come from its roles.

## 5. Role assignments and grants

A **role assignment** gives a principal a role in a group. It applies to resources owned by that group **and its descendants**, never to its ancestors, siblings or other tenants, and only while the principal is a current member of that group.

A **grant** gives a principal or a group exact permissions (never wildcards) on one resource, optionally until an expiry. A grant to a group applies to its current members. Grants stay inside the resource's tenant: a grant to a principal applies only while that principal is a member of the tenant, and a grant to a group only if the group is in the same tenant. Sharing across tenants, including with someone's personal group, needs the host to enable `externalGrants`.

## 6. How a decision is made

1. Refuse if the permission is not in the catalogue or does not belong to the resource's type (`unknown-permission`).
2. Refuse if the directory does not know the principal (`unknown-subject`) or the owning group, or the group's lineage does not end at it (`unknown-group`).
3. Allow through a **role** held in a group on the resource's lineage while a member of that group. Every principal is `owner` of their personal group.
4. Otherwise allow if the subject is the resource's **owner** and a member of a group on its lineage, using the policy's `resourceOwnerRole` (`owner` by default).
5. Otherwise allow through an unexpired **grant**.
6. Otherwise refuse (`not-permitted`).
7. If allowed, check the session against the permission's risk level. If it falls short, refuse with `insufficient-assurance` and the requirement, so the host can send the user to step up or re-authenticate.

The decision is `{ allowed: true, permission, via }` or `{ allowed: false, permission, reason, requirement }`. Reasons are for the server and audit. Only the coarse error codes below cross HTTP.

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

## 10. Versioning

This is contract version 1, provided by package 0.x. Before 1.0, breaking changes are listed in the release notes.

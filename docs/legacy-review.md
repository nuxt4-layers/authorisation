# Legacy Layer Review: `nuxt4-layers/legacy-authorisation`

**Reviewed:** 2026-10-08, commit `9087b04` on `master` (16 files, about 1 300 lines, most of it the README).
**Purpose:** Record what to keep and what to leave behind when building this layer. No legacy source is copied into this repository.

## 1. Summary

The legacy layer's README is a thoughtful guide to naming permissions and writing attribute-based conditions, and its evaluator showed the right instinct (default deny, policy as data). The code around it was a sketch: every endpoint trusted a cookie holding an email address, the client decided access, and the layer could only build inside its original monorepo. It is treated as a source of ideas, not code.

## 2. What it contained

| Area | Contents |
|---|---|
| Server | `GET /api/authorisation/session` (all `global` policies), `GET`/`POST /api/authorisation/policies`, `PUT`/`DELETE /api/authorisation/policies/[id]`, an `IPolicyRepository` port reached through an undeclared service locator |
| Client | `useAuthorisation()` with `can(action, resource)`, evaluating policies in the browser |
| Logic | `policyEvaluator.ts` (RBAC permission lists with ABAC conditions), `permissions.ts` constants |
| UI | `pages/account/Permissions.vue`, a role editor |
| Data model | `PolicyRole` (id, name, scope string, permissions, conditions), `RoleAssignment` (user, role, scope), `IIdentity` (id, roles, capabilities) |

## 3. Critical defects

### Security

- **No authorisation on the authorisation API.** Every endpoint checked only that a cookie named `authentication-token-email` existed. Anyone could set it to any value and then create, change or delete roles.
- **The client was the enforcement point.** `can()` ran in the browser against policies the server sent to every signed-in user; no server code called the evaluator. Every user could read every global policy.
- **Superuser bypass.** `identity.roles.includes('superuser')` returned `true` for everything, before any policy, with no assurance or audit requirement.
- **Unvalidated input.** Request bodies were cast to `PolicyRole` and stored as-is: any permission string, any scope, any conditions. `PUT` merged an arbitrary partial object.
- **Predictable identifiers.** New policy IDs came from `Math.random()`.
- **Conditions compared with `$user.<path>` and `resource.<path>` through lodash `get`**, so a policy could read any property, including inherited ones.
- **Scope was a free string** (`global`, `tenant:company_123`) that nothing checked; assignments' scopes were never compared with resources.

### Correctness and build

- `getPolicyRepository()` was called through a Nitro auto-import that did not exist in the layer.
- The session endpoint ignored the user and returned the global policies to everyone.
- `lodash-es` and Pinia were used or declared without being needed or declared correctly; `@monorepo/authentication` was `extends`-ed, coupling the layers through inheritance.
- The page used a `layout: 'account'` and an `authentication` middleware the layer did not provide, raw colours and `alert()`/`confirm()`.
- No tests.

### Scope

- `IIdentity.roles` mixed identity attributes into authorisation input; group membership (`$user.tenantId`, `$user.managedGroupIds`) was assumed to live on the user.
- The README's integration list (`user-manager`, `membership-manager`, `tenancy-manager`) described direct dependencies rather than contracts.

## 4. Ideas carried forward

1. **Permission naming** (README chapter 1): `<resource>:<action>`, plural resources, business capabilities rather than buttons, scope never in the name. Now validated by `isPermissionName`.
2. **Risk levels** (`low`, `medium`, `high`, `critical`) driving stronger authentication. Now each risk level maps to an assurance requirement in the policy.
3. **Wildcards belong in role definitions, not in permission names.** Now patterns (`orders:*`, `*:view`, `*`), with the added rule that wildcards never cover high or critical permissions.
4. **Default deny.** Now rule 1 of the decision engine, including unknown permissions, principals and groups.
5. **Policy as validated data**, so roles can be stored and edited. Now zod schemas for roles and conditions.
6. **A small set of attribute conditions** (README chapter 2). Kept to four operators on resource attributes and the resource owner, with `{ ref: 'subject.principalId' }` instead of string variables. Time, IP and geography rules are left out: they belong to the host or to Authentication's step-up.
7. **A storage port with swappable adapters.** Now the composition-supplied persistence port (ADR-0002).
8. **The test-matrix style** in README §2.10. Now `tests/decision.test.ts`.

## 5. Ideas left behind

- The superuser bypass. Platform administration is a group like any other; its powers come from roles and are subject to the same assurance rules.
- Client-side enforcement. A client composable may come later for user-experience hints only.
- `IIdentity` and user-held roles, tenant IDs and managed-group lists. Groups and memberships belong to Identity and reach this layer through the `AuthorisationDirectory` port.
- Free-text scope strings. Scope is the resource's owning group and its lineage.
- Debug policies, `matches_regex`, `in_cidr`, time windows and computed values like `30_days_ago`.

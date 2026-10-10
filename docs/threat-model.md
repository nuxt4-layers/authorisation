# Threat Model and Control Register

**Scope:** `@nuxt4-layers/authorisation`, contract version 1.
**Baseline:** OWASP ASVS 5.0.0 Level 2, with Level 3 requirements for authorisation and tenant isolation where appropriate (Security Architecture §1). References are to ASVS 5.0.0 chapters (V8); mapping to individual requirement IDs is recorded in the phase 2 verification.

## 1. Assets

- The integrity of decisions: who may do what to which group's information.
- Roles, role assignments and grants (phase 2).
- The confidentiality of group membership and resource existence, which decisions must not reveal.

## 2. Trust boundaries

| Boundary | Trusted input | Untrusted input |
|---|---|---|
| Browser → server | Nothing | Every identifier, attribute and claim in a request |
| Authentication → host → Authorisation | The authenticated principal, read on the server | — |
| Identity → host directory adapter → Authorisation | Lineage and current memberships | — |
| Domain capability → Authorisation | The resource description the domain capability read from its own store | A resource ID or owning group supplied by a client |
| Host → database | The `authorisation` schema | Other capabilities' schemas (never read) |

## 3. Threats and controls

| ID | Threat | Control | Evidence | Status |
|---|---|---|---|---|
| T1 | Access granted by default or by an unanticipated path | Deny by default; unknown permission, principal or group refused (V8) | `tests/decision.test.ts` "deny by default" | Implemented |
| T2 | Cross-tenant access | Tenant supplied by the directory, never the client; separate `tenant-mismatch` check against the server-resolved request tenant; roles, custom roles and grants confined to the resource's tenant; no superuser (V8) | "tenant isolation" decision tests | Implemented |
| T3 | Access kept after leaving a group | Only `active` and `paused` memberships count; roles and principal grants require them; creator provenance grants nothing; grants stay inside the resource's tenant by default | "membership status and departure", "creator provenance" tests | Implemented |
| T4 | Privilege escalation through broad wildcards | Wildcards never cover high or critical permissions; a role naming an unknown permission is refused at startup | decision and composition tests | Implemented |
| T5 | Typos that silently grant nothing or everything | Permission and pattern grammar; catalogue membership required | `tests/permissions.test.ts` | Implemented |
| T6 | Sensitive operations from a weak or stale session | Risk level maps to assurance; floors in the policy (V8) | policy and decision tests | Implemented |
| T7 | Decision reveals existence of resources or groups | Coarse HTTP error codes; detailed reasons stay server-side (V8) | `tests/contracts.test.ts` | Implemented |
| T8 | Client-side enforcement relied on | No client decision API; enforcement is server-only (V8) | Architecture | Implemented |
| T9 | Missing port leads to an implicit permissive store | Required ports fail closed (ADR-0002) | `tests/composition.test.ts` | Implemented |
| T10 | Supply-chain compromise | Minimal dependencies (`zod`); `minimumReleaseAge`, `blockExoticSubdeps`, frozen lockfile, dependency review (development-only exceptions recorded in §4) | `pnpm-workspace.yaml`, workflows | Implemented |
| T11 | Unauthorised change to roles, assignments or grants | Server functions only (no endpoint yet), for callers that have authorised the change; validated against the directory and the catalogue; every change announced. The layer's own `authorisation.*` permissions guard the phase 3 endpoints | `tests/database.test.ts` | Implemented (server functions); endpoints phase 3 |
| T12 | Last owner removed, locking a group out | Ownership is Identity's: it refuses removing a group's last active owner, and the `owner` role follows Identity's owners through iam-integration's adapters | Identity's approvals tests | Implemented in Identity |
| T13 | Stale membership from a caching directory adapter | Consistency levels in the port: `strong` (no cache) for high and critical permissions, `bounded` (≤ 30 s) otherwise; directory failure fails closed; decisions never cached or embedded in sessions | `tests/database.test.ts` | Implemented |
| T14 | Policy changes not auditable | Events for every role, assignment and grant change, and denials (V16) | `tests/database.test.ts` | Implemented |
| T15 | Personal data in logs and events | Events carry opaque IDs only | `shared/events.ts` | Implemented |
| T16 | Prototype or path traversal through conditions | Conditions read own properties of `resource.attributes` only | decision tests | Implemented |
| T18 | A paused member, hidden from the group, changes its information or reads sensitive material unnoticed | Paused standing (a membership, or the whole principal) confers only `view` permissions at `low` or `medium` risk on every route, personal group and grants included; `effect` is declared per permission and defaults to `change`; an unknown principal status confers nothing; an active route is never hidden by a paused one (§6a) | "paused memberships and principals" decision tests; `tests/database.test.ts` | Implemented |
| T17 | Privilege gained through the group hierarchy, e.g. by reparenting a group under one whose admins should not see it | The hierarchy confers nothing by default; inheritance only through an explicit `group-and-descendants` assignment, which follows the current tree; assigning that scope is a critical operation | "the hierarchy confers no privilege by default" tests | Implemented (engine); permission checks on assignment phase 2 |
| T19 | A closed person keeps access, or their roles and grants outlive their erasure | `eraseAuthorisationPrincipal` removes every assignment and grant the principal holds, on `identity.closed` through iam-integration's handler (deferred only by a recorded legal hold); idempotent and announced; the export lists only what the principal holds, by opaque identifier and permission name | `tests/database.test.ts` | Implemented (phase 2b) |

## 4. Deferred controls and risk treatments

| Gap | Risk | Treatment |
|---|---|---|
| No administration endpoints yet | Roles are changed by host server code only | Phase 3 |
| Phishing-resistant requirement for `critical` can be turned off | Critical operations from phishable sessions | Allowed only with a documented host risk treatment |
| `simple-git` 3.36.0 advisories GHSA-x6jw-m9v5-85vh (critical), GHSA-858h-whjf-mvg5 and GHSA-g4wm-2vf7-vfgr (high), allow-listed in `dependency-review.yml` | Command execution if an attacker controls `simple-git` arguments or Git configuration | Accepted 2026-10-08, review by 2027-01-08. Reached only through `nuxt` → `@nuxt/devtools` (a devDependency, never installed into hosts); devtools passes fixed arguments (`branch`, `revparse --short HEAD`, `status`) on the local checkout in `nuxt dev` only. No patched 3.x exists, and `simple-git` 4.x drops the default export devtools imports. Remove the allow-list once devtools depends on a patched `simple-git`. |
| `braces` 3.0.3 advisory GHSA-vfj7-8cjw-p6xm (high), allow-listed in `dependency-review.yml` | Denial of service from a deeply nested brace pattern | Accepted 2026-10-08, review by 2027-01-08. Reached only through `nuxt` → `nitropack` → `globby`/`micromatch` (devDependencies here; `nuxt` is a peer), which expand glob patterns from the project's own configuration at build time, never user input. No patched `braces` release exists. Remove the allow-list once one does. |
| `node-forge` 1.4.0 advisory GHSA-86w9-cpqp-85rv (high), allow-listed in `dependency-review.yml` | Forged RSA signatures accepted by signature verification | Accepted 2026-10-08, review by 2027-01-08. Reached only through `nuxt` → `nitropack` → `listhen` (devDependencies here; `nuxt` is a peer), which uses it to generate, encode and load a self-signed certificate for `nuxt dev --https` and never verifies signatures. No patched `node-forge` release exists. Remove the allow-list once one does. |

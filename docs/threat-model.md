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
| T2 | Cross-tenant access | A role applies only on its group's lineage; lineage comes from the directory, never the client; no superuser (V8) | "tenant isolation" tests | Implemented |
| T3 | Access kept after leaving a group | Roles and resource ownership require current membership; grants stay inside the resource's tenant by default | "leaving a group ends access" tests | Implemented |
| T4 | Privilege escalation through broad wildcards | Wildcards never cover high or critical permissions; a role naming an unknown permission is refused at startup | decision and composition tests | Implemented |
| T5 | Typos that silently grant nothing or everything | Permission and pattern grammar; catalogue membership required | `tests/permissions.test.ts` | Implemented |
| T6 | Sensitive operations from a weak or stale session | Risk level maps to assurance; floors in the policy (V8) | policy and decision tests | Implemented |
| T7 | Decision reveals existence of resources or groups | Coarse HTTP error codes; detailed reasons stay server-side (V8) | `tests/contracts.test.ts` | Implemented |
| T8 | Client-side enforcement relied on | No client decision API; enforcement is server-only (V8) | Architecture | Implemented |
| T9 | Missing port leads to an implicit permissive store | Required ports fail closed (ADR-0002) | `tests/composition.test.ts` | Implemented |
| T10 | Supply-chain compromise | Minimal dependencies (`zod`); `minimumReleaseAge`, `blockExoticSubdeps`, frozen lockfile, dependency review | `pnpm-workspace.yaml`, workflows | Implemented |
| T11 | Unauthorised change to roles, assignments or grants | The layer's own `authorisation.*` permissions, critical risk for assignments and roles | — | Phase 2 |
| T12 | Last owner removed, locking a group out | Refuse removing the last owner | — | Phase 2 |
| T13 | Stale membership from a caching directory adapter | Contract requires current data; caches expire within seconds | `docs/composition-contract.md` | Host responsibility |
| T14 | Policy changes not auditable | Events for every role, assignment and grant change, and denials (V16) | Event contract | Contract implemented; emission phase 2 |
| T15 | Personal data in logs and events | Events carry opaque IDs only | `shared/events.ts` | Implemented |
| T16 | Prototype or path traversal through conditions | Conditions read own properties of `resource.attributes` only | decision tests | Implemented |

## 4. Deferred controls and risk treatments

| Gap | Risk | Treatment |
|---|---|---|
| No storage, endpoints or administration yet | Hosts cannot yet manage roles at runtime | Phase 2 and 3 |
| No Identity layer exists | Hosts must write their own directory adapter | Contract defined; Identity to follow |
| Phishing-resistant requirement for `critical` can be turned off | Critical operations from phishable sessions | Allowed only with a documented host risk treatment |

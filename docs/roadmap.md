# Roadmap

Each phase is delivered as its own pull request with tests, and keeps `pnpm check` green.

| Phase | Scope | Status |
|---|---|---|
| 1. Foundation | Package, manifest, public contract (subject, permissions, resources and lineage, roles, conditions, grants, decisions, errors, events, policy, ports), composition registry (fail closed), permission catalogue, pure decision engine, docs, threat model, CI, playground | Complete |
| 1a. Group model (contract 2) | Reconcile with platform-architecture's Group Model Definition v0.1: no implicit hierarchy inheritance (explicit assignment scope), tenant as a separate check, creator provenance without access, membership status, nullable personal group, personal-group role as policy, directory consistency levels for revocation | Complete |
| 2. Core | PostgreSQL schema and migrations for custom roles, role assignments (with scope) and grants; `authorise(event, permission, resource)` and `requireAuthorisation(...)` server functions that gather facts from the directory (`strong` reads for high and critical permissions, `bounded` otherwise) and database; denial and change events; last-owner protection; revocation tests | In review: storage, `authorise`/`requireAuthorisation`, approval qualification (`authorisationQualifies`, `countAuthorisationQualifying`), assignment, custom-role and grant server functions with events; last-owner protection is Identity's |
| 3. Administration | `/api/authorisation/*` endpoints to define custom roles, assign roles and share resources, each guarded by the layer's own permissions and step-up; client composable for user-experience hints only | Planned |
| 4. Default pages | Accessible (WCAG 2.2 AA), localisable role, membership-role and sharing pages through the `SemanticPresentationTheme` vocabulary; can be disabled | Planned |
| 5. Host integration | Composition into `platform-test-harness` beside Authentication, with a directory adapter, negative isolation tests and end-to-end tests | Planned |

## Dependencies on other capabilities

- **Identity** owns users, groups, group types, the single-parent hierarchy, memberships and their lifecycle, and the personal group created with every human identity (Group Model Definition v0.1). It does not exist yet; until it does, a host supplies the `AuthorisationDirectory` adapter from its own store. Identity can replace it without any change to this contract.
- **Tenancy**: tenants come through the directory port today. If a separate tenancy capability is introduced (catalogue v0.3 lists it as a candidate), the host adapts it into the same port.
- **Authentication** supplies the subject. The host passes `AuthenticatedPrincipal`, which satisfies `AuthorisationSubject` structurally.

## Deliberate exclusions

- Groups, memberships, invitations and profile data: Identity.
- Sign-in, sessions and step-up: Authentication. This layer only says which assurance a decision needs.
- Superuser bypasses, client-side enforcement and time, IP or geography rules (see `docs/legacy-review.md`).
- Approval workflows. A later capability can build them on the `high` and `critical` risk levels.

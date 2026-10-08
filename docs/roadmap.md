# Roadmap

Each phase is delivered as its own pull request with tests, and keeps `pnpm check` green.

| Phase | Scope | Status |
|---|---|---|
| 1. Foundation | Package, manifest, public contract (subject, permissions, resources and lineage, roles, conditions, grants, decisions, errors, events, policy, ports), composition registry (fail closed), permission catalogue, pure decision engine, docs, threat model, CI, playground | Complete |
| 2. Core | PostgreSQL schema and migrations for custom roles, role assignments and grants; `authorise(event, permission, resource)` and `requireAuthorisation(...)` server functions that gather facts from the directory and database; denial and change events; last-owner protection | Planned |
| 3. Administration | `/api/authorisation/*` endpoints to define custom roles, assign roles and share resources, each guarded by the layer's own permissions and step-up; client composable for user-experience hints only | Planned |
| 4. Default pages | Accessible (WCAG 2.2 AA), localisable role, membership-role and sharing pages through the `SemanticPresentationTheme` vocabulary; can be disabled | Planned |
| 5. Host integration | Composition into `platform-test-harness` beside Authentication, with a directory adapter, negative isolation tests and end-to-end tests | Planned |

## Dependencies on other capabilities

- **Identity** owns users, groups, group types, nesting rules, memberships and the personal group created with every identity. It does not exist yet; until it does, a host supplies the `AuthorisationDirectory` adapter from its own store. Identity can replace it without any change to this contract.
- **Authentication** supplies the subject. The host passes `AuthenticatedPrincipal`, which satisfies `AuthorisationSubject` structurally.

## Deliberate exclusions

- Groups, memberships, invitations and profile data: Identity.
- Sign-in, sessions and step-up: Authentication. This layer only says which assurance a decision needs.
- Superuser bypasses, client-side enforcement and time, IP or geography rules (see `docs/legacy-review.md`).
- Approval workflows. A later capability can build them on the `high` and `critical` risk levels.

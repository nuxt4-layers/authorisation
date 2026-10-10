# Roadmap

Each phase is delivered as its own pull request with tests, and keeps `pnpm check` green.

| Phase | Scope | Status |
|---|---|---|
| 1. Foundation | Package, manifest, public contract (subject, permissions, resources and lineage, roles, conditions, grants, decisions, errors, events, policy, ports), composition registry (fail closed), permission catalogue, pure decision engine, docs, threat model, CI, playground | Complete |
| 1a. Group model (contract 2) | Reconcile with platform-architecture's Group Model Definition v0.1: no implicit hierarchy inheritance (explicit assignment scope), tenant as a separate check, creator provenance without access, membership status, nullable personal group, personal-group role as policy, directory consistency levels for revocation | Complete |
| 2. Core | PostgreSQL schema and migrations for custom roles, role assignments (with scope) and grants; `authorise(event, permission, resource)` and `requireAuthorisation(...)` server functions that gather facts from the directory (`strong` reads for high and critical permissions, `bounded` otherwise) and database; denial and change events; last-owner protection; revocation tests | Complete: storage, `authorise`/`requireAuthorisation`, approval qualification (`authorisationQualifies`, `countAuthorisationQualifying`), assignment, custom-role and grant server functions with events; last-owner protection is Identity's |
| 2a. Paused members (contract 3) | `paused` membership status and principal `status`; `effect: 'view' \| 'change'` on catalogue permissions (default `change`); paused standing confers only `view` at `low` or `medium` risk on every route, the personal group and grants included; `paused` denial reason | Complete |
| 2b. Data-subject requests | `exportAuthorisationData` (assignments and grants held) for Profile's coordination, and `eraseAuthorisationPrincipal` on account closure (`authorisation.principal-erased`), through iam-integration's adapters | Complete |
| 3. Administration (contract 4) | Access administration as iam-integration's [access administration](https://github.com/nuxt4-layers/iam-integration/blob/35e86ab288fed79848b513a98cfbd98304a3cb26/docs/processes/access-administration.md) and [approvals](https://github.com/nuxt4-layers/iam-integration/blob/35e86ab288fed79848b513a98cfbd98304a3cb26/docs/processes/approvals.md) set out: pending changes with approval routes, step-up, recovery holds, digests and every rule re-checked when applying; the governance port; a transactional outbox (`relayAuthorisationOutbox`); per-group default roles (`authorisationDefaultRoles`), time-limited assignments, access reviews and maintenance (`runAuthorisationMaintenance`); roles as versioned documents (`exportAuthorisationRoles`, `importAuthorisationRoles`); `/api/authorisation/*` endpoints behind the subject resolver and an origin check; `useAuthorisation()` for user-experience hints only | Complete |
| 4. Default pages | Accessible (WCAG 2.2 AA, light and dark), localisable group access, sharing, tenant roles and change pages through the `SemanticPresentationTheme` vocabulary; movable and disable-able; overridable `AuthorisationPersonName`; Playwright with axe in CI | Complete |
| 5. Host integration | Composition into `platform-test-harness` beside Authentication, with a directory adapter, negative isolation tests and end-to-end tests; the suite's optional clock port (`provideAuthorisationClock`, [iam-integration's architecture §7](https://github.com/nuxt4-layers/iam-integration/blob/e986245d746507bf7093ca203e346ab1b571e3a8/docs/architecture.md#7-time)), from which grant expiry, authentication age and every recorded time are taken, failing closed on an invalid time | Complete |
| 6. End of life | iam-integration's [group deletion](https://github.com/nuxt4-layers/iam-integration/blob/9d84e3ee22ab9a58df79d880fdc288381b645ebd/docs/processes/group-deletion.md), [tenant lifecycle](https://github.com/nuxt4-layers/iam-integration/blob/9d84e3ee22ab9a58df79d880fdc288381b645ebd/docs/processes/tenant-lifecycle.md) and [retention](https://github.com/nuxt4-layers/iam-integration/blob/9d84e3ee22ab9a58df79d880fdc288381b645ebd/docs/processes/retention.md) processes ([contract](contracts.md) §19): `disposeAuthorisationGroup` and `disposeAuthorisationTenant` with their outbox confirmations, `exportAuthorisationTenantData`, retention of delivered events and decided changes under the optional legal-hold port | In review |

## Dependencies on other capabilities

- **Identity** owns users, groups, group types, the single-parent hierarchy, memberships and their lifecycle (including pausing), and the personal group created with every human identity (Group Model Definition v0.1). A host adapts its directory to `AuthorisationDirectory`; iam-integration provides the reference adapter.
- **Tenancy**: tenants come through the directory port today. If a separate tenancy capability is introduced (catalogue v0.3 lists it as a candidate), the host adapts it into the same port.
- **Authentication** supplies the subject. The host passes `AuthenticatedPrincipal`, which satisfies `AuthorisationSubject` structurally.

## Deliberate exclusions

- Groups, memberships, invitations and profile data: Identity.
- Sign-in, sessions and step-up: Authentication. This layer only says which assurance a decision needs.
- Superuser bypasses, client-side enforcement and time, IP or geography rules (see `docs/legacy-review.md`).
- Just-in-time elevation (iam-integration improvement register item 7): planned later.

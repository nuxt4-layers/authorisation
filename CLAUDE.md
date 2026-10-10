# @nuxt4-layers/authorisation — notes for Claude

## What this is
Nuxt 4 foundation layer for authorisation (may this subject perform this permission on this resource, now?).
Governed by `nuxt4-layers/platform-architecture`; persistence follows ADR-0002. British spelling everywhere ("authorisation"), including code and the manifest.

## Commands
- `pnpm install`, then `pnpm dev:prepare` for Nuxt types. Never add a `prepare`/`postinstall` script: Git installs would then pull devDependencies into hosts
- `pnpm check` = `nuxt typecheck` + `vitest run`; run it after every code change
- `pnpm build:playground` proves the layer composes in a host
- Single test file: `pnpm vitest run tests/<name>.test.ts`
- Browser tests: `pnpm test:e2e` (builds the playground, then Playwright with axe in light and dark mode, port 3300). Needs `AUTHORISATION_TEST_DATABASE_URL`; locally set `PLAYWRIGHT_CHROMIUM_EXECUTABLE` if Playwright's own browser is not installed
- Theme Manager is pinned as `git+https://github.com/nuxt4-layers/theme-manager.git#<sha>` (listed in `onlyBuiltDependencies`); the lockfile must record the `codeload.github.com` tarball, never `git@github.com`

## Rules
- Contract (`contracts/`, `shared/`) imports only zod. No Nuxt, Vue, h3, server code, drivers or other `@nuxt4-layers/*` packages. Enforced by `tests/contracts.test.ts`.
- Public surface: package root, `./contracts`, `./capability`, `./presentation`, `./tailwind.css`, the `provide*` server functions (`provideAuthorisationClock` among them: optional, the system clock without it; `provideAuthorisationGovernance` and `provideAuthorisationSubjectResolver` required for changes and endpoints) and `migrateAuthorisationDatabase`, `authorise`, `requireAuthorisation`, `authorisationQualifies`, `countAuthorisationQualifying`, `listAuthorisationRoleAssignments`, `assignAuthorisationRole`, `unassignAuthorisationRole`, `defineAuthorisationRole`, `deleteAuthorisationRole`, `createAuthorisationGrant`, `revokeAuthorisationGrant`, `exportAuthorisationData`, `eraseAuthorisationPrincipal`, `getAuthorisationChanges`, `getAuthorisationAdministration`, `listAuthorisationAccessReview`, `authorisationDefaultRoles`, `runAuthorisationMaintenance`, `relayAuthorisationOutbox`, `exportAuthorisationRoles`, `importAuthorisationRoles`, `disposeAuthorisationGroup`, `disposeAuthorisationTenant`, `exportAuthorisationTenantData`, `provideAuthorisationLegalHolds`, the `/api/authorisation/*` endpoints, `useAuthorisation()`, the default pages, the `Authorisation*` components and `useAuthorisationText()`, `useAuthorisationAction()`, `useAuthorisationRoutes()`. `server/internal` and `server/database` are private.
- Storage: append-only migrations in `server/database/migrations.ts` (never edit a released one); parameterised SQL only; rows are validated before they reach a decision. Database suites need `AUTHORISATION_TEST_DATABASE_URL` (admin URL of a local, disposable PostgreSQL 16); they skip locally without it and fail in CI.
- Authorisation stores no domain data, groups or memberships. Groups, lineage, tenants, memberships (with status) and personal groups come from Identity through the `AuthorisationDirectory` port. Follow platform-architecture's Group Model Definition. Authentication's principal is passed in structurally; never import either package.
- Groups own information: a role or principal grant counts only while the principal is an active member (docs/contracts.md §5, §6). Creator provenance never grants access. The hierarchy confers no privilege unless an assignment is scoped `group-and-descendants`. Tenant isolation is a separate check. Keep the departure, no-implicit-inheritance and tenant-isolation tests.
- Deny by default. Unknown permission, principal or group is refused. No superuser or bypass.
- Wildcards never cover `high` or `critical` permissions.
- Enforcement is server-side only. Any client API is a user-experience hint.
- People change access only through pending changes (`server/internal/changes.ts`), following iam-integration's access-administration and approvals processes: no self-grant outside one's personal group; `owner` is never assigned, removed or a default role (owners follow Identity's events); approvals bound to the change's digest; every rule re-checked when applying, in the same transaction as the decision. Keep `tests/administration.test.ts` proving the processes' acceptance tests.
- Every change writes its events to the outbox in the same transaction; only `authorisation.denied` goes to the best-effort sink. Events carry identifiers, codes and times only, with strict schemas.
- Endpoints (`server/api/authorisation/`) take the subject only from `requireSubject` (the host's resolver); parse bodies with strict schemas through `readJson`; call the server functions, never SQL; and are wrapped in `authorisationHandler`. `tests/http.test.ts` mounts every file, so a new endpoint is tested by being added. Role documents, maintenance, the relay, erasure, disposal and the data and tenant exports are never endpoints.
- Presentation (`presentation/`, `modules/presentation.ts`) imports only the contract and reaches the server only through `useAuthorisation()`; never `$fetch` or `/api/`. It decides nothing. Text comes from `presentation/messages.ts` via `useAuthorisationText()`. Style only through the SemanticPresentationTheme vocabulary (`authorisationClasses`), never raw colours or Tailwind default sizes; any cross-role pairing goes in `DELIBERATE_PAIRINGS` (`presentation/pairings.ts`, never auto-imported) and `docs/contracts.md` §17. Never weaken an axe or contrast assertion to get green. Never show a person's name: that is the host's `AuthorisationPersonName`.
- HTTP errors stay coarse (`forbidden`); detailed reasons stay on the server and in events.
- Required ports fail closed. No implicit in-memory or file fallback stores.
- No names, email addresses, resource attributes or other personal data in events or logs.
- Defaults are secure; loosening policy requires a documented risk treatment.
- Keep `docs/contracts.md`, `docs/threat-model.md` (control register) and `docs/roadmap.md` in step with code.
- Package manager: pnpm. Commit `pnpm-lock.yaml`.

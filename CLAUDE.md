# @nuxt4-layers/authorisation — notes for Claude

## What this is
Nuxt 4 foundation layer for authorisation (may this subject perform this permission on this resource, now?).
Governed by `nuxt4-layers/platform-architecture`; persistence follows ADR-0002. British spelling everywhere ("authorisation"), including code and the manifest.

## Commands
- `pnpm install`, then `pnpm dev:prepare` for Nuxt types. Never add a `prepare`/`postinstall` script: Git installs would then pull devDependencies into hosts
- `pnpm check` = `nuxt typecheck` + `vitest run`; run it after every code change
- `pnpm build:playground` proves the layer composes in a host
- Single test file: `pnpm vitest run tests/<name>.test.ts`

## Rules
- Contract (`contracts/`, `shared/`) imports only zod. No Nuxt, Vue, h3, server code, drivers or other `@nuxt4-layers/*` packages. Enforced by `tests/contracts.test.ts`.
- Public surface: package root, `./contracts`, `./capability`, the `provide*` server functions. `server/internal` is private.
- Authorisation stores no domain data, groups or memberships. Groups, lineage, memberships and personal groups come from Identity through the `AuthorisationDirectory` port. Authentication's principal is passed in structurally; never import either package.
- Groups own information: a role, resource ownership or principal grant counts only while the principal is a current member (see docs/contracts.md §6). Keep the "leaving a group ends access" and tenant-isolation tests.
- Deny by default. Unknown permission, principal or group is refused. No superuser or bypass.
- Wildcards never cover `high` or `critical` permissions.
- Enforcement is server-side only. Any client API is a user-experience hint.
- HTTP errors stay coarse (`forbidden`); detailed reasons stay on the server and in events.
- Required ports fail closed. No implicit in-memory or file fallback stores.
- No names, email addresses, resource attributes or other personal data in events or logs.
- Defaults are secure; loosening policy requires a documented risk treatment.
- Keep `docs/contracts.md`, `docs/threat-model.md` (control register) and `docs/roadmap.md` in step with code.
- Package manager: pnpm. Commit `pnpm-lock.yaml`.

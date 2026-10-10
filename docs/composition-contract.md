# Authorisation Composition Contract

## 1. Purpose

This document defines how a host Nuxt application composes the authorisation capability. The host is the composition root (Composition and Dependency Model §1). Authorisation stays a bounded foundation capability.

## 2. Package composition

Install through the package manager and compose the package root with Nuxt `extends`, following the Layer Consumption Workflow:

- during early development, use a Git-backed dependency **pinned to a tag or commit SHA**. The package runs no install-time scripts, so only its runtime dependencies are installed;
- commit the lockfile and install with `--frozen-lockfile` in CI;
- never follow a mutable default branch in production.

Compose authorisation as a **peer** of other capabilities. It does not extend, and is not extended by, Authentication, Identity, UI or any domain capability.

## 3. Dependency graph

```text
Authentication ── AuthenticatedPrincipal ──┐
                                           ▼
Identity ── groups, lineage, memberships,
            owners, approvals, holds ─────► host adapters ──► Authorisation
                                           ▲                      ▲
Domain capabilities ── permissions ────────┘                      │
Domain capabilities ── "may this subject do this to this resource?"┘
                                                                  │
                         outbox events (relay) ──► host ──► Identity's handler, notifications, audit
                         denials (optional sink) ──► Audit / logging
```

Authorisation has **no package dependency** on Authentication, Identity, any domain capability, any database vendor SDK or any UI. The manifest declares Authentication and Identity as required **capabilities**: the host connects their contracts to this one.

Domain capabilities depend on Authorisation's contract, never the reverse.

## 4. Host responsibilities

The host application:

- selects a compatible version and pins it;
- supplies a PostgreSQL pool through `provideAuthorisationDatabase` (required) and calls `migrateAuthorisationDatabase()` once from its Nitro plugin;
- supplies a directory through `provideAuthorisationDirectory` (required), adapting Identity's contract:
  - `resolveActor(principalId, options)` returns the principal's own `status` (`active`, `paused` or `suspended`, from the identity's state), their personal group (or `null` for identities without one) and direct memberships, each with its group (lineage and tenant) and `status` (`active`, `paused`, `suspended` or `ended`), or `null` for an unknown principal;
  - `describeGroup(groupId, options)` returns the group's lineage (root first, one parent per group) and its tenant, or `null`;
  - both honour `options.consistency`: `strong` reads the source of truth with no cache; `bounded` may use a cache no older than `AUTHORISATION_MAX_STALENESS_SECONDS` (30 s). A failure must reject, never return stale or partial data (docs/contracts.md §10);
  - the hierarchy it describes must not imply membership: a member of a parent group is not listed as a member of its children unless Identity's own versioned policy says so;
- supplies Identity's governance facts through `provideAuthorisationGovernance` (required for every change request and decision; without it they fail closed), from iam-integration's `authorisationGovernanceFromIdentity`: for a group and a requester, the group's approval requirement and reference rule, the safety periods in force, its parent and root groups, whose personal group it is, the requester's recovery hold and the identities they control; whether a principal owns a group; and how many do. Read from Identity's own record at `strong` consistency; a failure rejects;
- supplies the signed-in subject for the layer's endpoints through `provideAuthorisationSubjectResolver({ resolve(event) })` (required for the endpoints), adapting Authentication's `getAuthenticatedPrincipal(event)`; null when nobody is signed in;
- sets `NUXT_AUTHORISATION_BASE_URL` to its public origin: state-changing `/api/authorisation/*` requests from anywhere else are refused, and without it all are;
- relays the outbox: calls `relayAuthorisationOutbox({ publish, limit })` on a schedule or after requests, publishing each event to its consumers (iam-integration's [architecture §4](https://github.com/nuxt4-layers/iam-integration/blob/35e86ab288fed79848b513a98cfbd98304a3cb26/docs/architecture.md#4-events)), and schedules `runAuthorisationMaintenance()` (every few minutes): neither is an endpoint;
- in its Identity event handler, asks `authorisationDefaultRoles(groupId)` for the roles a new member or guest receives (iam-integration's `defaultRoles`), and keeps `owner` in step with Identity's owners through `assignAuthorisationRole` and `unassignAuthorisationRole`: owners are never changed through Authorisation's own changes;
- replaces the `AuthorisationPersonName` component with one that names people through Profile, if it composes Profile; the default shows only an opaque placeholder;
- imports `@nuxt4-layers/authorisation/tailwind.css` after Theme Manager's `presentation.css` when it keeps the default pages, and moves or disables them in `nuxt.config.ts` (`authorisation: { pages: { paths, enabled }, presentation }`);
- supplies every domain capability's permission definitions through `provideAuthorisationPermissions` (once per capability is fine), each with the `effect` its capability declares (`view` or `change`; missing means `change`);
- optionally supplies an event sink, which receives only refused decisions (`authorisation.denied`), and policy overrides;
- optionally supplies the suite's clock through `provideAuthorisationClock` (docs/contracts.md §13): the same `{ now(): Date }` it gives every member, or none, so that each uses the system clock. Only its server code composes it; a clock that can be moved is for tests only;
- passes the authenticated principal from Authentication as the subject of each decision;
- integration-tests the composed system, including negative tests for tenant isolation and for leaving a group.

Example Nitro plugin:

```ts
import { ORDER_PERMISSIONS } from '@nuxt4-layers/orders/contracts'

export default defineNitroPlugin(() => {
  provideAuthorisationDatabase({ dialect: 'postgres', pool })
  provideAuthorisationDirectory(identityDirectoryAdapter)
  provideAuthorisationGovernance(authorisationGovernanceFromIdentity({ governance: getIdentityAccessGovernance() }))
  provideAuthorisationSubjectResolver({ resolve: event => getAuthenticatedPrincipal(event) })
  provideAuthorisationPermissions(ORDER_PERMISSIONS)
  provideAuthorisationClock(suiteClock) // optional: the same clock as every other member, or none
})

// A scheduled task of the host:
await runAuthorisationMaintenance()
await relayAuthorisationOutbox({ publish: event => hostEventBus.publish(event), limit: 100 })
```

## 5. Layer responsibilities

The authorisation layer:

- owns the permission catalogue rules, roles, role assignments, grants, the decision engine, pending changes and their approvals, a group's default roles and review interval, and its outbox;
- writes every change and its events in one transaction, and checks every rule again when a change applies;
- owns the `authorisation` database schema and its migrations;
- enforces decisions on the server only;
- publishes `AuthorisationDecision` and `AuthorisationEvent`;
- takes every time it keeps or judges from the host's clock, or the system clock when none is supplied;
- fails closed when a required port is absent, or the directory, database or clock fails.

## 6. Persistence (ADR-0002)

- The host creates and owns the pool: credentials, TLS, pooling mode and lifecycle.
- The layer reads and writes only its own schema, `authorisation` by default. Hosts may override the name; it must be a lower-case PostgreSQL identifier.
- The host SHOULD connect with a role limited to that schema.
- No other capability reads the `authorisation` schema. Group and principal IDs are stored as opaque values with no cross-schema foreign keys.

## 7. Failure boundaries

| Condition | Behaviour |
|---|---|
| Required port missing | `AuthorisationCompositionError` at first use. The operation is refused. There is no fallback store or directory. |
| Invalid port shape or schema name | `TypeError` from the `provide*` call at startup |
| Invalid policy, or a role naming a permission missing from the catalogue | Error from `provideAuthorisationPolicy` or `provideAuthorisationPermissions` at startup |
| Conflicting permission definitions | `TypeError` from `provideAuthorisationPermissions` |
| Directory does not know the principal or group | Refused (`unknown-subject`, `unknown-group`) |
| Directory, governance port or database failure | `unavailable` (503). Refused; nothing is recorded; internal details are not disclosed |
| Governance port or subject resolver missing | `AuthorisationCompositionError` when a change or an endpoint first needs it; the endpoint answers `unavailable` |
| Outbox publication fails | The relay stops; the event stays unpublished and is published on the next run (at least once). The change is unaffected |
| Port failure while maintenance applies a delayed change | That change stays `delayed`, for the next run |
| Clock fails or answers anything but a valid `Date` | `unavailable` (503). Refused before anything is read; never another time |
| Denial sink failure | Reported via `console.error`. The decision is unchanged. |

## 8. Composed-system verification

A consuming application must test its own combination of the pinned authorisation version, its directory adapter over Identity, its database, the permissions its domain capabilities declare, and the server routes that ask for decisions. The layer's own tests establish its contract; they cannot establish the correctness of a host's adapters.

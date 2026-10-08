# @nuxt4-layers/authorisation

A Nuxt 4 foundation layer that decides whether a signed-in principal may perform an action on a resource. It is governed by [`nuxt4-layers/platform-architecture`](https://github.com/nuxt4-layers/platform-architecture) (Identity and Authorization Architecture, ADR-0001, ADR-0002).

**Status:** phase 1 of 5, the foundation. The contract, composition ports and decision engine are in place; storage, server functions and administration follow (see [docs/roadmap.md](docs/roadmap.md)).

## What it does

```text
subject + permission + resource + group context + roles + grants -> decision
```

- **Groups own information.** Every resource belongs to one group: an organisation, company, club, committee, event, department and so on. Groups nest; the root of a group's lineage is its tenant, the isolation boundary.
- **Every identity has a personal group**, a unary group like a Unix user's own group, for the things a user keeps to themselves.
- **Roles are held in groups** and reach that group's descendants, never its ancestors, siblings or other tenants, and only while the holder is a member.
- **Leaving a group ends access to everything in it**, including what the leaver created. Joining one gives access up to the roles held there.
- **Grants** share one resource with another principal or group.
- **Risk levels** demand stronger authentication: `high` needs AAL2, `critical` a recent, phishing-resistant sign-in.
- Deny by default. No superuser. Enforcement is on the server only.

## What it does not do

Sign-in and sessions (Authentication), users, groups and memberships (Identity), and domain data (the domain capabilities). It reads groups and memberships through a port and stores none of them.

## Using it

```ts
// nuxt.config.ts of the host
export default defineNuxtConfig({
  extends: ['@nuxt4-layers/authorisation'],
})
```

```ts
// server/plugins/authorisation.ts of the host
export default defineNitroPlugin(() => {
  provideAuthorisationDatabase({ dialect: 'postgres', pool })
  provideAuthorisationDirectory(identityDirectoryAdapter)
  provideAuthorisationPermissions(ORDER_PERMISSIONS)
})
```

Domain capabilities declare their permissions, e.g. `{ name: 'orders:process_refund', description: 'Refund an order', risk: 'high' }`, and import types only from `@nuxt4-layers/authorisation/contracts`.

## Documentation

- [Contract](docs/contracts.md): permissions, roles, grants and how a decision is made
- [Composition contract](docs/composition-contract.md): what a host supplies
- [Threat model and control register](docs/threat-model.md)
- [Roadmap](docs/roadmap.md)
- [Legacy layer review](docs/legacy-review.md)

## Development

```sh
pnpm install
pnpm dev:prepare
pnpm check             # nuxt typecheck + vitest
pnpm build:playground  # proves the layer composes in a host
```

Requires Node 22 and pnpm 10.

## Licence

MIT

# @nuxt4-layers/authorisation

> **AI-Driven Development**
>
> This repository is part of [Nuxt 4 Layers](https://github.com/nuxt4-layers), an experimental, AI-driven software engineering initiative.
>
> AI performs the principal architecture, development, testing, security assessment and documentation activities under human direction. The project owner retains authority over requirements, governance, acceptance and releases.
>
> **Our objective is to demonstrate that disciplined, specification-led AI development can deliver secure, maintainable, standards-compliant, production-quality open-source software.**
>
> All contributions are subject to the same engineering standards, quality controls and repository policies, regardless of origin. See the [AI development methodology](https://github.com/nuxt4-layers/platform-architecture/blob/master/AI_DEVELOPMENT.md).


A Nuxt 4 foundation layer that decides whether a signed-in principal may perform an action on a resource. It is governed by [`nuxt4-layers/platform-architecture`](https://github.com/nuxt4-layers/platform-architecture) (Identity and Authorization Architecture, ADR-0001, ADR-0002).

**Status:** phase 1 of 5, the foundation. The contract, composition ports and decision engine are in place; storage, server functions and administration follow (see [docs/roadmap.md](docs/roadmap.md)).

## What it does

```text
subject + permission + resource + group context + roles + grants -> decision
```

- **Groups own information.** Every resource belongs to one group: an organisation, company, club, committee, event, department and so on. Each group has at most one parent. Tenants are a separate isolation boundary, checked on their own.
- **Every human identity has a personal group**, a unary group like a Unix user's own group, for the things a user keeps to themselves.
- **Roles are held in groups** and count only while the holder is an active member. The hierarchy confers nothing by default: a role reaches child groups only when its assignment explicitly says so.
- **Leaving a group ends the access it gave**, including to what the leaver created: creating something is provenance, not ownership. Joining one gives access up to the roles held there.
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

# Changelog

All notable changes to `@nuxt4-layers/authorisation`. The package follows [semantic versioning](https://semver.org/), and contract version 4 is frozen for 1.x.

## Unreleased

- The layer's own tests pass on Windows as well as on Linux and macOS: the paths they compare with import specifiers and routes are written with `/` on every platform (`tests/support/paths.ts`). On Windows the contract, architecture and endpoint tests used to fail, or check nothing.

## 1.0.0 (2026-10-11)

The first stable release: everything in contract version 4 ([docs/contracts.md](docs/contracts.md)).

- Deny-by-default decisions over roles, assignment scopes and grants, with tenant isolation, paused members and step-up requirements by risk.
- Access administration through pending changes with approvals, no self-grant, a transactional outbox, default roles, time-limited assignments, access reviews and role documents.
- Just-in-time elevation of eligible assignments and the visible-scopes query.
- Service identities refused as requesters and approvers; end of life and retention.
- The `/api/authorisation/*` endpoints and the accessible default pages.

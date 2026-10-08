# Contributing

Thank you for helping. This layer decides who may do what, so changes are
reviewed with security first. Read [CLAUDE.md](CLAUDE.md) for the project rules
and [docs/threat-model.md](docs/threat-model.md) before changing server code.

## Workflow

1. Fork the repository and branch from `master`.
2. Make a focused change with tests. Run `pnpm check`. A change to the decision
   engine needs a negative test showing what it must still refuse.
3. Open a pull request. A maintainer approves CI for first-time contributors;
   every pull request needs a code owner's review and a green Quality check
   before it is merged.

Commits to `master` must be signed. Sign yours with
[SSH or GPG](https://docs.github.com/authentication/managing-commit-signature-verification),
or a maintainer will squash-merge (GitHub signs the merge commit).

## Dependencies

Add a dependency only when necessary, and say why in the pull request. New
dependencies must be maintained, MIT-compatible and free of install scripts.
Always commit `pnpm-lock.yaml`.

## Security issues

Never in public issues or pull requests: see [SECURITY.md](SECURITY.md).

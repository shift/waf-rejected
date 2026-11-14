# Contributing to WAF-Rejected

Thanks for helping improve WAF-Rejected. This project is a security component
that inspects production traffic, so changes are reviewed with correctness and
fail-closed behaviour ahead of convenience.

## Before you start

- Read [`SECURITY.md`](SECURITY.md). **Do not** report vulnerabilities in
  public issues or pull requests.
- Read [`docs/developer-guide/`](docs/developer-guide/) and
  [`docs/operations/support-matrix.md`](docs/operations/support-matrix.md).
- For substantial changes, open an issue describing the problem, the threat
  model impact, and the proposed approach before writing code.

## Development environment

All builds and tests run through Nix:

```sh
nix develop
nix develop -c cargo build
nix develop -c cargo test --lib
nix develop -c cargo fmt -- --check
nix develop -c cargo clippy --lib -- --deny warnings
```

The full feature matrix is the authoritative local check:

```sh
./scripts/ci-feature-matrix.sh
./scripts/validate-configs.sh
```

Useful extras:

- `./scripts/run-crs-corpus.sh --engine both` for detection parity.
- `./scripts/bench-subms.sh` and `./scripts/verify-performance.sh` for
  performance work; include before/after numbers in the PR.
- `cargo deny check` and `cargo audit` for supply-chain changes.

## Scope and design rules

- **Security is not simplified.** Do not remove inspection, weaken fail-closed
  behaviour, or skip a rule to make a benchmark faster.
- **No silent gaps.** A rule or protocol that is not implemented must fail
  loudly (build error or startup error), never silently pass traffic.
- **Correctness before speed.** Performance changes must keep the CRS corpus
  parity and transform fixtures green.
- **Defaults matter.** New features should be opt-in unless explicitly agreed
  in an issue; document security trade-offs.

## Commit and pull-request conventions

- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
  `type(scope): summary`.
- Keep commits atomic. Do not mix refactoring with behaviour changes.
- Sign off your commits (`git commit -s`) to certify the
  [Developer Certificate of Origin 1.1](https://developercertificate.org/).
- PRs must include:
  - what changed and why,
  - security impact (including fail-open/fail-closed behaviour),
  - tests run and their results,
  - performance numbers for hot-path changes,
  - documentation updates.
- By submitting a contribution you agree it is licensed under
  MIT OR Apache-2.0.

## Review and merge

- A maintainer reviews every PR; security-sensitive changes need a second
  review.
- CI must be green. If CI is unavailable, include the exact local commands and
  output in the PR.
- Squash-merge is the default; the PR title becomes the commit message.

## Code of conduct

Participation is covered by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

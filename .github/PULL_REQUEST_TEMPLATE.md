## What changed

<!-- Describe the change and link the issue. -->

## Why

<!-- The problem, threat model impact, or performance motivation. -->

## Security impact

- [ ] No change to inspection coverage, fail-open/fail-closed behaviour, or defaults.
- [ ] Changes inspection coverage or defaults (explain below).
- [ ] Not a security-related change.

<!-- If coverage or defaults changed, state exactly what is weakened or added. -->

## Tests

<!-- Commands run and results. Include the feature matrix for non-trivial changes. -->

```sh
nix develop -c cargo fmt -- --check
nix develop -c cargo test --lib
./scripts/ci-feature-matrix.sh
```

## Performance (hot-path changes only)

<!-- Before/after p50/p99, hardware, command. -->

## Documentation

- [ ] Docs updated (user guide / operations / developer guide / CHANGELOG).
- [ ] Not needed.

## Checklist

- [ ] Commits follow Conventional Commits and are signed off (`git commit -s`).
- [ ] No secrets, credentials, customer data, or internal documents included.
- [ ] This PR is not a security vulnerability report (see SECURITY.md).

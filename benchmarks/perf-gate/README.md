# perf-gate

Engine-level performance regression gate. See
[`../../docs/design/perf-gate.md`](../../docs/design/perf-gate.md)
for the measurement model, baseline policy and limitations.

```sh
nix develop -c ./benchmarks/perf-gate/run.sh
nix develop -c ./benchmarks/perf-gate/compare.sh benchmarks/perf-gate/results/<file>.json
nix develop -c ./benchmarks/perf-gate/compare.sh --enforce benchmarks/perf-gate/results/<file>.json
nix develop -c ./benchmarks/perf-gate/selftest.sh
```

`run.sh` writes timestamped reports to `results/`. `baseline.json` is the
committed reference; update it only with a reviewed, intentional change and the
old/new numbers in the PR.

`compare.sh` checks two things: the absolute p50 of every row, and the same-run
`4k-sqli / 4k-allow` ratio per backend. The ratio cancels CPU-frequency, load
and guest-GC-mode shifts that scale every row together, so it still catches an
attack-path regression when a slow host makes all absolute rows look worse.

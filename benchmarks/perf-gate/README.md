# perf-gate

Engine-level performance regression gate. See
[`../../docs/suggestions_from_agents/perf-gate.md`](../../docs/suggestions_from_agents/perf-gate.md)
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

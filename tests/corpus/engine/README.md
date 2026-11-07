# Native engine counterexample corpus

`counterexamples.json` is the persisted regression corpus for disagreements
between Coraza and the native Rust engine. It starts empty and is appended by
the differential harness:

```bash
nix develop -c cargo run --bin crs_corpus --features wasm-reactor,native-engine -- \
  --engine rust --require-engine --generated 500 --fail-on-mismatch
```

Each entry is a minimized request plus the reference and native decisions (or
engine errors). Cases are deduplicated by request bytes, so re-running the same
seed does not grow the file. A non-empty corpus means the native engine has a
known decision difference and must not be shipped without an explicit review.

Format version 1 is defined by
`waf_ingress::engine::differential::CounterexampleFile`.

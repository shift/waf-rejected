# Parser hardening

Property and fuzz coverage for the security-critical parsers that run before
CRS body inspection. The goal is to prove that hostile input cannot panic,
over-read, recurse without bound, or bypass the configured limits.

## Covered parsers

| Module | What is exercised |
| --- | --- |
| `src/waf/protobuf.rs` | Dependency-free protobuf wire decoder: varints (including 10-byte and truncated forms), fixed32/fixed64, length-delimited fields, packed repeated values, unknown fields, enum membership, string validation, and the `max_depth` / `max_string_bytes` / `max_bytes_len` / `max_repeated` / `max_decoded_fields` limits. |
| `src/waf/grpc.rs` | `content-type` classification, `:path` parsing, 5-byte frame validation (flag, big-endian length, truncation, frame count, per-message size), `-bin` base64 metadata, and `grpc-encoding` handling. |
| `src/waf/graphql.rs` | JSON body/query extraction, query tokenisation and parsing, depth/alias/field counters, normalisation and operation hashing, and the configured body/query/variable/depth/alias/field limits. |
| `src/waf/grpc_allowlist.rs` | Allowlist JSON parsing/validation, binary and JSON `FileDescriptorSet` parsing, descriptor-to-allowlist generation, and TOML overrides. |
| `src/waf/admission.rs` | Request classification into cheap/heavy inspection from the post-precheck body. |

## Property tests

`proptest` cases live in a `proptests` module next to each parser's unit tests
and run as part of the normal library test suite:

```bash
nix develop -c cargo test --lib --features wasm-reactor
```

Properties include:

- arbitrary bytes/strings never panic (invalid UTF-8, NUL/control bytes,
  huge varints, truncated frames, deeply nested JSON);
- generated valid protobuf messages decode to the expected fields;
- generated valid gRPC frame sequences validate with the expected frame and
  byte counts;
- every 5-byte gRPC prefix plus payload either validates with the declared
  length or returns a typed `FrameError`;
- GraphQL depth/alias/field counters are monotonic and bounded;
- allowlist/descriptor input either validates or returns a typed error.

## Fuzz targets

`cargo-fuzz` targets live in the isolated `fuzz/` workspace and are **not**
part of the root build:

| Target | Input |
| --- | --- |
| `protobuf` | Arbitrary protobuf wire bytes against a fixed descriptor registry. |
| `grpc_frames` | Arbitrary gRPC frame bytes, also fed to the method-path parser. |
| `graphql_body` | Arbitrary GraphQL JSON request bodies. |
| `allowlist_json` | Arbitrary allowlist and descriptor bytes. |

Seed corpora are under `fuzz/corpus/<target>/`. See `fuzz/README.md` for the
full command reference.

Short local smoke run (30 seconds per target by default):

```bash
scripts/fuzz-smoke.sh
scripts/fuzz-smoke.sh 60   # override seconds per target
```

The script skips cleanly when nightly or `cargo-fuzz` is unavailable. Never
run unbounded fuzzing on shared or CI runners.

## Limits and invariants

- The protobuf decoder enforces the configured depth, string/bytes length,
  repeated-count and total-field limits before materialising values.
- The gRPC frame validator rejects lengths above `i32::MAX`, truncated
  messages, invalid compressed flags, oversized messages and excess frames.
- The GraphQL parser has a hard recursion cap (`MAX_PARSE_DEPTH = 512`) in
  addition to the configurable `max_depth`, so a hostile document cannot
  exhaust the stack before policy is applied.
- Binary descriptor parsing caps nested message depth at
  `MAX_MESSAGE_FIELD_DEPTH` (16), matching the allowlist reachability limit.
- Parser fixes must not change security policy or weaken limits; add a
  regression test for every finding.

## Findings fixed during hardening

- GraphQL selection-set parsing recursed without a hard cap; a deeply nested
  query could overflow the stack. Added `MAX_PARSE_DEPTH` and a regression
  property test.
- Binary `FileDescriptorSet` parsing recursed through nested message types
  without a depth cap. Added the descriptor depth limit and a regression
  property test.
- gRPC frame payload iteration and decoded-byte accounting now use checked /
  saturating arithmetic so malformed lengths cannot wrap.

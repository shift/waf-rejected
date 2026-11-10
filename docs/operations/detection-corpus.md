# CRS detection corpus

The CRS detection corpus is a pinned, licensed set of OWASP Core Rule Set
request regression cases and a harness that runs them through the Coraza
backends. It exists to catch **false negatives** after detection changes
(prefilter, rule pruning, tuning) and to prove **decision parity** between the
WASI reactor and the native sidecar.

The corpus is a test fixture. It does not change detection rules, defaults,
paranoia level, or engine behaviour.

## Source and provenance

| Item | Value |
| --- | --- |
| Project | OWASP Core Rule Set (CRS) |
| Version | 4.14.0 |
| Commit | `b5b788b5bc50e68836e17995b191f72e848fed75` |
| Upstream path | `tests/regression/tests/REQUEST-*` |
| Source archive SHA-256 | `c970605a62ae2dc9213d5de775fc5fbbed9423bf0435ce5456d2ffc769702123` |
| Licence | Apache License 2.0 (`tests/corpus/crs/LICENSE`) |

The generated files are:

- `tests/corpus/crs/corpus.json` — the full decision corpus.
- `tests/corpus/crs/smoke.json` — 16 representative cases used by unit tests.
- `tests/corpus/crs/PROVENANCE.md` — conversion rules and exclusion counts.
- `tests/corpus/crs/SOURCE_MANIFEST.txt` — SHA-256 of every upstream YAML that
  contributed.

No payload was authored for this corpus. Each case records its upstream file
and test ID in `source.file` / `source.test_id`. The converter reproduces the
upstream client's request defaults: the `application/x-www-form-urlencoded`
Content-Type and `Content-Length` for bodies, ftw's form re-encoding, and the
go-ftw `{{ "x" | repeat N }}` template.

## Format

`corpus.json` is versioned JSON:

```json
{
  "format_version": 1,
  "source": {
    "project": "OWASP Core Rule Set",
    "version": "4.14.0",
    "commit": "b5b788b5bc50e68836e17995b191f72e848fed75",
    "url": "https://codeload.github.com/coreruleset/coreruleset/tar.gz/b5b788b5bc50e68836e17995b191f72e848fed75",
    "sha256": "c970605a62ae2dc9213d5de775fc5fbbed9423bf0435ce5456d2ffc769702123",
    "license": "Apache-2.0",
    "upstream_path": "tests/regression/tests/REQUEST-*",
    "exclusions": { "rule above paranoia level 1": 1723 },
    "source_manifest_sha256": "3d316c962f8aaba8f71ce1a34b8782beb7182a8657902796e19028d12f987494"
  },
  "cases": [
    {
      "id": "crs-942100-1",
      "description": "Simple SQL Injection",
      "request": {
        "method": "POST",
        "uri": "/post",
        "http_version": "HTTP/1.1",
        "headers": {
          "Host": "localhost",
          "Content-Type": "application/x-www-form-urlencoded",
          "Content-Length": "15"
        },
        "body": "var=1234 OR 1=1"
      },
      "expected": "block",
      "expected_rule_ids": [942100],
      "tags": ["crs", "upstream", "sqli", "positive"],
      "source": {
        "file": "REQUEST-942-APPLICATION-ATTACK-SQLI/942100.yaml",
        "test_id": 1,
        "rule_id": 942100
      }
    }
  ]
}
```

Fields:

- `format_version` — currently `1`. The loader rejects unknown versions.
- `source` — provenance; `sha256` and `source_manifest_sha256` must be
  64-character hex digests.
- `id` — stable and unique.
- `request` — method, raw URI, HTTP version, headers, optional UTF-8 body.
  The harness serialises this into the same JSON envelope as
  `waf::coraza_payload::build_payload`. Raw URIs are preserved because upstream
  cases include spaces, backslashes and non-ASCII that `http::Uri` rejects.
- `expected` — `block` or `allow`.
- `expected_rule_ids` — upstream rule IDs the case exercises.
- `tags` — category (`sqli`, `xss`, `lfi`, `rfi`, `rce`, `php`, `java`,
  `protocol`, `protocol-attack`, `multipart`, `method`, `scanner`,
  `session-fixation`, `generic`, `anomaly`), direction (`positive`/`negative`),
  and `detection-only` where applicable.
- `source` — upstream file and test ID.

### Decision projection

Upstream CRS regression tests assert **logged rule IDs**, not HTTP decisions.
The corpus projects each case onto the block/allow decision exposed by both
engines, using the vendored PL1 bundle:

- `expect_ids` for an active PL1 critical rule that adds the critical inbound
  anomaly score (or a disruptive `deny`/`drop` rule) → `block`.
- `expect_ids` for an active PL1 warning/notice rule → `allow`, tagged
  `detection-only`, because the default inbound anomaly threshold is 5.
- `no_expect_ids` for an active PL1 rule → `allow`.

The projection is deliberately conservative. A `negative` case means "the
target rule must not fire", not "no other rule may block". If a different CRS
rule blocks the request, the harness reports a false positive even though the
block can be legitimate. The decision ABI does not expose matched rule IDs, so
this distinction cannot be recovered without changing the engines.

## Exclusions

The corpus contains 2,112 cases: 1,700 `block` and 412 `allow`. The remaining
upstream request cases are excluded and counted in `source.exclusions`:

| Reason | Count |
| --- | ---: |
| Rule above paranoia level 1 | 1,723 |
| No log expectation (status-only server tests) | 21 |
| Autocomplete-header cases | 12 |
| Encoded/raw request cases | 10 |
| `requires upstream regression tuning` | 8 |
| `match_regex` / `no_match_regex` | 7 |
| Multi-stage cases | 2 |
| `expect_error` | 1 |
| Negative with server-level status | 1 |
| Unknown rule ID | 1 |

The large PL2–PL4 exclusion is intentional: the vendored reactor runs at the
CRS default PL1 and this corpus must not change detection defaults. The
`requires upstream regression tuning` cases depend on the upstream test-only
`SecAction` (rule `900005`) that sets `tx.arg_name_length`, `tx.arg_length`,
`tx.max_num_args`, `tx.total_arg_length`, `tx.max_file_size` and
`tx.combined_file_sizes`; those variables are unset in the shipped bundle.

## Harness

Build and run:

```bash
# Default: wasm reactor, full corpus
cargo run --bin crs_corpus -- --engine wasm

# Both engines with an already-running sidecar
cargo run --bin crs_corpus --features wasm-reactor,coraza-native -- \
  --engine both --native-socket /run/waf/coraza.sock

# Tag filter, machine-readable report
cargo run --bin crs_corpus -- --filter sqli --json target/crs-sqli.json

# 16-case smoke corpus
cargo run --bin crs_corpus -- --corpus tests/corpus/crs/smoke.json
```

Or use the wrapper, which builds the native sidecar and starts it on a
temporary socket when needed:

```bash
./scripts/run-crs-corpus.sh --engine both --json target/crs-corpus.json
./scripts/run-crs-corpus.sh --filter xss --verbose
```

Options:

| Flag | Meaning |
| --- | --- |
| `--corpus PATH` | Corpus file (default `tests/corpus/crs/corpus.json`). |
| `--engine wasm\|native\|both` | Engines to run (default `wasm`). |
| `--filter TAG` | Repeatable/comma-separated tag filter. |
| `--limit N` | Run only the first N filtered cases. |
| `--json PATH` | Write the full report (per-case results, per-tag summary, parity). |
| `--module PATH` | Override the embedded reactor module. |
| `--native-socket PATH` | Sidecar socket (default `/run/waf/coraza.sock`). |
| `--native-timeout-ms N` | Native per-request budget (default 5000). |
| `--verbose` | Print every case, not only failures. |
| `--fail-on-mismatch` | Exit 3 if any case fails or errors. |

Exit codes: `0` completed, `1` fatal error, `2` invalid invocation/corpus, `3`
mismatch with `--fail-on-mismatch`.

The report contains `engines.<name>.by_tag` and a `parity` block when both
engines ran:

```json
{
  "engines": {
    "wasm": {
      "total": 2112,
      "passed": 2016,
      "false_negatives": 5,
      "false_positives": 91,
      "errors": 0,
      "detection_rate": 0.997055
    }
  },
  "parity": { "compared": 2112, "agree": 2112, "disagree": 0 }
}
```

## Baseline (2026-11-02)

Recorded on `test/crs-corpus` based on `main` at `cf9ba16`, with the embedded
`wasm/coraza_reactor/coraza_reactor.wasm` and the native sidecar built from the
same commit. No detection rules or defaults were changed.

| Engine | Passed | Detection (positives) | False negatives | False positives | Errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| wasm | 2,016 / 2,112 | 1,695 / 1,700 (99.7%) | 5 | 91 | 0 |
| native | 2,016 / 2,112 | 1,695 / 1,700 (99.7%) | 5 | 91 | 0 |
| parity | — | — | — | — | 2,112 / 2,112 agree |

### Per-tag detection

| Tag | Cases | Positives | Detected | Detection | FN | FP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `sqli` | 262 | 219 | 219 | 100.0% | 0 | 7 |
| `xss` | 147 | 132 | 132 | 100.0% | 0 | 10 |
| `rce` | 418 | 307 | 307 | 100.0% | 0 | 20 |
| `php` | 215 | 180 | 180 | 100.0% | 0 | 2 |
| `java` | 623 | 597 | 594 | 99.5% | 3 | 24 |
| `lfi` | 33 | 26 | 26 | 100.0% | 0 | 0 |
| `rfi` | 12 | 10 | 10 | 100.0% | 0 | 0 |
| `protocol` | 219 | 85 | 85 | 100.0% | 0 | 22 |
| `protocol-attack` | 59 | 42 | 40 | 95.2% | 2 | 3 |
| `multipart` | 8 | 4 | 4 | 100.0% | 0 | 0 |
| `method` | 8 | 4 | 4 | 100.0% | 0 | 0 |
| `scanner` | 7 | 5 | 5 | 100.0% | 0 | 0 |
| `session-fixation` | 7 | 6 | 6 | 100.0% | 0 | 0 |
| `generic` | 90 | 81 | 81 | 100.0% | 0 | 3 |
| `anomaly` | 4 | 2 | 2 | 100.0% | 0 | 0 |
| `detection-only` | 26 | 0 | — | n/a | 0 | 5 |

Tags overlap (`detection-only` is a subset of `negative`; every case also has
`crs` and `upstream`), so the table is not additive.

### Known false negatives

Both engines miss the same five cases:

| Case | Gap |
| --- | --- |
| `crs-921250-1`, `crs-921250-2` | Old RFC 2109 `$Version` cookie format. Coraza's cookie parser does not expose `$Version` as `REQUEST_COOKIES:/\x22?\x24Version` in the same way as the ModSecurity regression harness. |
| `crs-944150-12`, `crs-944150-13` | Log4j named-entity evasion (`$&lbrace;`, `$&LBRACE;`). |
| `crs-944150-14` | Log4j numeric-entity evasion (`&#36;{`). |

These are engine/parser gaps against the upstream log-level suite, not corpus
construction errors. They should be treated as detection debt; fixing them is a
separate change that must not alter the corpus expectation.

### Known false positives

The 91 false positives are all `negative`/`detection-only` cases:

- 5 are `detection-only` positives for WARNING/NOTICE rules (`crs-920100-10`,
  `-14`, `crs-920310-1`, `-4`, `crs-920311-1`). The target rule alone does not
  reach the anomaly threshold, but another rule contributes enough score to
  block.
- 86 are rule-specific negatives. By category: `java` 24, `protocol` 22,
  `rce` 20, `xss` 10, `sqli` 7, `generic` 3, `protocol-attack` 3, `php` 2.
  Examples: `crs-944100-11/12`, `crs-941310-4..7`, `crs-932230-1`,
  `crs-920470-3..5`.

Because the upstream suite runs in `DetectionOnly` mode and the engines expose
only block/allow, a negative case that is blocked by a **different** rule is
indistinguishable from a real over-block. The baseline therefore reports the
upper bound of possible false positives; triage requires matched rule IDs,
which the current ABI does not return.

## Regeneration

```bash
./scripts/vendor-crs-corpus.sh
```

The script downloads the pinned commit archive, verifies its SHA-256, converts
the request YAML with `yq` + `python3` (re-executing through `nix shell` when
needed), and rewrites the corpus, smoke set, provenance and source manifest.
It refuses to run if the archive digest changes, so a pin update is explicit.

Review the diff and run the harness before committing. Do not edit
`corpus.json` by hand; update the converter or the pin instead.

## CI

The optional `crs-corpus` job in `.github/workflows/feature-matrix.yml` is
ignored by default. It runs only on a manual `workflow_dispatch` with
`run_crs_corpus` enabled, and is marked `continue-on-error` so it cannot gate
required checks. It runs `./scripts/run-crs-corpus.sh --engine both` and uploads
the JSON report. The local feature matrix does not run it; use the wrapper
directly.

## Change policy

- Do not change detection rules, paranoia level or engine defaults to improve
  the baseline.
- If a corpus case is wrong, fix the converter and regenerate; do not hand-edit
  the case.
- Record engine gaps here. Suggestions for rule or engine changes belong in
  `docs/design/`.

## Native engine differential

The same harness supports the native Rust engine replacement:

```bash
nix develop -c cargo run --bin crs_corpus --features wasm-reactor,native-engine -- \
  --engine rust --require-engine --generated 500 --fail-on-mismatch
```

`--generated` produces deterministic SQLi/XSS/LFI/RCE requests with encoding and
placement permutations, compares the Rust decision with Coraza, and persists
minimized counterexamples in `tests/corpus/engine/counterexamples.json`. The
accounting, determinism, resource-bound and fail-closed guarantees are described
in `docs/design/engine-guarantees.md`.

# OWASP Core Rule Set regression corpus provenance

- Project: OWASP Core Rule Set (CRS)
- Version: 4.14.0
- Commit: `b5b788b5bc50e68836e17995b191f72e848fed75`
- Source: https://codeload.github.com/coreruleset/coreruleset/tar.gz/b5b788b5bc50e68836e17995b191f72e848fed75
- Source archive SHA-256: `c970605a62ae2dc9213d5de775fc5fbbed9423bf0435ce5456d2ffc769702123`
- License: Apache License 2.0, see `LICENSE` in this directory.
- Upstream path: `tests/regression/tests/REQUEST-*`
- Converter: `scripts/convert-crs-corpus.py`
- Regenerate: `./scripts/vendor-crs-corpus.sh`

## What is included

Every case in `corpus.json` is a request-phase regression test copied from the
upstream YAML. No payloads were authored for this corpus. Each case records its
upstream file and test ID in the `source` object.

Request construction follows the upstream client: the converter adds the
`application/x-www-form-urlencoded` Content-Type and `Content-Length` defaults
that ftw applies to bodies, applies ftw's form re-encoding, and expands the
go-ftw `{{ "x" | repeat N }}` template. No other payload bytes are changed.

The upstream suite is a log-level suite. This corpus is a decision-level
projection for the default PL1 rule bundle:

- a case expecting a PL1 critical rule that contributes the critical inbound
  anomaly score (or a disruptive `deny`/`drop` rule) is `block`;
- a case expecting a PL1 warning/notice rule is `allow` and tagged
  `detection-only`, because the default inbound anomaly threshold is not met;
- a `no_expect_ids` case for a PL1 rule is `allow`.

## What is excluded

- autocomplete headers: 12
- encoded/raw request: 10
- expect_error: 1
- match_regex: 7
- multi-stage: 2
- negative with server-level status: 1
- no log expectation: 21
- requires upstream regression tuning: 8
- rule above paranoia level 1: 1723
- unknown rule id: 1

The largest exclusion is rule coverage above paranoia level 1: the vendored
reactor runs at the CRS default PL1 and this corpus does not change detection
defaults. Response-phase suites (`RESPONSE-*`) are not read at all. Cases that
only assert an HTTP status (without a CRS rule expectation) are excluded
because the status can come from the web server rather than CRS. Cases using
`encoded_request`, `raw_request`, `autocomplete_headers`, `match_regex`,
`no_match_regex`, `expect_error`, or multiple stages are excluded because they
cannot be represented by the request/decision envelope without changing the
test. Cases whose serialised payload exceeds the reactor's 60 KiB safety limit
are excluded and reported above.

## Integrity

`SOURCE_MANIFEST.txt` lists the SHA-256 of every upstream YAML that
contributed to the corpus. `corpus.json` records the source archive SHA-256
and the SHA-256 of the sorted `<file-sha>  <path>` manifest lines in
`source.source_manifest_sha256`.

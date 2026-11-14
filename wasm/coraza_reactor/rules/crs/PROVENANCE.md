# OWASP Core Rule Set provenance

- Project: OWASP Core Rule Set (CRS)
- Version: 4.14.0
- Commit: `b5b788b5bc50e68836e17995b191f72e848fed75` (tag `v4.14.0`)
- Source: https://codeload.github.com/coreruleset/coreruleset/tar.gz/refs/tags/v4.14.0
- License: Apache License 2.0, see `LICENSE` in this directory.

## Vendored content

`crs-setup.conf` is the upstream `crs-setup.conf.example` unmodified.
`crs.conf` is a generated flattening of the setup file followed by the
request-side rule files below. The individual files are kept alongside it for
auditability.

Included rule files:

- `REQUEST-901-INITIALIZATION.conf`
- `REQUEST-905-COMMON-EXCEPTIONS.conf`
- `REQUEST-911-METHOD-ENFORCEMENT.conf`
- `REQUEST-913-SCANNER-DETECTION.conf`
- `REQUEST-920-PROTOCOL-ENFORCEMENT.conf`
- `REQUEST-921-PROTOCOL-ATTACK.conf`
- `REQUEST-922-MULTIPART-ATTACK.conf`
- `REQUEST-930-APPLICATION-ATTACK-LFI.conf`
- `REQUEST-931-APPLICATION-ATTACK-RFI.conf`
- `REQUEST-932-APPLICATION-ATTACK-RCE.conf`
- `REQUEST-933-APPLICATION-ATTACK-PHP.conf`
- `REQUEST-934-APPLICATION-ATTACK-GENERIC.conf`
- `REQUEST-941-APPLICATION-ATTACK-XSS.conf`
- `REQUEST-942-APPLICATION-ATTACK-SQLI.conf`
- `REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf`
- `REQUEST-944-APPLICATION-ATTACK-JAVA.conf`
- `REQUEST-949-BLOCKING-EVALUATION.conf`

Included data files: all upstream `rules/*.data` files used by the selected
rules through `@pmFromFile`.

## Not included

- Response inspection rules (`RESPONSE-950` through `RESPONSE-980`); the
  reactor sets `SecResponseBodyAccess Off`.
- Example customisation files (`REQUEST-900-...`, `REQUEST-999-...`); these
  are deployment-specific and contain no upstream detection rules.
- CRS plugins and the regression test corpus.

## Transforming directives

The bundle is concatenated verbatim, except for two documented patches applied
by `scripts/vendor-coraza-crs.sh` to `REQUEST-901-INITIALIZATION.conf` before
it is copied and flattened:

1. **gRPC media types.** `tx.allowed_request_content_type` is extended with
   the `application/grpc*` types so rule 920420 does not reject the gRPC
   requests the reactor inspects itself. `crs-setup.conf` stays upstream-clean.
2. **Phase-1 early blocking.** Rule 901115 (the default for rule 900120) sets
   `tx.early_blocking=1` instead of upstream's `0`. Rule 901115 only applies
   its default when `tx.early_blocking` is unset, so the final value is
   deterministically 1 and an explicit `0` from a caller still wins. With
   early blocking on, a request whose phase-1 anomaly score already reaches
   the threshold is denied before its body is scanned. The block decision is
   identical; only phase-2 alerts for an already-blocked request are skipped,
   which is the documented CRS tradeoff for this mode. This matches the native
   sidecar default (`--early-blocking`).

`@pmFromFile` keeps its upstream filename and resolves through Coraza's
`WithRootFS`, which is an embedded copy of `rules/`; no runtime filesystem
access is required.

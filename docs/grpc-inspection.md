# gRPC Protocol-Aware Inspection

**Status:** enabled by default when Coraza is enabled (`wasm-reactor` feature)
**Module:** `src/waf/grpc.rs`
**Config:** `[waf.grpc]`

gRPC request bodies are length-prefixed protobuf frames. Feeding those bytes to
CRS body rules is both meaningless (regular expressions cannot parse protobuf)
and expensive (a byte-linear scan of multi-megabyte payloads). gRPC requests
are therefore inspected at the protocol level *before* the Coraza reactor runs,
and their bodies are withheld from CRS body rules.

**Header and URI rules still run for gRPC.** Only the protobuf body is hidden.

## What is inspected

| Check | Behaviour |
| --- | --- |
| `content-type` | `application/grpc`, `application/grpc+proto`, `application/grpc+json`, `application/grpc-web`, `application/grpc-web+*`, `application/grpc-web-text*` |
| `:path` | Must be `/package.Service/Method`; validated against `method_allowlist` |
| Frame prefix | 5 bytes per message: compressed flag (`0`/`1`) and 4-byte big-endian length |
| Frame limits | Per-message size (`max_message_bytes`) and frame count (`max_frames`) |
| Truncation / lengths | Truncated prefixes, truncated messages and lengths above `i32::MAX` are rejected |
| `grpc-encoding` | `identity` accepted; every other encoding is rejected |
| `-bin` metadata | Base64 syntax validated; never passed to regex/text scanners |
| `grpc-web-text` | Body base64-decoded before frame validation |
| Protobuf fields | Decoded against descriptor metadata from the artifact: per-field string/bytes/repeated/depth limits, unknown-field policy, enum values, string sanity checks |

An empty body is accepted as a zero-frame body: streaming requests whose
payload is not buffered by the host are not rejected by this check.

## Decisions

| Condition | Decision |
| --- | --- |
| Envelope valid, method allowed (or monitor mode) | allow; body withheld from CRS body rules |
| Method not in a non-empty allowlist, `unknown_method_action = block` | `403` |
| Malformed frame/wire data, bad base64 metadata, unsupported encoding, unknown field (when rejected), invalid enum or string | `400` |
| Message larger than `max_message_bytes`, too many frames, or a field limit exceeded | `413` |
| Request cannot be inspected and `fail_mode = closed` | `503` |
| Request cannot be inspected and `fail_mode = open` | allow (body still withheld) |

`fail_mode` only applies to inspection *failures* (for example a
`grpc-web-text` body that cannot be decoded). Deterministic protocol
violations above are always rejected.

Because the body is withheld from Coraza, the reactor's 64 KiB payload cap no
longer turns large gRPC messages into `503` responses. Transport-level body
limits (`server.max_body_size`) still apply.

## Configuration

```toml
[waf.grpc]
# Effective only when waf.enabled and waf.coraza.enabled are true.
enabled = true

# Fully-qualified methods that may be called. Empty = monitor only.
# Merged with methods from allowlist_file when both are set.
method_allowlist = [
  "/acme.billing.v1.Billing/Charge",
  "/acme.billing.v1.Billing/GetInvoice",
]

# Generated allowlist artifact (JSON) from `grpc-allowlist`. Optional.
allowlist_file = "/etc/waf/grpc/allowlist.json"

# Maximum decoded size of one message (default 4 MiB). Used for methods that
# have no per-method limit in the artifact and for config-only entries.
max_message_bytes = 4194304

# Maximum frames per request body (default 64).
max_frames = 64

# "allow" or "block". An explicit value here wins over the artifact's
# unknown_method_action. Unset falls back to the artifact's value, then to
# "block" when the effective allowlist is non-empty and "allow" when empty.
unknown_method_action = "block"

# Field-level policy (applies when the artifact carries message metadata).
max_string_bytes = 1048576      # one string value
max_bytes_len = 1048576         # one bytes value
max_repeated = 1024             # values for one repeated field
max_depth = 32                  # nested message depth (request = 0)
max_decoded_fields = 100000     # total wire fields per message tree
reject_unknown_fields = false   # true = reject field numbers absent from descriptor
validate_strings = true         # reject invalid UTF-8, NUL and control bytes

# Content scanning of decoded string/bytes fields: "off" or "strings".
# "strings" (default) sends decoded values to Coraza as a synthetic form body.
content_scan = "strings"
# Maximum decoded field bytes in one synthetic content-scan payload (64 KiB).
max_content_scan_bytes = 65536
```

Validation (`Config::validate`) rejects a zero `max_message_bytes`,
`max_frames`, `max_string_bytes`, `max_bytes_len`, `max_repeated`, `max_depth`,
`max_decoded_fields` or `max_content_scan_bytes`, a `content_scan` value other
than `off`/`strings`, an unknown `unknown_method_action`, allowlist entries
that are not `/package.Service/Method` paths, and an `allowlist_file` that is
empty or cannot be loaded and validated (the error names the file and the
reason).

`allowlist_file` is loaded once by `WafEngine::with_config` (through
`GrpcInspector::try_from_config`) and never re-read per request. `from_config`
remains a file-free constructor for callers and tests that supply the policy
inline.

### Precedence

| Setting | Order |
| --- | --- |
| Effective method allowlist | `method_allowlist` **union** artifact methods |
| `max_message_bytes` | artifact per-method value, else global `waf.grpc.max_message_bytes` |
| `unknown_method_action` | explicit `waf.grpc.unknown_method_action`, else artifact value, else `block` when the effective allowlist is non-empty |

If `waf.grpc.enabled` is true and the configured `allowlist_file` cannot be
read, parsed or validated, `WafProxyService::new` aborts with
`WAF engine initialisation failed`; the process does not start with a silently
empty allowlist.

### Field-level inspection

When the artifact contains message metadata for the method's input type,
`GrpcInspector` decodes each request frame with a minimal wire-format decoder
(`src/waf/protobuf.rs`) and applies this policy:

* `string` values are limited by `max_string_bytes`; with `validate_strings`
  enabled they must be valid UTF-8 and must not contain NUL, C0 control bytes
  (tab, LF and CR are allowed) or DEL.
* `bytes` values are limited by `max_bytes_len`.
* repeated fields (including packed scalars) are limited by `max_repeated`.
* nested `message` fields recurse up to `max_depth`; the request message is
  depth 0.
* `max_decoded_fields` caps the total number of wire fields in the tree.
* field numbers absent from the descriptor are skipped by default, or rejected
  with `400` when `reject_unknown_fields = true`.
* `enum` fields are checked against the `enum_values` recorded from the
  descriptor when present. Enums without recorded values are accepted.
* failures report the fully-qualified field path (for example
  `acme.billing.v1.Request.customer_name` or
  `acme.billing.v1.Request.items[2].sku`) in the decision reason.

The raw protobuf bytes are still never given to CRS. If the artifact has no
message metadata for the input type (for example a version 1 artifact or a
method added only to `method_allowlist`), inspection falls back cleanly to the
envelope checks above. Unknown nested message types are treated as opaque
length-delimited fields rather than decoded.

### Field-content scanning

Structural field checks do not detect SQLi/XSS text inside a valid string.
With `content_scan = "strings"` (the default when descriptor metadata is
present), the inspector collects decoded `string` values and UTF-8 `bytes`
values after structural validation and sends them to the configured Coraza
backend as a **synthetic** request:

* body: `application/x-www-form-urlencoded`, keys `f0`, `f1`, ... in field
  order, values percent-encoded;
* URI: `/__grpc__/package.Service/Method`;
* method: `POST`.

The synthetic payload is evaluated directly against the same backend (WASM
reactor or native sidecar) that inspects ordinary requests. It bypasses the
gRPC pre-check, so a content scan cannot recurse. The raw protobuf body is
never sent to CRS.

A backend block becomes a gRPC-aware rejection: `403` by default, or a
`grpc-status` response when `server.grpc_aware_rejections = true`. The reason
names the scanned field paths, for example:

```
gRPC content inspection blocked field(s) [acme.billing.v1.Request.customer_name]: ...
```

Cost and limits:

* one extra Coraza evaluation per gRPC request that has descriptor metadata
  and at least one scannable field. The evaluation cost scales with the
  decoded field bytes, like ordinary CRS body inspection;
* the scan runs under heavy-inspection admission control (`[waf.admission]`).
  The request is classified **before** the gRPC pre-check, from the original
  `application/grpc*` content type, body presence and descriptor metadata, so
  a content scan occupies one heavy permit for the whole evaluation. Saturated
  admission rejects with `503 + Retry-After` before the scan runs; it never
  allows the request uninspected. `content_scan = "off"` stays cheap and
  bypasses the heavy queue because it performs no Coraza evaluation;
* at most `max_content_scan_bytes` decoded field bytes are included (default
  64 KiB). Structural validation still covers the whole message; only
  collection is capped. Values are truncated deterministically at a UTF-8
  boundary once the budget is exhausted;
* binary `bytes` values that are not valid UTF-8 are not scanned as text;
* `content_scan = "off"` restores the previous structural-only behaviour and
  performs no extra evaluation.

`benches/grpc_content.rs` measures the full `GrpcInspector::inspect` path with
content scanning on and off. On the reference benchmark host the p50 was
approximately 39 ms / 165 ms / 705 ms for 1/4/16 KiB strings with scanning
enabled, versus 2.5 µs / 6.6 µs / 22 µs with `content_scan = "off"`. The extra
cost is the Coraza body evaluation, not protobuf decoding or payload
construction. Deployments that cannot budget it should lower
`max_content_scan_bytes` or set `content_scan = "off"`. With admission enabled
these costs are bounded: in the load-validation A/B a 4 KiB scan at
concurrency 64 kept p95 at ~0.40 s with excess requests rejected `503`,
instead of queueing to a 2.8 s p95 with admission bypassed. See
[performance-validation.md](operations/performance-validation.md#grpc-content-scan-admission-ab).

Metrics: `waf_grpc_content_scans_total` counts synthetic evaluations and
`waf_grpc_content_blocks_total` counts requests blocked by them. The existing
`waf_grpc_decisions_total` still records the overall gRPC pre-check outcome.

### Generating the allowlist

Do not hand-maintain `method_allowlist`. Generate it from the protobuf
`FileDescriptorSet` and commit the resulting artifact; see
[Generating the allowlist from a descriptor set](#generating-the-allowlist-from-a-descriptor-set).

## Limitations

* Field-level inspection checks type, size, structure, enum membership and
  basic string sanity. Content scanning (`content_scan = "strings"`) adds a
  synthetic Coraza evaluation of decoded string/UTF-8 bytes values; it is not a
  byte-for-byte scan of the raw protobuf and does not inspect non-UTF-8 binary
  `bytes` fields. Set `content_scan = "off"` to skip the extra evaluation.
* Metadata is emitted for messages reachable from request types to
  `MAX_MESSAGE_FIELD_DEPTH` (16) in the generator. Deeper messages are treated
  as opaque length-delimited fields at runtime. Methods without descriptor
  metadata keep envelope-only behaviour.
* `grpc-encoding` values other than `identity` are rejected rather than
  decompressed. Supporting compression requires decompression limits and is
  deliberately out of scope.
* gRPC-Web text bodies are decoded here for validation; the transport/decoding
  branch owns the request path for binary-safe frames.
* Frame validation applies when a body is available. Streaming request bodies
  are inspected header/URI/method-only, consistent with `fast_evaluate`.

## Tests

`src/waf/grpc.rs` covers content-type detection, method-path parsing, valid,
truncated, oversized, negative-length and wrong-compressed-flag frames,
allowlist allow/block/monitor behaviour, base64 `-bin` metadata and text
scanner exclusion, and `grpc-web-text` decoding. Field tests cover a valid
descriptor-backed message, oversized strings with the field path in the
reason, unknown fields allowed/rejected by config, nested depth limits,
malformed wire data (`400`), enum values, string control bytes, packed repeated
counts, and the missing-metadata fallback. Content-scan tests cover SQLi/XSS
blocking with the field path in the reason, benign values, non-UTF-8 `bytes`
exclusion, the byte cap and deterministic truncation, `content_scan = "off"`,
and single-increment metrics. `src/waf/mod.rs` verifies that a
gRPC protobuf body is not delivered to downstream rules while a non-gRPC body
still is, that a content-scanning request is classified heavy while
`content_scan = "off"` stays cheap, that saturated admission rejects before the
scan or rule chain runs, and that a content scan holds exactly one permit.
Artifact tests cover allow/block from a generated file, merging with
`method_allowlist`, per-method limits smaller than the global value,
unknown-method action precedence, an unreadable file, and deterministic
generation of field metadata. `src/config.rs` rejects a missing or invalid
`allowlist_file` and zero field limits, and `src/proxy/service.rs` verifies
that such a file aborts start-up.

## Generating the allowlist from a descriptor set

**Tool:** `grpc-allowlist` (`src/bin/grpc-allowlist.rs`)
**Library:** `src/waf/grpc_allowlist.rs`
**Wrapper:** `scripts/grpc-allowlist.sh`

Hand-writing `method_allowlist` drifts from the deployed services and fails
open in practice: a method added to the `.proto` but forgotten in the config is
blocked (or, in monitor mode, silently allowed). The generator derives the
list directly from the compiled descriptor so reviewers can see exactly which
methods a build exposes.

### Ingestion workflow

1. Compile the descriptor set from the exact protos used to build the service.
   `--include_imports` is required so every request/response type, including
   `google.protobuf.*`, is present in the set:

   ```bash
   protoc \
     --descriptor_set_out=grpc/descriptor.binpb \
     --include_imports \
     -I proto \
     proto/acme/billing/v1/billing.proto
   ```

   `protoc --descriptor_set_out=... --include_imports` writes the binary wire
   format. To produce the JSON form, convert the descriptor set with any
   protobuf implementation that supports the JSON mapping (`file`,
   `package`, `messageType`, `service`, `method`, `inputType`, `outputType`,
   `clientStreaming`, `serverStreaming`). Both camelCase and snake_case field
   names are accepted.

2. Generate the artifact:

   ```bash
   ./scripts/grpc-allowlist.sh \
     --descriptor grpc/descriptor.binpb \
     --max-message-bytes 4194304 \
     --overrides grpc/allowlist-overrides.toml \
     --output grpc/allowlist.json
   ```

   The format is detected from the extension (`.binpb`/`.pb` binary, `.json`
   JSON); use `--format binpb|json|auto` to override. Without `--output` the
   artifact is written to stdout. Alongside the method allowlist the generator
   emits `messages` field metadata for every type reachable from a request
   type (up to `MAX_MESSAGE_FIELD_DEPTH`), including nested messages and enum
   numeric values. No flags are needed: regenerating an existing descriptor
   upgrades the artifact to `ir_version` 2 deterministically.

3. Review the diff and commit `grpc/allowlist.json` next to the descriptor.

4. Reference the committed artifact from the WAF config:

   ```toml
   [waf.grpc]
   allowlist_file = "/etc/waf/grpc/allowlist.json"
   ```

   `allowlist_file` is loaded and validated once at start-up; the artifact's
   methods are merged with `method_allowlist` and its per-method limits and
   unknown-method action are applied as described in [Precedence](#precedence).

### Artifact shape

```json
{
  "ir_version": 2,
  "source": {"kind": "protobuf", "sha256": "438b9d3d..."},
  "methods": [
    {
      "path": "/acme.billing.v1.Billing/Charge",
      "client_streaming": false,
      "server_streaming": false,
      "input": "acme.billing.v1.Request",
      "output": "acme.billing.v1.Response",
      "max_message_bytes": 4194304
    }
  ],
  "messages": [
    {
      "message": "acme.billing.v1.Request",
      "fields": [
        {"name": "customer_name", "number": 1, "type": "string",
         "repeated": false, "required": false},
        {"name": "items", "number": 2, "type": "message", "repeated": true,
         "required": false, "message_type": "acme.billing.v1.Request.Item"},
        {"name": "state", "number": 3, "type": "enum", "repeated": false,
         "required": false, "enum_values": [0, 1, 2]}
      ]
    }
  ],
  "unknown_method_action": "block"
}
```

* `ir_version` — artifact schema version; the loader accepts `1` and `2`.
  Version 1 artifacts have no `messages` metadata and fall back to
  envelope-only inspection.
* `source.kind` — always `protobuf`.
* `source.sha256` — SHA-256 of the descriptor bytes exactly as ingested, so a
  reviewer can prove the artifact came from a specific compiled descriptor.
* `methods` — sorted by `path`. Streaming flags and fully-qualified types come
  straight from the descriptor; nested message types are resolved
  (`acme.billing.v1.Request.Item`).
* `messages` — sorted by message name; fields are sorted by number. Contains
  message types reachable from request (input) types up to
  `MAX_MESSAGE_FIELD_DEPTH`. `message_type` is present for `message` fields and
  `enum_values` for `enum` fields when the descriptor defines them.
* `unknown_method_action` — `allow` (monitor) or `block`; the generator
  defaults to `block`.

Output is canonical: methods are sorted, the JSON is pretty-printed with a
fixed field order, and a trailing newline is written. Running the generator
twice over the same bytes produces byte-identical output.

### Per-method overrides

`--max-message-bytes` sets the default limit; `--overrides` supplies a small
TOML file for per-method limits (for example upload methods) and defaults:

```toml
max_message_bytes = 4194304
unknown_method_action = "block"

[methods."/acme.billing.v1.Billing/Upload"]
max_message_bytes = 16777216
```

Precedence: command-line `--max-message-bytes` / `--unknown-method-action`
beat the override file's defaults; per-method entries beat both. An override
for a path that is not in the descriptor is an error, so a renamed method
cannot silently keep a stale limit. Unknown keys are rejected by the parser.

### Provenance and CI diffing

Commit the descriptor and the generated artifact together, then enforce in CI:

```bash
./scripts/grpc-allowlist.sh \
  --descriptor grpc/descriptor.binpb \
  --overrides grpc/allowlist-overrides.toml \
  --output /tmp/grpc-allowlist.json

git diff --no-index --exit-code grpc/allowlist.json /tmp/grpc-allowlist.json
```

This fails when a proto change adds, removes or re-types a method without the
committed artifact being regenerated, making every exposure change a reviewable
diff. Two further checks are cheap and worth running:

* `source.sha256` in the committed artifact must match the committed
  descriptor:
  `sha256sum grpc/descriptor.binpb` equals the artifact value.
* the artifact must load without errors; a unit test can call
  `waf::grpc_allowlist::load_allowlist("grpc/allowlist.json")`.

The generator exits non-zero with a specific message for: malformed wire data
or JSON, a descriptor without services, missing service/method/type names,
duplicate method paths (including collisions across files), input or output
types not present in the descriptor set (usually a missing
`--include_imports`), and overrides for unknown methods. It never emits a
partial artifact.

### Loader interface

`src/waf/grpc_allowlist.rs` exposes the contract the inspector will use:

```rust
pub fn load_allowlist(path: impl AsRef<Path>) -> Result<GrpcAllowlist, GrpcAllowlistError>;

impl GrpcAllowlist {
    pub fn allows(&self, path: &str) -> bool;
    pub fn max_message_bytes_for(&self, path: &str) -> Option<usize>;
    pub fn message_for(&self, message: &str) -> Option<&GrpcMessage>;
    pub fn validate(&self) -> Result<(), GrpcAllowlistError>;
}
```

`load_allowlist` reads and validates the whole document (IR version, source
kind/hash shape, method paths, types, non-zero limits, duplicate paths, known
action). The returned struct is immutable data only; `GrpcAllowlist` is
`Serialize`/`Deserialize` with `deny_unknown_fields`, so a typo in the artifact
fails loading instead of being ignored.

`GrpcInspector::try_from_config` is the runtime integration point: it calls
`load_allowlist` when `waf.grpc.allowlist_file` is set, merges the artifact
methods with `method_allowlist`, prefers the artifact's per-method
`max_message_bytes`, and resolves `unknown_method_action` in the order
documented above. `GrpcInspector::from_config` never performs I/O and ignores
`allowlist_file`.

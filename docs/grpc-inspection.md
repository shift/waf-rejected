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

An empty body is accepted as a zero-frame body: streaming requests whose
payload is not buffered by the host are not rejected by this check.

## Decisions

| Condition | Decision |
| --- | --- |
| Envelope valid, method allowed (or monitor mode) | allow; body withheld from CRS body rules |
| Method not in a non-empty allowlist, `unknown_method_action = block` | `403` |
| Malformed frame, bad base64 metadata, unsupported encoding | `400` |
| Message larger than `max_message_bytes` or too many frames | `413` |
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
method_allowlist = [
  "/acme.billing.v1.Billing/Charge",
  "/acme.billing.v1.Billing/GetInvoice",
]

# Maximum decoded size of one message (default 4 MiB).
max_message_bytes = 4194304

# Maximum frames per request body (default 64).
max_frames = 64

# "allow" or "block". Unset defaults to "block" when the allowlist is
# non-empty and "allow" when it is empty (monitor mode).
unknown_method_action = "block"
```

Validation (`Config::validate`) rejects a zero `max_message_bytes` or
`max_frames`, an unknown `unknown_method_action`, and allowlist entries that
are not `/package.Service/Method` paths.

### Generating the allowlist

Do not hand-maintain `method_allowlist`. Generate it from the protobuf
`FileDescriptorSet` and commit the resulting artifact; see
[Generating the allowlist from a descriptor set](#generating-the-allowlist-from-a-descriptor-set).

## Limitations

* **No protobuf field-level inspection.** Values are not decoded, so a
  malicious string inside a protobuf field is not matched by CRS rules.
  Field-level inspection requires the service descriptor (`FileDescriptorSet`)
  and is tracked separately. The frame cap and the method allowlist are the
  current controls.
* gRPC-Web text bodies are decoded here for validation; the transport/decoding
  branch owns the request path for binary-safe frames.
* `grpc-encoding` values other than `identity` are rejected rather than
  decompressed. Supporting compression requires decompression limits and is
  deliberately out of scope.
* Frame validation applies when a body is available. Streaming request bodies
  are inspected header/URI/method-only, consistent with `fast_evaluate`.

## Tests

`src/waf/grpc.rs` covers content-type detection, method-path parsing, valid,
truncated, oversized, negative-length and wrong-compressed-flag frames,
allowlist allow/block/monitor behaviour, base64 `-bin` metadata and text
scanner exclusion, and `grpc-web-text` decoding. `src/waf/mod.rs` verifies
that a gRPC protobuf body is not delivered to downstream rules while a
non-gRPC body still is.

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
   artifact is written to stdout.

3. Review the diff and commit `grpc/allowlist.json` next to the descriptor.

4. Reference the committed artifact from the WAF config:

   ```toml
   [waf.grpc]
   allowlist_file = "/etc/waf/grpc/allowlist.json"
   ```

   `allowlist_file` is the planned loader hook; the inspector integration is
   tracked separately. The loader interface is documented below.

### Artifact shape

```json
{
  "ir_version": 1,
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
  "unknown_method_action": "block"
}
```

* `ir_version` — artifact schema version; the loader accepts `1` only.
* `source.kind` — always `protobuf`.
* `source.sha256` — SHA-256 of the descriptor bytes exactly as ingested, so a
  reviewer can prove the artifact came from a specific compiled descriptor.
* `methods` — sorted by `path`. Streaming flags and fully-qualified types come
  straight from the descriptor; nested message types are resolved
  (`acme.billing.v1.Request.Item`).
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
    pub fn validate(&self) -> Result<(), GrpcAllowlistError>;
}
```

`load_allowlist` reads and validates the whole document (IR version, source
kind/hash shape, method paths, types, non-zero limits, duplicate paths, known
action). The returned struct is immutable data only; `GrpcAllowlist` is
`Serialize`/`Deserialize` with `deny_unknown_fields`, so a typo in the artifact
fails loading instead of being ignored. The inspector branch owns the decision
to call it from `waf.grpc.allowlist_file` and to prefer per-method
`max_message_bytes` over the global value; this module does not modify
`src/waf/grpc.rs`.

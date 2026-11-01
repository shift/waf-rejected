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

The allowlist can be generated from a protobuf `FileDescriptorSet`: walk the
services in the descriptor and emit `/package.Service/Method` for every method
in each service. That generator is being built on a separate branch; it is not
part of this inspection change.

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

# Security Audit — Request Path (November 2026)

- **Baseline:** `1678d4f` (`docs: refresh security model with control status matrix`)
- **Scope:** HTTP/1.1, HTTP/2, HTTP/3, gRPC/gRPC-Web, WebSocket, decompression, WAF inspection, auth, rate limiting, client-IP resolution, fail-closed behaviour.
- **Method:** source review of the request path plus targeted unit tests. No production behaviour was changed.
- **Test command:** `nix develop -c cargo test --lib 'proxy::'` (normal run) and `nix develop -c cargo test --lib 'proxy::' -- --include-ignored` (demonstrates the ignored findings).

## Summary

| Severity | Count |
| --- | --- |
| Critical | 0 |
| High | 3 |
| Medium | 8 |
| Low | 9 |

No Critical issue was found. The request path is generally fail-closed: framing, decompression, body-size, admission and WAF errors return 4xx/5xx, and `evaluate_shared` maps a panicking offloaded evaluation to `Block` when `fail_closed` is set. The main risks are inspection bypasses caused by protocol classification and by headers that the proxy forwards without normalising.

---

## High

### H1 — A unary gRPC RPC can be forced into the streaming path, bypassing body inspection

**Affected:** `src/proxy/grpc_body.rs:31`, `:135-176`; `src/proxy/service.rs:1337-1445`

**Reasoning / reproduction:** `probe_grpc_body` classifies a body as unary only when the first complete frame is followed by end-of-stream. If the first frame is complete but the stream is still open, it waits `STREAM_DETECTION_GRACE` (25 ms). On timeout it returns `GrpcBodyMode::Streaming`. A client can send one complete unary message and simply delay `END_STREAM` for more than 25 ms. The service then takes the streaming branch, which evaluates only headers/URI and forwards the body through `GrpcStreamGuard`; the gRPC field-content scan and Coraza body rules never run. The default `server.grpc_streaming_policy` is `transport-only`, so the request is allowed.

The ignored test `proxy::grpc_body::tests::unary_rpc_with_delayed_end_stream_is_not_forced_into_streaming` demonstrates the current result (`Streaming` instead of `Unary`).

**Impact:** Any gRPC method can be made to bypass gRPC field-content inspection and CRS body rules by holding the stream open for 25 ms. This defeats the frame-based gRPC inspection fix for unary RPCs.

**Recommended fix:** Do not use a timeout to decide that a single complete frame is streaming. Either (a) inspect every complete frame in streaming mode before forwarding it, or (b) treat an open stream with exactly one complete frame as unary after a bounded wait and inspect that frame, or (c) make `reject` the default streaming policy. A second complete frame should be the only signal that a body is genuinely streaming.

---

### H2 — Multiple `X-Forwarded-For` headers let the first (client-controlled) value win

**Affected:** `src/proxy/service.rs:2157` (`headers.get("x-forwarded-for")`)

**Reasoning / reproduction:** `resolve_client_ip_detailed` reads only the first `X-Forwarded-For` header. If a trusted proxy appends a new `X-Forwarded-For` header instead of comma-appending to the existing one, the request carries two headers. The first is the value supplied by the client; the second is the value added by the trusted proxy. The WAF trusts the first and returns the spoofed address.

The ignored test `proxy::service::tests::multiple_forwarded_for_headers_fall_back_to_peer` demonstrates the current result (`203.0.113.9` instead of the peer `10.0.0.5`).

**Impact:** Client-IP spoofing behind a trusted proxy that uses separate headers. This bypasses per-IP rate limits, geographic blocking and audit attribution.

**Recommended fix:** Use `headers.get_all("x-forwarded-for")` and either combine all values in wire order before walking the chain, or reject multiple `X-Forwarded-For` headers and fall back to the immediate peer. Apply the same rule to `X-Real-IP`.

---

### H3 — Client-controlled routing/override headers are forwarded to the upstream

**Affected:** `src/proxy/service.rs:2290-2365` (`build_upstream_request` header copy loop)

**Reasoning / reproduction:** The proxy strips `Host`, `Connection`, `Proxy-Connection`, `Upgrade`, `Transfer-Encoding`, `Keep-Alive`, `X-Forwarded-For`, `X-Real-IP` and `X-Forwarded-Proto`, but forwards other client headers unchanged. In particular it forwards `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Prefix`, `X-Forwarded-Port`, `X-Forwarded-Host` (when no `Host` header is present, as is common on HTTP/2), `X-HTTP-Method-Override`, `X-Method-Override` and the standard `Forwarded` header. Many upstream frameworks use these for routing or method override.

The ignored test `proxy::service::tests::client_routing_and_override_headers_are_not_forwarded` demonstrates that these headers reach the upstream request.

**Impact:** The WAF can inspect `/public` while the upstream routes the request to `/admin` (or changes the method) based on a client-supplied header. This is a path/method inspection bypass and can also spoof the upstream's view of the client address.

**Recommended fix:** Strip or overwrite all client-supplied forwarding/routing/override headers at the trust boundary. At minimum: `Forwarded`, `X-Forwarded-Host`, `X-Forwarded-Port`, `X-Forwarded-Prefix`, `X-Original-URL`, `X-Rewrite-URL`, `X-HTTP-Method-Override`, `X-Method-Override`. If an upstream needs a trusted value, set it from the WAF's own state.

---

## Medium

### M1 — Headers nominated by `Connection` are not stripped

**Affected:** `src/proxy/service.rs:2290-2320`

**Reasoning:** The proxy removes the `Connection` header itself but does not parse its tokens and remove the headers they name. A request with `Connection: X-Custom-Hop` and `X-Custom-Hop: secret` forwards `X-Custom-Hop` to the upstream. The ignored test `proxy::service::tests::connection_nominated_headers_are_stripped` demonstrates this.

**Impact:** Hop-by-hop header leakage and a request-smuggling primitive if an upstream honours `Connection`-nominated framing headers (for example `Connection: Content-Length`).

**Recommended fix:** Parse every `Connection` header value, collect the nominated field names, and skip those names in the copy loop (in addition to the fixed hop-by-hop list).

---

### M2 — `Content-Length` is not reconciled with the buffered body on HTTP/2 and HTTP/3

**Affected:** `src/proxy/service.rs:1490-1540`, `:2234-2365`; `src/proxy/http3.rs:479-500`; `src/proxy/buffer_pool.rs:302-351`

**Reasoning:** `read_incoming_body_bytes` ignores its `_size_hint` and reads until end-of-stream. HTTP/2 and HTTP/3 do not enforce that the DATA length matches `Content-Length` (hyper's h2 `Incoming` only subtracts the length; the h3 path reads all DATA frames). The original `Content-Length` header is then copied to the upstream request. For an HTTP/1.1 upstream, hyper truncates the body to the declared length; for an HTTP/2 upstream, the mismatched header and DATA can both be forwarded. The ignored test `proxy::service::tests::content_length_is_reconciled_with_buffered_body` shows a 10-byte body forwarded with `Content-Length: 5`.

**Impact:** WAF/upstream body differential. The WAF inspects bytes the upstream will not receive, or the upstream receives a body whose declared length is wrong. This is a request-smuggling primitive when the upstream or an intermediary trusts the header.

**Recommended fix:** After buffering (and after decompression), compare the actual body length with the declared `Content-Length` and reject a mismatch with `400`. For buffered bodies, rewrite `Content-Length` to the actual length before forwarding. Apply the same check in the HTTP/3 `read_body` path.

---

### M3 — `security.auth.rate_limit` is accepted but never enforced

**Affected:** `src/waf/auth.rs:31`, `:41`; `src/proxy/service.rs:801-812`

**Reasoning:** `AuthConfig` exposes `rate_limit: Option<RateLimitConfig>`, but `ApiKeyValidator` never reads it and no other request-path code uses it. A configured per-API-key rate limit is silently ignored.

**Impact:** Operators relying on per-key throttling get no protection. A stolen or over-used key is limited only by the global/per-IP WAF rate limiter, if enabled.

**Recommended fix:** Implement per-key token buckets in `ApiKeyValidator` (or the proxy) and enforce them after key validation, or reject the configuration at startup so the control cannot be silently absent.

---

### M4 — Streaming gRPC trailers are not validated

**Affected:** `src/proxy/grpc_body.rs:483-490`; `src/proxy/service.rs:1530` (buffered path only)

**Reasoning:** The buffered path calls `validate_request_trailers`, but `GrpcStreamGuard` forwards a trailer block unchanged. A streaming gRPC request can therefore carry `Content-Length`, `Transfer-Encoding`, `Connection`, `Upgrade`, `Trailer` or other connection metadata in its trailers.

**Impact:** Framing/connection metadata reaches the upstream in a trailer block. This is a lower-risk smuggling/desync primitive than a request header, but it violates the same invariant the buffered path enforces.

**Recommended fix:** Call `validate_request_trailers` on the trailer block inside `GrpcStreamGuard` before emitting `Frame::trailers`, and reject with a body error on failure.

---

### M5 — WebSocket upgrade requests are not body-checked; framing headers are forwarded

**Affected:** `src/proxy/service.rs:1662-1735`

**Reasoning:** `proxy_websocket` builds the upstream handshake from the client headers, skipping only `Host`, `Connection`, `Upgrade`, `Proxy-Connection`, `X-Forwarded-*` and `X-Real-IP`. It never reads `req.body()`. A client can send `Content-Length`/`Transfer-Encoding`/`Content-Encoding` on the upgrade request. The body is not inspected, and the declared framing is forwarded to the upstream. Depending on the upstream, the body bytes can be interpreted as WebSocket frames or cause the handshake to hang.

**Impact:** Uninspected request body on the upgrade path, potential upstream desync/DoS, and a bypass of the normal body-size/decompression controls.

**Recommended fix:** Reject WebSocket upgrades that declare a body (`Content-Length` other than 0, or `Transfer-Encoding`), or drain and inspect the body before tunnelling. Do not forward `Content-Length`, `Transfer-Encoding` or `Content-Encoding` on the handshake.

---

### M6 — HTTP/3 per-client admission map can exceed its cap

**Affected:** `src/proxy/h3_admission.rs:157-161`

**Reasoning:** When `clients.len() >= MAX_TRACKED_CLIENTS`, the code prunes only entries whose `Weak` has no live holders, then inserts the new client unconditionally. If all tracked clients are live, the map grows past `MAX_TRACKED_CLIENTS` without bound.

**Impact:** Memory growth when the per-client HTTP/3 limit is enabled and an attacker uses many live source addresses.

**Recommended fix:** If the map is at capacity after pruning and no entry can be evicted, reject the new client (or evict the least-recently-used live entry) instead of inserting.

---

### M7 — Brotli trailing garbage is accepted

**Affected:** `src/proxy/decompression.rs:88`

**Reasoning:** `brotli::Decompressor` stops at the end of the first brotli stream and ignores trailing bytes. The ignored test `proxy::decompression::tests::brotli_trailing_garbage_is_rejected` shows `Ok(b"payload")` for a body with trailing garbage.

**Impact:** The WAF silently accepts a malformed compressed body and forwards only the decoded prefix. This is a parser differential with upstreams that reject trailing data or decode concatenated streams.

**Recommended fix:** Use a decoder that reports trailing bytes, or check that the decoder consumed the entire input and reject leftovers as `Malformed`.

---

### M8 — gRPC gzip decoding ignores concatenated members and trailing bytes

**Affected:** `src/waf/grpc.rs:283-302` (`decompress_gzip`)

**Reasoning:** `decompress_gzip` uses `flate2::read::GzDecoder`, which decodes only the first gzip member. Concatenated members and trailing bytes are ignored. The HTTP body decompressor was hardened to `MultiGzDecoder`, but the gRPC per-message decoder was not.

**Impact:** The WAF inspects only the first gzip member of a compressed gRPC message. An upstream that decodes concatenated members (or a different gRPC implementation) could see content the WAF did not inspect.

**Recommended fix:** Use `MultiGzDecoder` and reject trailing bytes that are not another valid member, matching `decompress_request_body`.

---

## Low

### L1 — `Content-Length` accepts a leading `+`

**Affected:** `src/proxy/framing.rs:192` (`part.parse::<u64>()`)

**Reasoning:** Rust's `u64` parser accepts `+5`. RFC 9112 defines `Content-Length = 1*DIGIT`, and hyper's HTTP/1.1 parser rejects `+5`. The WAF accepts it on HTTP/2/HTTP/3. The ignored test `proxy::framing::tests::rejects_prefixed_content_length` demonstrates the current acceptance.

**Impact:** Parser differential between the WAF and an HTTP/1.1 upstream. Usually results in a 502, but can be a smuggling primitive if an intermediary accepts the prefixed value.

**Recommended fix:** Require every byte of the value to be an ASCII digit before parsing.

---

### L2 — HTTP/1.0 accepts `Transfer-Encoding: chunked`

**Affected:** `src/proxy/framing.rs:105-130`, `:212-235`

**Reasoning:** `validate_request_framing_for_version` applies the same transfer-coding rules to HTTP/1.0 and HTTP/1.1. HTTP/1.0 does not define chunked transfer coding. The ignored test `proxy::framing::tests::http10_rejects_transfer_encoding` demonstrates the current acceptance.

**Impact:** Framing differential with an HTTP/1.0 upstream or intermediary.

**Recommended fix:** Reject `Transfer-Encoding` for `FramingVersion::Http10`.

---

### L3 — API-key comparison is not constant-time

**Affected:** `src/waf/auth.rs:80-84`

**Reasoning:** `InMemoryKeyStore::validate` hashes the presented key and performs a `HashSet::contains`. The comparison is not constant-time. The hash preimage makes practical exploitation difficult, but the comparison is still a timing side channel.

**Impact:** Theoretical key-oracle/timing attack.

**Recommended fix:** Compare the computed hash against stored hashes with a constant-time equality function, or use a keyed MAC and constant-time verification.

---

### L4 — WebSocket handshake response header parsing can panic on invalid upstream headers

**Affected:** `src/proxy/service.rs:1900-1925`

**Reasoning:** The upstream handshake response is parsed line by line with `split_once(':')`, then passed to `Response::builder().header(name, value)`. `http::response::Builder::header` panics on an invalid header name or value. A compromised or malformed upstream can therefore panic the request task.

**Impact:** Denial of service for the affected connection/task.

**Recommended fix:** Parse with `HeaderName::from_bytes` and `HeaderValue::from_str`, skip invalid fields, and return `502` if the response head is malformed.

---

### L5 — HTTP/2 and HTTP/3 do not restrict the `TE` header

**Affected:** `src/proxy/framing.rs:105-130`

**Reasoning:** The multiplexed-version check rejects `Transfer-Encoding` and connection-specific headers, but not `TE`. HTTP/2 permits only `TE: trailers`; other values are invalid. The proxy forwards `TE` only for gRPC with `trailers`, but the framing validator itself does not reject other values.

**Impact:** Low; a non-gRPC `TE` value is dropped by `build_upstream_request`, but the request is not rejected as malformed.

**Recommended fix:** On HTTP/2/HTTP/3, reject `TE` unless every token is `trailers`.

---

### L6 — Trailer validation does not restrict all unsafe fields

**Affected:** `src/proxy/framing.rs:148-170`

**Reasoning:** `validate_request_trailers` rejects `Content-Length`, `Transfer-Encoding`, `Trailer` and the fixed connection-specific list, but allows `Content-Encoding`, `Content-Type`, `Host`, `TE`, `X-Forwarded-*` and other routing headers in trailers.

**Impact:** Low; trailers are after the body, but an upstream that merges trailers into its request view could be influenced.

**Recommended fix:** Allow only known end-to-end trailer fields (for example `grpc-status`, `grpc-message`, `grpc-status-details-bin`) or reject all fields outside an explicit allowlist.

---

### L7 — HTTP/3 per-client admission is keyed on the QUIC peer, not the resolved client

**Affected:** `src/proxy/http3.rs:118`; `src/proxy/h3_admission.rs:130-170`

**Reasoning:** Admission is acquired before request headers are resolved, using `peer_ip`. Behind a trusted HTTP/3 proxy, every client shares the proxy's peer address, so the per-client limit collapses to a single bucket.

**Impact:** Low; the global limit still applies, but the per-client control is ineffective in a proxied deployment.

**Recommended fix:** Document that the per-client limit is per QUIC peer, or move the per-client check after `resolve_client_ip` (keeping the global permit before body read).

---

### L8 — Allow-cache early hit skips protocol pre-checks; descriptor reloads must invalidate

**Affected:** `src/waf/mod.rs:1537-1558`, `:1594-1620`; `src/waf/allow_cache.rs`

**Reasoning:** `cache_hit_early` runs before `precheck_core` and skips the gRPC/GraphQL pre-checks. The safety argument depends on the fingerprint covering every pre-check input and on `invalidate_allow_cache()` being called when protocol descriptors reload. If a descriptor or allowlist is reloaded without invalidation, a stale `Allow` can be served.

**Impact:** Low; requires the experimental `allow-cache` feature and a descriptor reload path that does not invalidate.

**Recommended fix:** Include a descriptor/allowlist generation in the cache key, or make descriptor reload call `invalidate_allow_cache()` unconditionally.

---

### L9 — Dead `WebSocketHandler` fast path would bypass inspection if wired in

**Affected:** `src/proxy/websocket.rs:400-470`

**Reasoning:** `WebSocketHandler::inspect_websocket_message` allows text messages under 1024 bytes that contain none of `< > ' " ; &`, and binary messages under 512 bytes, without WAF evaluation. The current request path uses `WafProxyService::bridge_websocket` instead, so this code is not reachable today.

**Impact:** Informational. If the handler is re-enabled, small messages bypass inspection.

**Recommended fix:** Remove the fast path or route it through the same `evaluate_shared` path as the live bridge.

---

## Fail-closed review

The following error paths were checked and return `Block`/4xx/5xx rather than `Allow`:

- Framing errors: `400` (`service.rs:1152`, `http3.rs:225`).
- Body too large / read error / timeout: `413`/`400`/`408`.
- Decompression unsupported / too large / malformed: `415`/`413`/`400`.
- gRPC probe errors: `413`/`400`; streaming guard errors surface as body errors.
- Admission rejection: `503` with `Retry-After`.
- WAF `Block`/`RateLimit`: configured status / `429`.
- Offloaded evaluation panic: `Block 503` when `fail_closed` is set (`mod.rs:1800-1825`).
- WAF initialisation failure: service construction fails (`service.rs:700-707`).

One residual note: the cheap inline evaluation path (`evaluate_shared` when `InspectionCost::Cheap`) does not catch a panicking rule. A panic aborts the request task rather than returning `Allow`, so it is not a fail-open, but it is a availability risk. This is not counted as a finding.

## Tests added

All new tests are marked `#[ignore]` with the finding ID so the normal suite stays green. Run them with `--include-ignored` to see the current behaviour.

| Test | Finding |
| --- | --- |
| `proxy::grpc_body::tests::unary_rpc_with_delayed_end_stream_is_not_forced_into_streaming` | H1 |
| `proxy::service::tests::multiple_forwarded_for_headers_fall_back_to_peer` | H2 |
| `proxy::service::tests::client_routing_and_override_headers_are_not_forwarded` | H3 |
| `proxy::service::tests::connection_nominated_headers_are_stripped` | M1 |
| `proxy::service::tests::content_length_is_reconciled_with_buffered_body` | M2 |
| `proxy::decompression::tests::brotli_trailing_garbage_is_rejected` | M7 |
| `proxy::framing::tests::rejects_prefixed_content_length` | L1 |
| `proxy::framing::tests::http10_rejects_transfer_encoding` | L2 |

Verification performed:

- `nix develop -c cargo test --lib 'proxy::'` — 68 passed, 0 failed, 8 ignored.
- `nix develop -c cargo test --lib 'proxy::' -- --include-ignored` — the 8 ignored tests fail as expected, demonstrating the findings.
- `nix develop -c cargo fmt -- --check` — clean.

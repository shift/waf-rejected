# Configuration key rule

Every key in the TOML schema must do something. A key that is parsed but never
read is a security footgun: an operator can set a control that silently has no
effect. Configuration is strict (`serde(deny_unknown_fields)`), so the schema
is the contract.

## The rule

1. Wire the key to runtime behaviour, or remove it from the serde struct.
2. Add wired keys to `CONSUMED_KEYS` in `src/config.rs`.
3. Run the guard: `nix develop -c cargo test --lib
   every_config_key_is_consumed_or_removed`.

The guard serialises `Config::default()` (including `Option::None` fields) to
JSON, walks every key path and compares the result with `CONSUMED_KEYS`. It
fails when:

- a schema key is missing from `CONSUMED_KEYS` — wire it or remove it, then add
  it; or
- `CONSUMED_KEYS` lists a key that no longer exists — remove the stale entry.

A removed key disappears from the struct, so `Config::load` rejects a file that
still sets it with the file name, section/key path and line/column.

## Audit helper

`scripts/audit-config-keys.sh` prints every declared key and a heuristic count
of references in `src/` outside `config.rs`. `NONE` is a strong signal that the
key is dead; a hit may still be unrelated (generic names such as `enabled`), so
inspect the accessor. The script is a review aid; the unit test above is the
enforced guard.

## Audit result (2026-11)

Keys declared but never read by the runtime, and the action taken:

| Key | Action | Why |
|---|---|---|
| `storage.backend` | **Wired** | Selects the redb/sled audit exporter. |
| `storage.path` | **Wired** | File/directory the audit exporter opens. |
| `storage.cache_size` | **Wired** | redb page-cache size passed to the exporter. |
| `storage.ttl_cleanup_interval` | **Wired** | Minimum interval between retention passes (`0` = every write). Audit events have no per-event TTL, so the historical name is documented as a cleanup schedule. |
| `storage.max_events` | **Added/wired** | Replaces the legacy `store_max_events` retention cap. |
| `storage.enable_follower_reads` | **Removed** | No follower/replica read path exists in this deployment. |
| `storage.enable_compression` | **Removed** | The event exporters do not compress values; the key never changed the on-disk format. |
| `storage.max_memory_entries` | **Removed** | The runtime audit store has no memory backend (memory remains an internal `StorageAdapter` for tests). |
| `proxy.upstream_url`, `proxy.bind_addr` | **Removed** | Duplicates of top-level `upstream_uri`/`bind_addr`; the proxy read the top-level values. |
| `waf.upstream_timeout_ms` | **Removed** | Duplicate deadline; `proxy.timeout_seconds` is the upstream request timeout. |
| `waf.security_events.format` | **Removed** | The event path emits structured records through the configured exporters; no plain/JSON/CEF switch consumed this value. |
| `waf.security_events.sled_compress` | **Removed** | `SledExporter` accepted the flag but serialised the same bytes either way. |
| `waf.wasm.rules_config` | **Removed** | The legacy WASM engine has no rules-file input. |
| `security.ai.model.*` | **Removed** | The AI detector consumes only `enabled`, `threat_threshold` and `timeout_ms`; model selection was a placeholder. |
| `security.compliance.*` | **Removed** | The compliance managers were never connected to the proxy. They remain a feature-gated library API built from `AuditConfig`/`RegulatoryConfig`/`RetentionConfig` directly. |
| `logging.level`, `logging.json_format` | **Wired** | `init_tracing` now builds the filter and JSON layer from `[logging]` (an explicit `RUST_LOG` still wins). |

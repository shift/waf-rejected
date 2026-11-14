# Migrating the security-event store: sled → redb

**Applies to:** `0.1.0-beta.17` and later.
**Default backend:** redb. **Legacy backend:** sled (still selectable, not
removed).

This runbook covers a one-way cut-over from the legacy sled event store to the
default redb store, and the reverse operation for a rollback. The tool is
`waf-storage-migrate` (built by default; requires the `export-sled` and
`export-redb` features).

## What "the event store" means

There are two on-disk layouts:

| Layout | Written by | Path | Shape |
|---|---|---|---|
| redb (default) | `RedbExporter` / `[storage] enabled = true` + `backend = "redb"` | `[storage] path`, default `./data/waf_security_events.redb` | one file, tables `data`, `ttl_metadata`, `expiration_index` |
| sled adapter (legacy) | `SledStorageAdapter` | `[storage] path` | sled directory, trees `data`, `ttl`, `meta` |
| sled exporter (legacy events) | `SledExporter` (`[storage] backend = "sled"`, or legacy `enable_sled = true`) | `[storage] path`, or legacy `sled_db_path` / default `./waf_security_events.sled` | sled directory, tree `security_events` |

`waf-storage-migrate` auto-detects the legacy exporter tree. If the source sled
directory contains a non-adapter tree (normally `security_events`), that tree is
copied; otherwise the adapter `data` tree is copied. Use `--from-tree NAME` to
be explicit.

## Durability and cost

* redb: every write transaction sets `Durability::Immediate`. `export_event`
  returns only after the commit is fsynced, so an acknowledged security event
  survives a crash. Cost: one fsync per write transaction (the exporter writes
  one event per transaction unless the caller uses `export_batch`, which still
  commits per event in the current implementation; a bulk commit is a future
  optimisation).
* sled: the legacy adapter/exporter explicitly flushes after each write. sled's
  own default is `flush_every_ms = 500`, which does **not** guarantee that an
  acknowledged event survives a crash, so the explicit flush is a durability
  requirement, not tuning.
* Migration reads and writes everything twice (copy + verify), so budget disk
  space for the new store plus the old store until the cut-over is accepted.

redb compaction is not available in-process (the adapter shares the database
behind an `Arc`; redb's `compact` needs `&mut Database`). To reclaim space,
migrate into a fresh redb file with `--force`/a new path and swap it in during a
maintenance window.

## Pre-flight

1. **Quiesce writes** to the source store: stop the WAF, or run the migration
   against a filesystem snapshot. The verification pass assumes the key set does
   not change underneath it.
2. **Check space**: `df -h` on the destination filesystem. Expect roughly the
   source size plus redb overhead (copy-on-write; freed pages are reused but not
   returned to the OS immediately).
3. **Back up the source**: copy the sled directory (or a `tar` of it). A
   filesystem snapshot is equivalent.
4. **Confirm versions**: the migration binary must be from the same release as
   the WAF you are about to run. Run `waf-storage-migrate --version`.
5. **Permissions**: the destination directory must be writable by the WAF user
   and readable by the operator running the migration.

## Dry run and migration

The tool has no write-free dry run; the safe rehearsal is to migrate into a
scratch path and inspect the summary:

```bash
waf-storage-migrate \
  --from ./data/waf_security_events.sled \
  --to /tmp/rehearsal.redb
```

Then run the real cut-over with the destination path the WAF will use:

```bash
waf-storage-migrate \
  --from /var/lib/waf/data/waf_security_events.sled \
  --to   /var/lib/waf/data/waf_security_events.redb
```

Useful options:

| Option | Effect |
|---|---|
| `--from-backend sled --to-backend redb` | Explicit backend selection (defaults). |
| `--from-tree security_events` | Read a specific legacy sled tree. |
| `--batch-size N` | Keys per commit/checkpoint (default 1000). |
| `--force` | Clear a non-empty destination first. Refused otherwise. |
| `--sample N` | Verify the first N entries byte-for-byte instead of the full SHA-256 digest. |
| `--state-file PATH` | Checkpoint path (default `<destination>.migrate-state.json`). |
| `--quiet` | Suppress per-batch progress. |
| `--reverse` | redb → sled downgrade (see below). |

Progress is printed per batch:

```
migrate: copied=1000 elapsed=1.4s rate=714/s
```

### What the tool guarantees

* **Idempotent resume.** The checkpoint records the source/destination identity
  and the last key durably copied. If the process is killed, re-running the same
  command continues after that key. A checkpoint that names a different
  source/destination is rejected rather than silently reused.
* **Verification.** A second pass compares key counts and a SHA-256 digest over
  `(key_length, key, value_length, value, ttl_presence)` in key order. A
  mismatch exits non-zero and leaves the checkpoint in place for inspection.
* **No accidental overwrite.** A non-empty destination is refused unless
  `--force` is given. `--force` clears the destination first.
* **Expiry is preserved** as remaining TTL; already-expired entries are skipped
  rather than resurrected.

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Copied and verified. |
| `2` | Usage/config conflict (same store, bad checkpoint identity). |
| `3` | Destination is not empty and `--force` was not passed. |
| `4` | Source/destination open or storage error. |
| `5` | Verification failed. |

## Cut over the WAF

Edit the WAF configuration:

```toml
[storage]
enabled = true
backend = "redb"
path = "/var/lib/waf/data/waf_security_events.redb"
max_events = 100000
```

Remove any legacy `[waf.security_events] store_backend` / `store_path` /
`store_max_events` / `enable_sled` / `sled_db_path` / `sled_max_events` keys:
`storage.enabled = true` and those keys together are rejected as ambiguous.

Restart the WAF. Readiness reports the store as a dependency; a failed open
fails the readiness check (the request path is not blocked by an export
failure, matching the existing best-effort audit contract).

## Rollback / downgrade

A downgrade is **supported only through the reverse migration**. redb and sled
do not share an on-disk format, so pointing the old binary at the redb file does
not work and is unsupported.

```bash
waf-storage-migrate --reverse \
  --from /var/lib/waf/data/waf_security_events.redb \
  --to   /var/lib/waf/data/waf_security_events.sled \
  --to-tree security_events
```

Then set `[storage] backend = "sled"` and `path` to the legacy sled directory,
and restart. Alternatively restore the pre-migration sled backup: that is
the fastest rollback and loses only events written to redb after the cut-over.

Keep the sled backup until the redb store has been accepted (at least one
retention period is recommended).

## Troubleshooting

| Symptom | Action |
|---|---|
| Exit 3, destination not empty | You are re-running after a successful migration, or the destination has unrelated data. Inspect it; use `--force` only if you intend to replace it. |
| Exit 5, digest/count mismatch | Re-run; the checkpoint resumes. If it repeats, the source is being written concurrently — quiesce it and rerun with `--force` into a fresh destination. |
| Exit 4, source open error | The WAF still holds the sled lock, or the path is wrong. Stop the WAF. |
| Migration is slow | Raise `--batch-size`; the per-batch fsync dominates. |
| Disk fills | redb copy-on-write needs headroom. Free space and re-run; the checkpoint resumes. Disk-full is not simulated in the test suite (it needs a quota/tmpfs), so monitor free space explicitly. |
| Interrupted run | Re-run the same command. Delete the `*.migrate-state.json` file only to force a fresh copy (the destination must then be empty or `--force` used). |

## Verification in the test suite

`src/waf/storage/migrate.rs` tests build a sled store, migrate it, and read every
event back from redb with identical content, including:

* a legacy `security_events` tree (the pre-redb exporter layout);
* a non-empty destination without `--force`;
* resume from a checkpoint without re-copying the prefix;
* redb → sled reverse migration.

`src/waf/storage/parity_tests.rs` additionally runs the same behavioural suite
against redb, sled and memory: insert/get/delete, ordering, prefix/range scans,
TTL, bulk deletion, concurrency, restart durability, size accounting and error
cases.

# Runnable Demo

`scripts/demo.sh` starts a mock upstream and the WAF on throwaway loopback
ports, sends benign, SQL injection, XSS and gRPC requests, prints the status of
each, and cleans up.

It uses the minimal configuration shape (native Rust CRS engine, fail closed)
and never touches the host's real ports or data directory.

## Run

From the repository root:

```bash
./scripts/demo.sh
```

If no binary is found the script builds one with
`nix develop -c cargo build --bin waf-ingress`. Override discovery with:

```bash
WAF_BIN=./result/bin/waf-ingress ./scripts/demo.sh
```

Artifacts (generated config, logs, mock upstream) are written under
`/tmp/opencode/waf-demo-*` and left in place for inspection. Only the processes
are stopped.

## What it does

1. Picks free loopback ports for the proxy, health listener and upstream.
2. Writes a minimal TOML config with `waf.coraza` left at its default (`rust`).
3. Starts a Perl (or Python fallback) mock upstream that returns `200 ok` for
   every path.
4. Waits for `/health/ready`.
5. Sends:
   - `GET /hello` — benign, expected to be forwarded (`200`).
   - `GET /?id=1 UNION SELECT ...` — SQL injection in the query string,
     expected `403`.
   - `POST /login` with `<script>alert(1)</script>` — XSS in the body,
     expected `403`.
   - `POST /demo.Echo/Say` with `content-type: application/grpc` and a valid
     length-prefixed frame — envelope-only gRPC, expected to be forwarded.
6. Prints a pass/fail summary and stops both processes.

## Expected output

```text
benign GET /hello                        200 (allowed)
sqli query string                        403 (blocked)
xss request body                         403 (blocked)
grpc envelope (empty protobuf message)   200 (allowed)
```

Exact status codes for the gRPC row depend on the upstream mock; the demo only
requires that it is not a WAF block.

## Troubleshooting

- **`address already in use`** — the script picks free ports at startup; if a
  race occurs, rerun it.
- **Readiness timeout** — inspect the WAF log path printed by the script. A
  missing `rules/crs` bundle or a bad config is fatal by design.
- **Everything is blocked** — check `fail_mode` and the WAF log. The demo
  config keeps `fail_mode = "closed"`.
- **No Perl/Python** — the mock upstream needs `perl` (preferred) or
  `python3`; any static upstream on the chosen port works if you edit the
  script.

See [quickstart](../user-guide/quickstart.md) for a manual walkthrough and
[configuration](../user-guide/configuration.md) for the full config surface.

# CRS prefilter corpus

`crs-prefilter-corpus.json` is the detection-parity corpus for the experimental
`crs-prefilter` feature. It is intentionally small and reviewable:

* **benign**: search, login (form + JSON), product JSON, article text, contact
  and review forms, a multipart text upload, XML order, multilingual prose,
  encoded query strings, CSV and base64 uploads.
* **attacks**: SQLi (classic, union, time, error, URL-encoded), XSS (script,
  image/onerror, `javascript:` URI, SVG, iframe), LFI (Unix, Windows,
  `php://filter`), RFI, RCE (shell, subshell, backticks, wget, PowerShell,
  `${IFS}`), PHP (`system`, `eval`, `php://input`, object injection), Java
  (`Runtime`, `ProcessBuilder`, JNDI), SSTI, SSRF, SSI, JSP and XXE.

Payloads are taken from the OWASP CRS 4.14 regression suite
(`tests/regression`) and documented public payload lists. The `family` field is
a label only; the harness uses the **actual full-CRS decision** from the pinned
native sidecar as ground truth.

Run the harness from the repository root:

```sh
nix develop -c cargo run --release --features crs-prefilter,coraza-native \
  --bin crs-prefilter-bench -- \
  --corpus tests/corpus/crs-prefilter-corpus.json \
  --socket /tmp/opencode/coraza.sock --reps 3
```

The sidecar must be started with the vendored bundle:

```sh
cd native/coraza-sidecar
nix develop -c env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOFLAGS=-mod=vendor \
  go build -trimpath -o /tmp/opencode/coraza-sidecar .
cd ../..
/tmp/opencode/coraza-sidecar --socket /tmp/opencode/coraza.sock \
  --rules wasm/coraza_reactor/rules/crs/crs.conf --max-body 1048576
```

The harness also reports the **unsafe** body-withholding parity (withhold the
body whenever the prefilter is clean, ignoring the ungated-rule guard). That
number shows exactly which ungated rules would be lost; the production mode
refuses to take that path while any ungated body rule exists.

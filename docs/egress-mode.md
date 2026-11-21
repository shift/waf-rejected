# Egress mode

Egress mode is a local fetch service for agents. The agent posts a URL to
`http://127.0.0.1:8082/egress/fetch`; the service performs the request, inspects
the response and returns the body plus a verdict. It is **not** a network proxy
and it does **not** tunnel traffic.

It is disabled by default. Edge behaviour, thresholds and rules do not change
when `[egress]` is absent from the configuration.

## Why a fetch service instead of a CONNECT proxy

A CONNECT proxy would be the obvious shape for "let the agent reach the
internet", but it cannot inspect an HTTPS response body. The bytes inside the
tunnel are encrypted end-to-end between the agent and the origin; the proxy sees
ciphertext. Inspecting them requires terminating TLS in the proxy with a CA that
the agent trusts. That means generating and installing a local root CA on every
laptop, rotating it, and supporting agents and language runtimes that each use a
different trust store. It is a bad default and a worse support burden.

Egress mode avoids the tunnel. The service is the HTTP client:

```text
agent --POST /egress/fetch {url}--> egress service --TLS--> origin
agent <--body + verdict----------- egress service <--TLS-- origin
```

Because the service terminates the origin TLS with the normal public roots
(bundled `webpki-roots`), it sees the plaintext response. It can inspect the
body before the agent ever receives it, without a local CA, without a
certificate of its own, and without a privileged network namespace.

The trade-off is that the agent must use the service's API. That is acceptable
for this threat model: the aim is to stop an agent from being steered into
fetching a dangerous URL, and to tell it when a fetched page contains
instructions aimed at it. It does not stop an agent that deliberately bypasses
the service.

## API

Every response carries the same headers as the edge contract:

| header | value |
|---|---|
| `x-waf-verdict` | `fetched`, `recorded`, `blocked` or `failed` |
| `x-waf-rule-id` | first matched rule id (absent when no rule matched) |
| `x-waf-rule-ids` | all matched rule ids, comma separated |

### Request

```http
POST /egress/fetch
content-type: application/json

{ "url": "https://example.org/a", "max_bytes": 2097152, "timeout_ms": 15000 }
```

`max_bytes` and `timeout_ms` are optional per request. They are clamped to the
configured values; a request cannot raise the deployment cap or budget.

### Responses

```json
200 {"outcome":"fetched","rule_ids":[],"bytes":1234,"truncated":false,
     "as_of":"2026-11-21T20:00:00.000Z","body":"...","content_type":"text/html"}

200 {"outcome":"recorded","rule_ids":["EG-2001"],"bytes":1234,"truncated":false,
     "as_of":"...","body":"...","content_type":"text/html",
     "message":"response text contains injection marker \"ignore previous instructions\""}

403 {"outcome":"blocked","rule_ids":["EG-1002"],"bytes":0,"truncated":false,
     "as_of":"...","message":"blocked by EG-1002: host resolves to a cloud metadata address (169.254.169.254)"}

502 {"outcome":"failed","rule_ids":[],"bytes":0,"truncated":false,
     "as_of":"...","message":"connection to ... failed: ..."}
```

A refusal always names the rule and the reason. It is never the bare word
"forbidden".

`GET /metrics` on the egress listener renders the same Prometheus snapshot as
the health listener, including:

```text
waf_egress_outcome_total{outcome="fetched|recorded|blocked|failed"}
waf_egress_rule_hits_total{rule_id="EG-1001|...|EG-2003"}
```

## Rules

The identifiers are part of the contract.

| id | when | default action |
|---|---|---|
| EG-1001 | host resolves to a private/loopback/link-local address (RFC1918, 127/8, ::1, fc00::/7, fe80::/10) | refuse |
| EG-1002 | host resolves to a cloud metadata address (169.254.169.254, fd00:ec2::254) | refuse |
| EG-1003 | scheme not in `allow_schemes` (default `["https"]`) | refuse |
| EG-1004 | port not in `allow_ports` (default `[443]`) | refuse |
| EG-1005 | a query parameter name looks like a credential (`token`, `key`, `api_key`, `apikey`, `secret`, `password`, `sig`, `signature`, `access_token`, `auth`) | refuse |
| EG-2001 | response text contains an injection marker (`ignore previous instructions`, `ignore all previous`, `system prompt`, `you are now`, `disregard the above`), or hidden text: an HTML element with `display:none`/`font-size:0` carrying more than 200 characters of text | record (refuse when `mode = "refuse"`) |
| EG-2002 | body exceeds `max_bytes` | refuse, `truncated: true` |
| EG-2003 | content type not in `allow_content_types` | record |

Two configuration-driven domain rules extend the pre-connection group:

| id | when | default action |
|---|---|---|
| EG-1006 | host matches `deny_domains` (subdomains included) | refuse |
| EG-1007 | `allow_domains` is non-empty and the host does not match it | refuse |

The default is **record**, not refuse. A page with `<script>` is normal; only
the injection class escalates, and only when configured with `mode = "refuse"`.
EG-2002 always refuses because returning a body past the cap would defeat the
cap. EG-2003 remains a record even in refuse mode.

## Redirects and rebinding

At most `max_redirects` (default 3) redirects are followed. Every hop is
re-resolved and re-checked against EG-1001, EG-1002, EG-1003, EG-1004, EG-1005,
EG-1006 and EG-1007 **before the next connection**. A redirect to
`http://169.254.169.254/` is refused with EG-1002; the metadata endpoint is never
contacted.

The service resolves the name once per hop, checks every returned address, and
connects to the checked address rather than passing the name to a connector that
would resolve again. That closes the DNS-rebinding window between the check and
the connection. One private address in a set refuses the whole name.

## Configuration

```toml
[egress]
enabled = false
bind_addr = "127.0.0.1:8082"
mode = "record"                  # record | refuse
max_bytes = 2097152
timeout_ms = 15000
max_redirects = 3
allow_schemes = ["https"]
allow_ports = [443]
allow_domains = []               # empty = any domain that passes the IP checks
deny_domains = []
allow_content_types = ["text/html", "text/plain", "application/json", "application/xml", "text/markdown"]
```

`config.egress.toml` at the repository root is the laptop preset: loopback bind,
record mode, 2 MiB cap, 15 second budget.

## Running it on a laptop

```bash
WAF_CONFIG_FILE=config.egress.toml cargo run --release
```

Then:

```bash
curl -s http://127.0.0.1:8082/egress/fetch \
  -H 'content-type: application/json' \
  -d '{"url":"https://example.org/"}'
```

The egress listener binds `127.0.0.1:8082` and needs no upstream, no TLS
certificate and no CA. The ordinary edge listener still starts from the same
configuration; point `bind_addr` and `upstream_uri` elsewhere if you only want
egress mode running.

## What it does not protect against

- **It does not stop the agent from asking for a bad URL.** It stops the fetch.
  An agent that ignores the 403 and opens its own socket is outside this
  boundary.
- **It is not a sandbox.** The process is a normal user process; egress mode
  adds no filesystem, process or network isolation.
- **It cannot see inside a page it never fetched.** JavaScript-only content,
  responses behind authentication, and pages reached by a client other than
  this service are invisible to it.
- **It does not protect the origin from the agent.** It protects the agent from
  the response, not the other way round.
- **It cannot detect every hidden-text trick.** The HTML scan catches
  `display:none` and `font-size:0` blocks over 200 characters. Other hiding
  techniques (off-screen positioning, tiny opacity, colour matching) are not
  covered.
- **It is not a credential store.** EG-1005 refuses credential-looking query
  names; it does not scrub headers, cookies or bodies, and it never stores
  secrets.

## How agentic-loop consumes it

The agent loop calls the fetch endpoint instead of using its own HTTP client
for pages. It maps the verdict as follows:

- `blocked` (403) with `x-waf-rule-id` becomes a `blocked` span carrying the
  rule id and the refusal message. The step records the refusal and does not
  retry the same URL blindly.
- `recorded` (200) becomes a `fetched` span with a warning attached, so the
  body is available but the injection signal is visible in the trace.
- `fetched` (200) becomes a normal `fetched` span.
- `failed` (502) becomes a `failed` span; it is a transport or timeout error,
  not a policy refusal.

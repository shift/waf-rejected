# Nix deployment

WAF-Rejected ships a NixOS module and an OCI image in its flake:

```nix
{
  inputs.waf-rejected.url = "github:shift/waf-rejected";
}
```

| Output | Purpose |
| --- | --- |
| `nixosModules.default`, `nixosModules.waf-rejected` | `services.waf-rejected` |
| `packages.<system>.container` | Layered OCI image (`waf-rejected:latest`) |
| `packages.<system>.waf-ingress` | The binary and its rule bundle |

The module and the image run the same `waf-ingress` binary. The flake wrapper
sets `services.waf-rejected.package` to the flake's `waf-ingress`, so the
default package is never taken from the ambient `pkgs` set.

## How the binary is configured

`waf-ingress` takes no configuration flag. `--help` documents only
`--version` and `--help`. At start it loads, in order:

1. compiled defaults;
2. the TOML file named by `WAF_CONFIG_FILE` (falling back to `CONFIG_PATH`,
   then `config.toml`);
3. `WAF_*` environment variables, using `__` for nesting.

The module therefore sets `WAF_CONFIG_FILE` and exports the listener and
upstream options as `WAF_BIND_ADDR`, `WAF_HEALTH_BIND_ADDR` and, when set,
`WAF_UPSTREAM_URI`. These environment values override the same keys in the
file.

There is **no `--check-config` flag**, and the module does not invent one.
Configuration is not validated at Nix build/evaluation time; a malformed or
unknown key fails at service start with an error naming the file, section,
key and line. Validate a file against the real loader before deploying:

```bash
./scripts/validate-configs.sh
```

## NixOS

```nix
{
  imports = [ inputs.waf-rejected.nixosModules.default ];

  services.waf-rejected = {
    enable = true;
    configFile = ./waf-rejected.toml;   # copied to the Nix store
    bindAddr = "0.0.0.0:8080";
    healthBindAddr = "127.0.0.1:8081";
    upstreamUri = "http://127.0.0.1:3000";
    openFirewall = true;                # opens the proxy port only
  };
}
```

A minimal `waf-rejected.toml` matches the documented schema:

```toml
bind_addr = "0.0.0.0:8080"
health_bind_addr = "127.0.0.1:8081"
upstream_uri = "http://127.0.0.1:3000"

[logging]
level = "info"

[waf]
enabled = true
fail_mode = "closed"

[storage]
enabled = false
```

`bind_addr`, `health_bind_addr` and `upstream_uri` in the file are redundant
when the module options above are set; leaving them out is fine.

### Options

| Option | Default | Meaning |
| --- | --- | --- |
| `enable` | `false` | Run `waf-rejected.service` |
| `package` | flake `waf-ingress` | Binary package |
| `configFile` | required | TOML path, exported as `WAF_CONFIG_FILE` |
| `bindAddr` | `127.0.0.1:8080` | Proxy listener (`WAF_BIND_ADDR`) |
| `healthBindAddr` | `127.0.0.1:8081` | Health/metrics listener (`WAF_HEALTH_BIND_ADDR`) |
| `upstreamUri` | `null` | Upstream override (`WAF_UPSTREAM_URI`) |
| `user` | `waf` | System user (created when enabled) |
| `group` | `waf` | System group (created when enabled) |
| `openFirewall` | `false` | Open the proxy TCP port; health/metrics stays closed |
| `extraEnvironment` | `{}` | Extra non-secret `WAF_*` overrides |
| `environmentFile` | `null` | systemd `EnvironmentFile=` for secret overrides |

### Service hardening and state

The unit runs as the unprivileged `waf` user with `ProtectSystem=strict`,
`ProtectHome=true`, `PrivateTmp=true`, `NoNewPrivileges=true`, a native-only
syscall ABI, no ambient capabilities by default, and an empty capability
bounding set. When either listener is below port 1024, the module adds
`CAP_NET_BIND_SERVICE` to `AmbientCapabilities` and `CapabilityBoundingSet`.
Prefer keeping the WAF on 8080/8081 and mapping privileged ports in front of
it (load balancer, container port mapping, or firewall redirect).

`StateDirectory=waf` creates `/var/lib/waf` owned by the service user, and
`WorkingDirectory=/var/lib/waf` makes the binary's relative paths land there.
The WAF writes nothing by default. The directory is needed only when the
configuration enables the audit store:

```toml
[storage]
enabled = true
backend = "redb"
path = "/var/lib/waf/data/waf_security_events.redb"
```

or a CEF output file such as `/var/lib/waf/logs/security_events.cef`. Create
the subdirectories (`/var/lib/waf/data`, `/var/lib/waf/logs`) with
`systemd.tmpfiles.rules`, or use absolute paths whose parents already exist.
`StateDirectory` only creates the top-level directory.

## Container

```bash
nix build .#container
docker load < result
```

The image is `waf-rejected:latest`. It runs as UID/GID `1000`, carries the
crane-built binary, the CRS rules, `curl` (for the health check) and CA
certificates, and ships `config.docker.toml` at `/etc/waf/config.toml`.

```bash
docker run --rm \
  -p 8080:8080 \
  -p 127.0.0.1:8081:8081 \
  -v waf-state:/var/lib/waf \
  -v "$PWD/config.toml:/etc/waf/config.toml:ro" \
  -e WAF_UPSTREAM_URI=http://backend:3000 \
  waf-rejected:latest
```

- Proxy port: `8080/tcp` (container listener is `0.0.0.0:8080`). Map host port
  80/443 to it (`-p 80:8080`); the process never binds a privileged port.
- Health/metrics port: `8081/tcp`. Publish it on loopback unless the probe
  runs remotely.
- State volume: `/var/lib/waf`, for the redb audit store and CEF log. Mount it
  when `[storage] enabled = true` or the CEF exporter is active.
- Config: `/etc/waf/config.toml`. The baked file is non-secret; bind-mount your
  own file over it, or override individual keys with `WAF_*` variables.
- Health check: `curl -fsS http://127.0.0.1:8081/health/ready` every 10s.
- Capabilities: the image uses no ambient capabilities. Port mapping is done
  by Docker, not by binding low ports inside the container.

## Ports and endpoints

| Port | Endpoint | Notes |
| --- | --- | --- |
| 8080/tcp | Proxy traffic | `bindAddr` / `bind_addr` |
| 8081/tcp | `/health` | Overall health |
| 8081/tcp | `/health/live` | Process liveness |
| 8081/tcp | `/health/ready` | Dependency readiness; used by the image health check |
| 8081/tcp | `/metrics` | Prometheus metrics |

Health and metrics are always served on `health_bind_addr`, never on the proxy
listener.

## Secrets

The module and image store **no secrets**. `extraEnvironment` and the baked
container configuration are in the Nix store and are world-readable, so do not
put any of the following there:

- `security.auth.api_keys` and any other API key or token;
- TLS private keys (`server.tls.key_path`, upstream client keys);
- upstream credentials or cloud/API tokens.

Keep those in a runtime file and point the module at it:

```nix
services.waf-rejected.environmentFile = "/run/secrets/waf-rejected.env";
```

The file is passed to systemd as `EnvironmentFile=` and is not copied to the
store. In a container, bind-mount the secret and reference it from the mounted
configuration or pass secret `WAF_*` variables with `--env-file`.

Note that the config loader is strict: every `WAF_*` variable becomes a config
override, and an unknown key is fatal. Only export variables that map to real
configuration keys.

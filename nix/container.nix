# OCI image for WAF-Rejected.
#
# Mirrors the repository Dockerfile: the same binary (built by crane in the
# flake), the same `/etc/waf/config.toml` path, the same `/var/lib/waf` state
# volume and the same `/health/ready` probe. The upstream listener is
# `config.docker.toml` (0.0.0.0:8080 proxy, 0.0.0.0:8081 health/metrics).
#
# The image runs as UID/GID 1000 and does not bake in secrets. Configuration
# overrides are passed as `WAF_*` environment variables at run time; the image
# config itself only contains non-secret defaults.
{ lib, pkgs, waf-ingress }:

let
  uid = 1000;
  gid = 1000;
in
pkgs.dockerTools.buildLayeredImage {
  name = "waf-rejected";
  tag = "latest";

  contents = [
    waf-ingress
    pkgs.cacert
    pkgs.curl
  ];

  # Create the mount points and install the shipped non-secret config. A
  # bind-mounted file at /etc/waf/config.toml replaces it at run time.
  extraCommands = ''
    mkdir -p etc/waf tmp
    mkdir -p var/lib/waf/data var/lib/waf/logs
    chmod 1777 tmp
    install -m644 ${../config.docker.toml} etc/waf/config.toml
    chown -R ${toString uid}:${toString gid} var/lib/waf
  '';

  config = {
    Entrypoint = [ "/bin/waf-ingress" ];
    User = "${toString uid}:${toString gid}";
    WorkingDir = "/var/lib/waf";
    ExposedPorts = {
      "8080/tcp" = { };
      "8081/tcp" = { };
    };
    Volumes = {
      "/var/lib/waf" = { };
    };
    Env = [
      "RUST_LOG=info"
      "WAF_CONFIG_FILE=/etc/waf/config.toml"
      "WAF_UPSTREAM_URI=http://127.0.0.1:3000"
      "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
    ];
    Healthcheck = {
      Test = [ "CMD" "/bin/curl" "-fsS" "http://127.0.0.1:8081/health/ready" ];
      Interval = 10000000000; # 10s
      Timeout = 3000000000; # 3s
      StartPeriod = 20000000000; # 20s
      Retries = 3;
    };
  };

  meta = {
    description = "WAF-Rejected ingress proxy (OCI image)";
    homepage = "https://github.com/shift/waf-rejected";
    license = lib.licenses.asl20;
  };
}

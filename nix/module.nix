# NixOS module for WAF-Rejected (`waf-ingress`).
#
# The binary takes no configuration flag: it reads the TOML file named by
# `WAF_CONFIG_FILE` (falling back to `CONFIG_PATH`, then `config.toml`) and
# applies `WAF_*` environment overrides on top of it, using `__` for nesting.
# This module sets `WAF_CONFIG_FILE` and the listener/upstream overrides that
# the options below expose.
#
# There is no `--check-config` flag. `waf-ingress --help` documents only
# `--version` and `--help`, so this module does not validate the TOML at build
# time; a malformed file fails at service start with a strict error naming the
# file, section, key and line. Use `scripts/validate-configs.sh` in the source
# tree to validate configs against the real loader before deploying.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.waf-rejected;
  inherit (lib) mkIf mkOption mkEnableOption types;

  # Extract the port from a `host:port` (or `[v6]:port`) listener string.
  portOf = addr: lib.toInt (lib.last (lib.splitString ":" addr));

  # Binding below 1024 requires CAP_NET_BIND_SERVICE for the non-root user.
  needsNetBind =
    portOf cfg.bindAddr < 1024 || portOf cfg.healthBindAddr < 1024;
in
{
  options.services.waf-rejected = {
    enable = mkEnableOption "the WAF-Rejected ingress proxy";

    package = mkOption {
      type = types.package;
      default = pkgs.waf-rejected or (throw ''
        services.waf-rejected.package has no default outside this flake.
        Import `nixosModules.default` from the waf-rejected flake, or set
        services.waf-rejected.package to a waf-ingress build.'');
      defaultText = lib.literalExpression "waf-rejected.packages.\${system}.waf-ingress";
      description = "The `waf-ingress` package to run.";
    };

    configFile = mkOption {
      type = types.path;
      example = "/etc/waf-rejected/config.toml";
      description = ''
        Path to the TOML configuration passed as `WAF_CONFIG_FILE`. The file is
        read at every start; changes take effect on restart (`hot_reload`
        applies to the rule bundle, not this file).

        Keep secrets out of this file when it is a Nix store path. Use
        {option}`environmentFile` for values that come from a runtime secret.
      '';
    };

    bindAddr = mkOption {
      type = types.str;
      default = "127.0.0.1:8080";
      example = "0.0.0.0:8080";
      description = ''
        Proxy listener, exported as `WAF_BIND_ADDR` and therefore overriding
        `bind_addr` from the configuration file. The default keeps the proxy
        off the network until the operator opts in.
      '';
    };

    healthBindAddr = mkOption {
      type = types.str;
      default = "127.0.0.1:8081";
      example = "127.0.0.1:8081";
      description = ''
        Health and metrics listener (`/health`, `/health/live`,
        `/health/ready`, `/metrics`), exported as `WAF_HEALTH_BIND_ADDR`.
      '';
    };

    upstreamUri = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "http://127.0.0.1:3000";
      description = ''
        Upstream URI to proxy to, exported as `WAF_UPSTREAM_URI`. When null the
        `upstream_uri` value from the configuration file is used.
      '';
    };

    user = mkOption {
      type = types.str;
      default = "waf";
      description = "System user that runs the proxy.";
    };

    group = mkOption {
      type = types.str;
      default = "waf";
      description = "System group that runs the proxy.";
    };

    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Open the proxy port in the firewall. The health/metrics port is not
        opened: keep it on loopback or expose it through a separate rule.
      '';
    };

    extraEnvironment = mkOption {
      type = types.attrsOf types.str;
      default = { };
      example = {
        WAF_SERVER__MAX_BODY_SIZE = "262144";
        WAF_LOGGING__LEVEL = "info";
      };
      description = ''
        Extra `WAF_*` environment overrides merged into the service
        environment. Values are visible in the Nix store and in
        `systemctl show`; do not put secrets here.
      '';
    };

    environmentFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = "/run/secrets/waf-rejected.env";
      description = ''
        Optional runtime environment file (systemd `EnvironmentFile=`) for
        secret `WAF_*` overrides. The file is read at start and is not copied
        into the Nix store. It must be readable by {option}`user`.
      '';
    };
  };

  config = mkIf cfg.enable {
    users.groups = lib.mkIf (cfg.group != "root") {
      ${cfg.group} = { };
    };

    users.users = lib.mkIf (cfg.user != "root") {
      ${cfg.user} = {
        isSystemUser = true;
        group = cfg.group;
        description = "WAF-Rejected ingress proxy";
      };
    };

    networking.firewall.allowedTCPPorts =
      lib.optionals cfg.openFirewall [ (portOf cfg.bindAddr) ];

    systemd.services.waf-rejected = {
      description = "WAF-Rejected ingress proxy";
      documentation = [ "https://github.com/shift/waf-rejected" ];
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      environment = {
        WAF_CONFIG_FILE = toString cfg.configFile;
        WAF_BIND_ADDR = cfg.bindAddr;
        WAF_HEALTH_BIND_ADDR = cfg.healthBindAddr;
      } // lib.optionalAttrs (cfg.upstreamUri != null) {
        WAF_UPSTREAM_URI = cfg.upstreamUri;
      } // cfg.extraEnvironment;

      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/waf-ingress";
        User = cfg.user;
        Group = cfg.group;

        # Relative paths in the configuration (the default storage path is
        # `./data/waf_security_events.redb`) resolve below this directory.
        WorkingDirectory = "/var/lib/waf";
        StateDirectory = "waf";
        StateDirectoryMode = "0750";

        Restart = "on-failure";
        RestartSec = 2;
        LimitNOFILE = 65536;

        EnvironmentFile = lib.optional (cfg.environmentFile != null) cfg.environmentFile;

        # Hardening. The proxy only needs its listeners and the state dir.
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        RestrictSUIDSGID = true;
        RestrictRealtime = true;
        LockPersonality = true;
        SystemCallArchitectures = "native";

        # Only needed when an operator selects a privileged port (80/443).
        AmbientCapabilities =
          lib.optionals needsNetBind [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet =
          lib.optionals needsNetBind [ "CAP_NET_BIND_SERVICE" ];
      };
    };
  };
}

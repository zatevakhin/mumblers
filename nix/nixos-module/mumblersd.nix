{config, lib, pkgs, ...}:

let
  cfg = config.services.mumblersd;
  tomlFormat = pkgs.formats.toml {};

  selfSignedCertPath = "certs/mumblers.crt";
  selfSignedKeyPath = "certs/mumblers.key";

  effectiveCertificate =
    if (cfg.settings ? certificate) then cfg.settings.certificate else selfSignedCertPath;

  effectivePrivateKey =
    if (cfg.settings ? private_key) then cfg.settings.private_key else selfSignedKeyPath;

  effectiveSettings = cfg.settings
    // {
      certificate = effectiveCertificate;
      private_key = effectivePrivateKey;
    };

  generatedToml = tomlFormat.generate "mumblers.toml" effectiveSettings;
in {
  options.services.mumblersd = {
    enable = lib.mkEnableOption "mumblersd (Mumble server daemon)";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ../package.nix {};
      defaultText = "pkgs.callPackage ./nix/package.nix {}";
      description = "The mumblersd package to run.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open the configured TCP/UDP ports in the firewall.";
    };

    generateSelfSignedCerts = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Generate a self-signed certificate into the service StateDirectory
        when no certificate/key exist.
      '';
    };

    settings = lib.mkOption {
      type = lib.types.attrs;
      default = {
        bind_host = "127.0.0.1";
        bind_port = 64738;
        udp_bind_port = 64738;
        server_name = "mumblers";
        welcome_text = "Welcome";
        max_bandwidth = 72000;
        allow_anonymous = true;
        default_channel = "Root";
        channels = [];
        # Matches `0x8000_000b_u32 as i32` in the Rust defaults.
        codec_alpha = -2147483637;
        codec_beta = -2147483637;
        codec_prefer_alpha = true;
        enable_opus = true;
      };
      description = ''
        Server configuration written to TOML and passed to `mumblersd serve`.

        Keys correspond to the `ServerConfig` TOML fields (e.g. `bind_host`,
        `bind_port`, `udp_bind_port`, `certificate`, `private_key`).
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.generateSelfSignedCerts || ((cfg.settings ? certificate) && (cfg.settings ? private_key));
        message = "services.mumblersd: set services.mumblersd.settings.certificate and services.mumblersd.settings.private_key (or keep generateSelfSignedCerts = true).";
      }
    ];

    networking.firewall = lib.mkIf cfg.openFirewall {
      allowedTCPPorts = [ (cfg.settings.bind_port or 64738) ];
      allowedUDPPorts = [ (cfg.settings.udp_bind_port or (cfg.settings.bind_port or 64738)) ];
    };

    systemd.services.mumblersd = {
      description = "Mumblers Mumble server daemon";
      after = ["network-online.target"];
      wants = ["network-online.target"];
      wantedBy = ["multi-user.target"];

      preStart = lib.mkBefore ''
        set -euo pipefail

        state_dir="$STATE_DIRECTORY"
        mkdir -p "$state_dir"

        if ${lib.boolToString cfg.generateSelfSignedCerts}; then
          if [ ! -f "$state_dir/${selfSignedCertPath}" ] || [ ! -f "$state_dir/${selfSignedKeyPath}" ]; then
            ${cfg.package}/bin/mumblersd config --init --path "$state_dir/mumblers.toml" --force
          fi
        fi

        ${pkgs.coreutils}/bin/install -m 0600 -T ${generatedToml} "$state_dir/mumblers.toml"
      '';

      serviceConfig = {
        Type = "simple";
        DynamicUser = true;
        StateDirectory = "mumblersd";
        WorkingDirectory = "%S/mumblersd";

        ExecStart = "${cfg.package}/bin/mumblersd serve --config %S/mumblersd/mumblers.toml";
        Restart = "on-failure";
        RestartSec = 1;

        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictRealtime = true;

        # Allow binding to the configured ports and basic filesystem IO.
        RestrictAddressFamilies = ["AF_INET" "AF_INET6" "AF_UNIX"];
        SystemCallFilter = ["@system-service" "~@privileged" "~@resources"];
        UMask = "0077";
      };
    };
  };
}

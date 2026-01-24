{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = inputs:
    inputs.flake-parts.lib.mkFlake {inherit inputs;} {
      systems = ["x86_64-linux" "aarch64-darwin"];

      perSystem = {
        system,
        self',
        ...
      }: let
        overlays = [inputs.rust-overlay.overlays.default];
        pkgs = import inputs.nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);

        rustPlatform = pkgs.makeRustPlatform {
          cargo = rustToolchain;
          rustc = rustToolchain;
        };
      in {
        packages.mumblersd = rustPlatform.buildRustPackage {
          pname = cargoToml.package.name;
          version = cargoToml.package.version;
          src = pkgs.lib.cleanSource ./.;
          cargoLock = {
            lockFile = ./Cargo.lock;
          };
        };

        apps.mumblersd = {
          type = "app";
          program = "${self'.packages.mumblersd}/bin/mumblersd";
        };

        apps.default = self'.apps.mumblersd;

        devShells.default = pkgs.mkShell {
          buildInputs = [rustToolchain pkgs.libopus pkgs.cmake pkgs.python3];

          shellHook = ''
            export CMAKE_POLICY_VERSION_MINIMUM=3.5
            export PS1="(env:shell) $PS1"
          '';
        };
      };
    };
}

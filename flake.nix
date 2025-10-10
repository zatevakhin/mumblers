{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = inputs:
    inputs.flake-parts.lib.mkFlake {inherit inputs;} {
      systems = ["x86_64-linux" "aarch64-darwin"];

      perSystem = {system, ...}: let
        overlays = [inputs.rust-overlay.overlays.default];
        pkgs = import inputs.nixpkgs {
          inherit system overlays;
        };

        rustToolchain = (pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml).override {
          extensions = ["rust-src"];
        };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [rustToolchain pkgs.libopus pkgs.cmake];

          shellHook = ''
            export CMAKE_POLICY_VERSION_MINIMUM=3.5
            export PS1="(env:shell) $PS1"
          '';
        };
      };
    };
}

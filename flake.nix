{
  description = "Clusterflux development and verification environment";

  nixConfig = {
    extra-substituters = [ "https://clusterflux.cachix.org" ];
    extra-trusted-public-keys = [
      "clusterflux.cachix.org-1:bwo70JO4f9xI89aT6C9jwdeUUcno8y2hmKBUjBivyYs="
    ];
  };

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  inputs.rust-overlay = {
    url = "github:oxalica/rust-overlay";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; overlays = [ rust-overlay.overlays.default ]; };
          publicPackages = import ./packages.nix { inherit pkgs self; };
          privatePackages =
            if builtins.pathExists ./web/packages.nix then
              import ./web/packages.nix { inherit pkgs self; }
            else
              { };
        in
        publicPackages // privatePackages);

      checks = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; overlays = [ rust-overlay.overlays.default ]; };
          cargoDeny = assert pkgs.cargo-deny.version == "0.18.9"; pkgs.cargo-deny;
          cargoMachete = assert pkgs.cargo-machete.version == "0.9.1"; pkgs.cargo-machete;
          publicPackages = import ./packages.nix { inherit pkgs self; };
          compilerToolchain = builtins.fromJSON (builtins.readFile ./compiler-toolchain.json);
          checkedRust = pkgs.rust-bin.stable.${compilerToolchain.rust_release}.default.override {
            targets = [ compilerToolchain.wasm_target "x86_64-pc-windows-msvc" ];
          };
          checkedRustPlatform = pkgs.makeRustPlatform { cargo = checkedRust; rustc = checkedRust; };
        in
        {
          dependency-policy-tools = pkgs.runCommand "clusterflux-dependency-policy-tools" {
            nativeBuildInputs = [ cargoDeny cargoMachete ];
          } ''
            test "$(cargo-deny --version)" = "cargo-deny 0.18.9"
            test "$(cargo-machete --version)" = "0.9.1"
            mkdir -p "$out"
          '';
          toolchain-identity = pkgs.runCommand "clusterflux-toolchain-identity" {
            nativeBuildInputs = [ pkgs.nodejs_22 checkedRust ];
          } ''
            cd ${self}
            node scripts/check-compiler-toolchain.js
            mkdir -p "$out"
          '';
          public-workspace = checkedRustPlatform.buildRustPackage {
            pname = "clusterflux-public-workspace-check";
            version = "0.2.0";
            src = self;
            cargoLock.lockFile = ./Cargo.lock;
            nativeBuildInputs = [ pkgs.git ];
            cargoBuildFlags = [ "--workspace" ];
            cargoTestFlags = [ "--workspace" ];
            RUST_MIN_STACK = "2147483648";
            installPhase = ''mkdir -p "$out"'';
          };
          compiler-appliance = publicPackages.compiler-artifacts;
          package-layout = pkgs.runCommand "clusterflux-package-layout-check" { } ''
            test -x ${publicPackages.clusterflux-tools}/bin/clusterflux
            test -x ${publicPackages.clusterflux-tools}/bin/clusterflux-node
            test -s ${publicPackages.clusterflux-tools}/share/clusterflux/system-bundles.json
            test -s ${publicPackages.clusterflux-tools}/share/clusterflux/compiler-environment.json
            mkdir -p "$out"
          '';
          vscode = pkgs.runCommand "clusterflux-vscode-check" {
            nativeBuildInputs = [ pkgs.nodejs_22 ];
          } ''
            export CLUSTERFLUX_VSCODE_EXTENSION_ROOT=${self}/vscode-extension
            node ${self}/scripts/vscode-extension-smoke.js
            mkdir -p "$out"
          '';
          public-filter = pkgs.runCommand "clusterflux-public-filter-check" {
            nativeBuildInputs = [ pkgs.git pkgs.nodejs_22 pkgs.ripgrep ];
          } ''
            cd ${self}
            bash scripts/release-source-scan.sh
            node scripts/check-docs.js
            mkdir -p "$out"
          '';
        });

      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; overlays = [ rust-overlay.overlays.default ]; };
          compilerToolchain = builtins.fromJSON (builtins.readFile ./compiler-toolchain.json);
          checkedRust = pkgs.rust-bin.stable.${compilerToolchain.rust_release}.default.override {
            extensions = [ "clippy" "rustfmt" ];
            targets = [ compilerToolchain.wasm_target "x86_64-pc-windows-msvc" ];
          };
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              checkedRust
              (assert cargo-deny.version == "0.18.9"; cargo-deny)
              (assert cargo-machete.version == "0.9.1"; cargo-machete)
              cargo-xwin
              git
              jq
              llvmPackages.clang
              llvmPackages.lld
              llvmPackages.llvm
              nodejs_22
              podman
              zip
            ];
            shellHook = ''
              echo "Clusterflux shell: $(rustc --version), $(node --version), $(podman --version)"
            '';
          };
        });
    };
}

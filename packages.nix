{ pkgs, self }:
let
  compilerToolchain = builtins.fromJSON (builtins.readFile ./compiler-toolchain.json);
  checkedRust = pkgs.rust-bin.stable.${compilerToolchain.rust_release}.default.override {
    targets = [ compilerToolchain.wasm_target ];
  };
  checkedRustc = assert checkedRust.version == compilerToolchain.rust_release; checkedRust;
  checkedRustPlatform = pkgs.makeRustPlatform { cargo = checkedRust; rustc = checkedRust; };
  compiler-artifacts = checkedRustPlatform.buildRustPackage {
    pname = "clusterflux-system-compiler-artifacts";
    version = "0.2.0";
    src = self;
    cargoLock.lockFile = ./Cargo.lock;
    nativeBuildInputs = [ pkgs.lld ];
    doCheck = false;
    RUST_MIN_STACK = "1073741824";
    buildPhase = ''
      runHook preBuild
      cargo build --locked --release \
        --package clusterflux-system-compiler-driver \
        --target-dir target/compiler-native
      cargo build --locked --release \
        --target wasm32-unknown-unknown \
        --package clusterflux-sdk \
        --target-dir target/compiler-wasm
      runHook postBuild
    '';
    installPhase = ''
      runHook preInstall
      mkdir -p "$out/bin" "$out/sdk/deps"
      cp target/compiler-native/release/clusterflux-system-compiler-driver \
        "$out/bin/compile-workflow"
      cp target/compiler-wasm/wasm32-unknown-unknown/release/deps/libclusterflux-*.rlib \
        "$out/sdk/libclusterflux.rlib"
      cp target/compiler-wasm/wasm32-unknown-unknown/release/deps/libserde-*.rlib \
        "$out/sdk/libserde.rlib"
      cp target/compiler-wasm/wasm32-unknown-unknown/release/deps/* "$out/sdk/deps/"
      cp target/compiler-wasm/release/deps/*.so "$out/sdk/deps/"
      printf '%s\n' \
        'format=clusterflux-compiler-sdk-v1' \
        'rust_toolchain=${compilerToolchain.rust_release}' \
        'target=${compilerToolchain.wasm_target}' \
        'clusterflux_task_abi=1' \
        'serde_version=1.0.228' \
        'serde_features=derive' \
        > "$out/sdk/MANIFEST"
      (cd "$out/sdk" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
      runHook postInstall
    '';
  };

  compiler-root = pkgs.runCommand "clusterflux-system-compiler-root" { } ''
    mkdir -p "$out/opt/clusterflux/bin" "$out/opt/clusterflux/sdk" "$out/opt/rust/bin"
    cp ${compiler-artifacts}/bin/compile-workflow "$out/opt/clusterflux/bin/compile-workflow"
    cp -a ${compiler-artifacts}/sdk/. "$out/opt/clusterflux/sdk/"
    ln -s ${checkedRustc}/bin/rustc "$out/opt/rust/bin/rustc"
    ln -s ${pkgs.lld}/bin/wasm-ld "$out/opt/rust/bin/rust-lld"
  '';

  compiler-image-tar = pkgs.dockerTools.buildImage {
    name = "clusterflux-system-compiler";
    tag = "release";
    # Nixpkgs' gzip compressor uses parallel pigz and does not validate its
    # output. Keep archive construction separate from checked compression so a
    # corrupt stream can never be registered as the packaged compiler image.
    compressor = "none";
    copyToRoot = pkgs.buildEnv {
      name = "clusterflux-system-compiler-image-root";
      paths = [
        compiler-root
        pkgs.lld
        checkedRustc
        pkgs.stdenv.cc.cc.lib
        pkgs.glibc
      ];
      pathsToLink = [ "/bin" "/lib" "/lib64" "/opt" ];
    };
    config = {
      User = "65532:65532";
      WorkingDir = "/workspace";
      Labels = {
        "org.clusterflux.package-contract" = "system-bundles.json";
      };
    };
  };

  compiler-image = pkgs.runCommand "clusterflux-system-compiler-image.tar.gz" {
    nativeBuildInputs = [ pkgs.gzip ];
  } ''
    gzip -n -c ${compiler-image-tar} > "$out"
    gzip --test "$out"
  '';

  clusterflux-tools = checkedRustPlatform.buildRustPackage {
    pname = "clusterflux-tools";
    version = "0.2.0";
    src = self;
    cargoLock.lockFile = ./Cargo.lock;
    doCheck = false;
    # Nix's default `strip -S` keeps the ELF symbol table. These are standalone
    # release tools, so remove symbols as well as debug sections.
    stripAllList = [ "bin" ];
    nativeBuildInputs = [
      pkgs.git
      pkgs.lld
      pkgs.makeWrapper
      pkgs.jq
      pkgs.gnutar
      pkgs.gzip
    ];
    cargoBuildFlags = [
      "--package"
      "clusterflux-cli"
      "--package"
      "clusterflux-node"
      "--package"
      "clusterflux-coordinator"
      "--package"
      "clusterflux-relay"
      "--package"
      "clusterflux-dap"
    ];
    cargoTestFlags = [
      "--package"
      "clusterflux-cli"
      "--package"
      "clusterflux-node"
      "--package"
      "clusterflux-coordinator"
      "--package"
      "clusterflux-relay"
      "--package"
      "clusterflux-dap"
    ];
    # Optimized Wasmtime/LLVM codegen can exhaust a 1 GiB rustc worker stack.
    RUST_MIN_STACK = "2147483648";
    postInstall = ''
      mkdir -p "$out/share/clusterflux"
      cp ${compiler-image} "$out/share/clusterflux/system-compiler-image.oci.tar"
      ${pkgs.gzip}/bin/gzip --test "$out/share/clusterflux/system-compiler-image.oci.tar"
      image_config="$(${pkgs.gnutar}/bin/tar -xOf ${compiler-image} manifest.json | ${pkgs.jq}/bin/jq -r '.[0].Config')"
      image_digest="sha256:''${image_config%.json}"
      "$out/bin/clusterflux-system-package" write \
        --share-dir "$out/share/clusterflux" \
        --image-digest "$image_digest"
      "$out/bin/clusterflux-system-package" verify \
        --share-dir "$out/share/clusterflux"
      test -x "$out/bin/clusterflux"
      test -x "$out/bin/clusterflux-node"
      test -x "$out/bin/clusterflux-environment-setup"
      test -x "$out/bin/clusterflux-coordinator"
      test -x "$out/bin/clusterflux-relay"
      test -x "$out/bin/clusterflux-debug-dap"
      test -s "$out/share/clusterflux/system-compiler-image.oci.tar"
      test -s "$out/share/clusterflux/system-bundles.json"
      test -s "$out/share/clusterflux/compiler-environment.json"
      test -s "$out/share/clusterflux/compiler-image-digest.txt"
      for command in \
        clusterflux \
        clusterflux-node \
        clusterflux-environment-setup \
        clusterflux-coordinator \
        clusterflux-relay \
        clusterflux-debug-dap
      do
        ${pkgs.coreutils}/bin/timeout 5 "$out/bin/$command" --version >/dev/null
        ${pkgs.coreutils}/bin/timeout 5 "$out/bin/$command" --help >/dev/null
      done
      rm -f \
        "$out/bin/clusterflux-system-package" \
        "$out/bin/clusterflux-podman-smoke" \
        "$out/bin/clusterflux-wasmtime-smoke"
    '';
    postFixup =
      let
        runtimePath = pkgs.lib.makeBinPath [
          pkgs.cargo
          pkgs.git
          pkgs.lld
          pkgs.rustc
        ];
      in
      ''
        wrapProgram "$out/bin/clusterflux" --prefix PATH : ${runtimePath}
        wrapProgram "$out/bin/clusterflux-debug-dap" --prefix PATH : ${runtimePath}
      '';
    meta = {
      description = "Clusterflux CLI, node, coordinator, Iroh relay, and debugger adapter";
      mainProgram = "clusterflux";
    };
  };
in
{
  inherit clusterflux-tools compiler-artifacts compiler-image;
  clusterflux = clusterflux-tools;
  default = clusterflux-tools;
}

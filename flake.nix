{
  description = "sgx-ra: reproducible builds of Rust SGX enclaves (Intel SGX SDK 2.26, DCAP 1.23)";

  # Every input is pinned twice: by revision here (nixpkgs, crane) and by
  # narHash in flake.lock. `nix flake update` is a deliberate act: it changes
  # compilers and therefore MRENCLAVE.
  inputs = {
    # nixos-26.05 as of 2026-11-21.
    nixpkgs.url = "github:NixOS/nixpkgs/94c3211b0ee8ba969a3f12eb4aff8ba0f72971dd";
    crane.url = "github:ipetkov/crane/v0.24.0";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, crane, fenix }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      lib = pkgs.lib;

      # Exactly the toolchain of rust-toolchain.toml (channel 1.100.0 with
      # the x86_64-unknown-none target). The hash pins the rustup channel
      # manifest, which in turn pins every component tarball by sha256.
      rustToolchain = fenix.packages.${system}.fromToolchainFile {
        file = ./rust-toolchain.toml;
        sha256 = "sha256-MFHoWVcPZKjFrLnQnodCXbUsfZcofGfo9tV9fTTvklg=";
      };
      craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

      sgxSdk = pkgs.callPackage ./nix/sgx-sdk.nix { };
      dcap = pkgs.callPackage ./nix/dcap.nix { };
      # Intel's untrusted runtime + DCAP quote generation, for host apps.
      sgxRuntime = pkgs.callPackage ./nix/sgx-runtime.nix { };

      # Only what the build reads, so unrelated files (docs, target/, the
      # blueprint checkout) never change the derivation.
      src = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.unions [
          ./Cargo.toml
          ./Cargo.lock
          ./rust-toolchain.toml
          ./.cargo/config.toml
          ./crates
          ./examples
          ./enclave-sys
        ];
      };

      # All crates of Cargo.lock as fixed-output downloads (checksums from
      # Cargo.lock); the build itself runs --offline.
      cargoVendorDir = craneLib.vendorCargoDeps { inherit src; };

      # 1980-01-01T00:00:00Z, Nix's conventional epoch: the date sgx_sign
      # writes into SIGSTRUCT. Part of enclave.signed.so, not of MRENCLAVE.
      sourceDateEpoch = 315532800;

      # Reusable builder for any enclave crate of the workspace, e.g.
      #   mkEnclave { crate = "my-enclave"; }
      mkEnclave =
        { crate
        , enclaveConfig ? ./enclave-sys/Enclave.config.xml
          # A published key (see enclave-sys/README.md): it makes
          # enclave.signed.so reproducible and carries no trust. Clients pin
          # MRENCLAVE, never MRSIGNER.
        , signingKey ? ./enclave-sys/reproducible-signing-key.pem
        , mode ? "HW"
          # Relative to the repository root; see nix/enclave.nix.
        , edl ? "enclave-sys/Enclave.edl"
        }:
        pkgs.callPackage ./nix/enclave.nix {
          inherit craneLib sgxSdk src cargoVendorDir crate enclaveConfig
            signingKey sourceDateEpoch mode edl;
        };
      # Reusable builder for an untrusted host app crate (a binary on top of
      # sgx-ra-host), e.g. mkHostApp { crate = "my-host-app"; }
      mkHostApp = { crate }:
        pkgs.callPackage ./nix/host-app.nix {
          inherit craneLib sgxSdk sgxRuntime src cargoVendorDir crate
            sourceDateEpoch;
        };

      # OCI image (docker load < result) of a host app plus its enclave.
      mkHostImage = { hostApp, enclave, name, tag ? "latest" }:
        pkgs.callPackage ./nix/host-image.nix {
          inherit hostApp enclave sgxRuntime name tag;
        };
    in
    {
      lib.${system} = { inherit mkEnclave mkHostApp mkHostImage; };

      packages.${system} = rec {
        echo-enclave = mkEnclave { crate = "echo-enclave"; };
        # Simulation build, for the sim_host end-to-end test only.
        echo-enclave-sim = mkEnclave { crate = "echo-enclave"; mode = "SIM"; };
        enclave = echo-enclave;
        default = enclave;
        # Sealing example (docs/SEALING.md): needs the storage OCALLs.
        sealing-enclave = mkEnclave {
          crate = "sealing-enclave";
          edl = "enclave-sys/sealed-storage/Enclave.edl";
        };
        sealing-enclave-sim = mkEnclave {
          crate = "sealing-enclave";
          edl = "enclave-sys/sealed-storage/Enclave.edl";
          mode = "SIM";
        };

        echo-host-app = mkHostApp { crate = "echo-host-app"; };
        host-app = echo-host-app;
        echo-host-image = mkHostImage {
          hostApp = echo-host-app;
          enclave = echo-enclave;
          name = "sgx-ra-echo-host";
        };
        host-app-image = echo-host-image;

        sgx-runtime = sgxRuntime;
        sgx-sdk = sgxSdk;
        dcap-src = dcap.src;
        dcap-headers = dcap.headers;
        rust-toolchain = rustToolchain;
        cargo-vendor = cargoVendorDir;
      };

      devShells.${system}.default = pkgs.mkShell {
        packages = [ rustToolchain pkgs.libfaketime pkgs.openssl ];
        SGX_SDK = "${sgxSdk}";
        DCAP_INCLUDE = "${dcap.headers}/include";
        SOURCE_DATE_EPOCH = toString sourceDateEpoch;
      };
    };
}

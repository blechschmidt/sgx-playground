# Reproducible build of one sgx-ra enclave application (a no_std Rust
# `staticlib` crate of this workspace) into a signed SGX enclave.
#
# Pipeline: crane-vendored crates (from Cargo.lock) -> cargo build for
# x86_64-unknown-none with the pinned toolchain -> enclave-sys/build.sh
# (edger8r, cc, ld, sgx_sign gendata, sgx_sign sign).
#
# Outputs ($out):
#   enclave.signed.so   the loadable enclave
#   enclave.so          unsigned image (for re-signing with an operator key)
#   enclave.so.gendata  SIGSTRUCT signing material (sgx_sign gendata)
#   MRENCLAVE.txt       hex enclave measurement: the identity clients pin
#   MRSIGNER.txt        hex SHA-256 of the signing key modulus
#   SHA256SUMS          over all of the above
#
# Determinism measures (everything else is fixed by the flake inputs):
#   * rustc: codegen-units=1, fat LTO, no debuginfo, no incremental
#     (Cargo.toml [profile.release]); --remap-path-prefix for the source tree
#     and the vendored crates, so no build path reaches panic messages.
#   * C/ld: -ffile-prefix-map (build.sh), --build-id=none, unwrapped gcc and
#     binutils (no Nix cc-wrapper flags, rpaths or hardening defaults).
#   * sgx_sign: run under libfaketime at SOURCE_DATE_EPOCH, so the SIGSTRUCT
#     date is fixed; signed with a fixed key, and PKCS#1 v1.5 is
#     deterministic, so enclave.signed.so is bit-for-bit reproducible.
#   MRENCLAVE never depends on the signer: an operator can take enclave.so +
#   enclave.so.gendata, sign offline and `sgx_sign catsig` without changing
#   the measurement clients pin.
{ lib
, writeShellScript
, gcc-unwrapped
, binutils-unwrapped
, libfaketime
, coreutils
, which
, craneLib
, sgxSdk
, src
, cargoVendorDir
, crate
, enclaveConfig
, signingKey
  # EDL whose trusted bridge is linked in (enclave-sys/Enclave.edl, or
  # enclave-sys/sealed-storage/Enclave.edl for the storage OCALLs). A path
  # inside `src`, relative to its root.
, edl ? "enclave-sys/Enclave.edl"
, sourceDateEpoch
  # "SIM" links the SDK simulation runtime: for tests without SGX hardware
  # only, never accepted by a verifier (see enclave-sys/README.md).
, mode ? "HW"
, version ? "0.1.0"
}:

assert mode == "HW" || mode == "SIM";

let
  # The enclave is linked with plain gcc/ld: the Nix cc-wrapper would inject
  # hardening flags and rpaths into enclave.so. Unwrapped gcc still defaults
  # PT_INTERP to the store path of its glibc; set the conventional FHS path
  # (as any distribution gcc does) so no store path is measured. The SGX
  # loader ignores PT_INTERP. (-Wl options are ignored when compiling.)
  enclaveCc = writeShellScript "enclave-cc" ''
    exec ${gcc-unwrapped}/bin/gcc -B${binutils-unwrapped}/bin/ "$@" \
      -Wl,--dynamic-linker=/lib64/ld-linux-x86-64.so.2
  '';
  libName = "lib${builtins.replaceStrings [ "-" ] [ "_" ] crate}.a";
in
craneLib.mkCargoDerivation {
  pname = "${crate}-sgx${lib.optionalString (mode == "SIM") "-sim"}";
  inherit version src cargoVendorDir;

  # Nothing to share between derivations: the only artifact is one staticlib.
  cargoArtifacts = null;
  doInstallCargoArtifacts = false;
  doCheck = false;
  # The fixup phase would patchelf/strip enclave.so after it was measured
  # and signed. The outputs are final as installed.
  dontFixup = true;

  # `which`: sgx_edger8r runs `which gcc` and silently skips EDL
  # preprocessing when that fails.
  nativeBuildInputs = [ binutils-unwrapped libfaketime coreutils which ];

  SOURCE_DATE_EPOCH = toString sourceDateEpoch;
  LC_ALL = "C";
  TZ = "UTC";
  SGX_SDK = "${sgxSdk}";
  CC_ENCLAVE = "${enclaveCc}";

  buildPhaseCargoCommand = ''
    # Explicit RUSTFLAGS would replace the target rustflags of
    # .cargo/config.toml (portable crypto backends).
    unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS

    remap="target.x86_64-unknown-none.rustflags=[\"--remap-path-prefix=$PWD=/src\", \"--remap-path-prefix=${cargoVendorDir}=/cargo/vendor\"]"
    cargo build --release --locked --offline \
      --config "$remap" \
      --target x86_64-unknown-none -p ${crate}

    CC="$CC_ENCLAVE" bash enclave-sys/build.sh \
      --staticlib "target/x86_64-unknown-none/release/${libName}" \
      --sgx-sdk "$SGX_SDK" \
      --mode ${mode} \
      --config ${enclaveConfig} \
      --key ${signingKey} \
      --edl ${edl} \
      --out enclave-out
  '';

  installPhaseCommand = ''
    cd enclave-out
    expected_date=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y%m%d)

    # Cross-check the signed image against the measurement and the fixed
    # signing date before publishing anything.
    "$SGX_SDK/bin/x64/sgx_sign" dump -enclave enclave.signed.so \
      -dumpfile metadata.txt -cssfile sigstruct.bin >/dev/null
    hex() { od -An -tx1 -v -j "$2" -N "$3" "$1" | tr -d ' \n'; }
    mrenclave=$(hex enclave.so.gendata 188 32)
    [ "$mrenclave" = "$(tr -d '\n' < mrenclave.hex)" ]
    [ "$mrenclave" = "$(hex sigstruct.bin 960 32)" ] || {
      echo "SIGSTRUCT MRENCLAVE differs from gendata" >&2; exit 1; }
    cmp <(head -c 128 enclave.so.gendata) <(head -c 128 sigstruct.bin) || {
      echo "SIGSTRUCT header differs from gendata" >&2; exit 1; }
    date_le=$(hex sigstruct.bin 20 4)
    date_be=''${date_le:6:2}''${date_le:4:2}''${date_le:2:2}''${date_le:0:2}
    [ "$date_be" = "$expected_date" ] || {
      echo "SIGSTRUCT date $date_be, expected $expected_date (libfaketime not effective?)" >&2; exit 1; }
    # MRSIGNER = SHA-256 over the little-endian 384-byte modulus.
    mrsigner=$(head -c 512 sigstruct.bin | tail -c 384 | sha256sum | cut -d' ' -f1)

    mkdir -p $out
    install -m 0444 enclave.signed.so enclave.so enclave.so.gendata $out/
    echo "$mrenclave" > $out/MRENCLAVE.txt
    echo "$mrsigner" > $out/MRSIGNER.txt
    chmod 0444 $out/MRENCLAVE.txt $out/MRSIGNER.txt
    (cd $out && sha256sum enclave.signed.so enclave.so enclave.so.gendata MRENCLAVE.txt MRSIGNER.txt > SHA256SUMS)
    echo "${crate}: MRENCLAVE $mrenclave MRSIGNER $mrsigner"
  '';

  meta = {
    description = "SGX enclave image (${mode}) of the ${crate} crate";
    platforms = [ "x86_64-linux" ];
  };
}

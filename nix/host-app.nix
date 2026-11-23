# Build of an untrusted sgx-ra host app (a binary crate on top of
# sgx-ra-host with its `sgx` feature).
#
# The binary links Intel's libsgx_urts (nix/sgx-runtime.nix) through the
# Nix linker wrapper, which records the runtime's store path as RUNPATH. The
# DCAP library directory is compiled in as the default of --sgx-lib-dir
# (SGX_RA_DEFAULT_SGX_LIB_DIR), so the binary needs no environment.
#
# The host is not part of the trusted computing base and is not measured,
# but it is pinned by the same inputs as the enclave (flake.lock, toolchain,
# Cargo.lock), so it is reproducible as well.
{ craneLib
, which
, sgxSdk
, sgxRuntime
, src
, cargoVendorDir
, crate
, sourceDateEpoch
, version ? "0.1.0"
}:

craneLib.buildPackage {
  pname = crate;
  inherit version src cargoVendorDir;

  # One binary; no separate dependency derivation to share.
  cargoArtifacts = null;
  doInstallCargoArtifacts = false;
  # The workspace tests run without SGX (`cargo test`); they need no
  # separate run inside this derivation.
  doCheck = false;
  cargoExtraArgs = "--locked --offline -p ${crate} --features sgx";

  # sgx_edger8r runs `which gcc` and silently skips EDL preprocessing when
  # that fails.
  nativeBuildInputs = [ which ];

  SOURCE_DATE_EPOCH = toString sourceDateEpoch;
  SGX_SDK = "${sgxSdk}";
  SGX_MODE = "HW";
  SGX_URTS_LIB_DIR = "${sgxRuntime}/lib";
  SGX_RA_DEFAULT_SGX_LIB_DIR = "${sgxRuntime}/lib";

  postInstall = ''
    # Linked against Intel's runtime, found through RUNPATH.
    patchelf --print-rpath $out/bin/${crate} | grep -q '${sgxRuntime}/lib'
    $out/bin/${crate} --version
  '';

  meta = {
    description = "Untrusted SGX host app ${crate} (sgx-ra-host)";
    mainProgram = crate;
    platforms = [ "x86_64-linux" ];
  };
}

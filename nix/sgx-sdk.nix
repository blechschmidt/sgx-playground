# Intel SGX SDK 2.26 (2.26.100.0), Intel's prebuilt release for Ubuntu 24.04:
# the same installer the blueprint image uses
# (sgx-playground/containers/Dockerfile.build), so the trusted runtime
# libraries linked into the enclave are Intel's exact bits.
#
# The download is a fixed-output derivation (sha256 below). The installer is
# a shell header followed by a gzipped tarball; we unpack the payload directly
# instead of running Intel's interactive install script, and patch the two
# host tools we run (sgx_edger8r, sgx_sign) to the pinned glibc/libstdc++.
# The trusted static libraries (lib64/libsgx_t*.a) are copied unmodified.
{ lib, stdenv, fetchurl, autoPatchelfHook }:

stdenv.mkDerivation (finalAttrs: {
  pname = "intel-sgx-sdk";
  version = "2.26.100.0";

  src = fetchurl {
    url = "https://download.01.org/intel-sgx/sgx-linux/2.26/distro/ubuntu24.04-server/sgx_linux_x64_sdk_${finalAttrs.version}.bin";
    sha256 = "6a067a46463f7bae11310d47fbcdf199e405dfbd100e10105dee415a7a496b0d";
  };

  nativeBuildInputs = [ autoPatchelfHook ];
  # sgx_sign: libstdc++, libgcc_s, libc. sgx_edger8r: libm, libc.
  buildInputs = [ stdenv.cc.cc.lib ];

  # Keep Intel's layout and bits: no lib64 -> lib move, no stripping, no
  # RPATH shrinking. Only the build tools are patched (postFixup).
  dontMoveLib64 = true;
  dontStrip = true;
  dontPatchELF = true;
  dontPatchShebangs = true;
  dontAutoPatchelf = true;

  unpackPhase = ''
    runHook preUnpack
    lines=$(sed -n 's/^NR_SCRIPT_LINES=\([0-9]*\)$/\1/p' "$src")
    [ -n "$lines" ]
    mkdir payload
    tail -n "+$lines" "$src" | tar -xz -C payload
    runHook postUnpack
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out
    cp -r payload/package/{bin,include,lib64,pkgconfig,licenses,buildenv.mk} $out/
    chmod -R u+w $out
    # Sample code and the gdb plugin are not needed; keep the closure small.
    rm -rf $out/lib64/gdb-sgx-plugin
    runHook postInstall
  '';

  # Only the host tools get an interpreter/RPATH for the pinned glibc and
  # libstdc++; the trusted archives (and the untrusted *.so, unused here)
  # stay byte-identical to Intel's release.
  postFixup = ''
    autoPatchelf $out/bin/x64/sgx_edger8r $out/bin/x64/sgx_sign
    # Smoke test: both tools start (their help/version paths exit non-zero).
    edger8r_help=$($out/bin/x64/sgx_edger8r --help 2>&1 || true)
    grep -q -- '--trusted-dir' <<< "$edger8r_help"
    sign_version=$($out/bin/x64/sgx_sign -version 2>&1 || true)
    echo "$sign_version"
    grep -q '2\.26\.100' <<< "$sign_version"
  '';

  meta = {
    description = "Intel SGX SDK ${finalAttrs.version} (prebuilt, Ubuntu 24.04 release)";
    homepage = "https://github.com/intel/linux-sgx";
    license = lib.licenses.bsd3;
    platforms = [ "x86_64-linux" ];
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
  };
})

# Intel's SGX runtime for the untrusted host: the untrusted runtime
# (libsgx_urts 2.26) and the DCAP 1.23 quote generation stack
# (libsgx_dcap_ql, QE3/PCE logic, the quote provider library) together with
# Intel's signed architectural enclaves (QE3, PCE, ID enclave).
#
# These are Intel's prebuilt Ubuntu 24.04 (noble) packages, the same
# versions the blueprint's server image installs from Intel's apt
# repository (sgx-playground/containers/Dockerfile.build). Each .deb is a
# fixed-output download pinned by the SHA-256 from the repository's
# Packages index (dists/noble/main/binary-amd64/Packages).
#
# The signed enclave images are copied bit for bit: QE3/PCE are measured
# and signed by Intel, and any change would make them fail to load. Only
# the ordinary shared libraries get an interpreter-free RUNPATH to the
# pinned glibc/libstdc++, plus curl for the quote provider, which
# dlopen()s libcurl.so.4 to reach the PCCS.
{ lib, stdenv, fetchurl, dpkg, autoPatchelfHook, curl }:

let
  repo = "https://download.01.org/intel-sgx/sgx_repo/ubuntu/pool/main";
  deb = path: sha256: fetchurl { url = "${repo}/${path}"; inherit sha256; };
  debs = [
    (deb "libs/libsgx-enclave-common/libsgx-enclave-common_2.26.100.0-noble1_amd64.deb"
      "7d5f2be3511feeb7b45a68256520a6fe4ec1d47a0977586dec16580f14a794db")
    (deb "libs/libsgx-urts/libsgx-urts_2.26.100.0-noble1_amd64.deb"
      "3f8329f0e93605efef20f37d40aa10301d065bac2997f5a1f76ab1069a4a9ce8")
    (deb "utils/libsgx-ae-pce/libsgx-ae-pce_2.26.100.0-noble1_amd64.deb"
      "f16630b2b9919ee295713debb5665712718df11a8cfff3f9fcb99b23caa0c19a")
    (deb "libs/libsgx-ae-qe3/libsgx-ae-qe3_1.23.100.0-noble1_amd64.deb"
      "0397288a0a6f1b1eb31a2f6ea1f5e1cbea6416b30d1641c8705641b23ccba00c")
    (deb "libs/libsgx-ae-id-enclave/libsgx-ae-id-enclave_1.23.100.0-noble1_amd64.deb"
      "d618d71d6b297a8e29e5573cb6e042d1446af5f41496ebdee152f6977dd74d22")
    (deb "libs/libsgx-pce-logic/libsgx-pce-logic_1.23.100.0-noble1_amd64.deb"
      "0caf5fd24c5e2c0c0fa77b460152c252e1d417804b77fdc6944284d67fd3eec4")
    (deb "libs/libsgx-qe3-logic/libsgx-qe3-logic_1.23.100.0-noble1_amd64.deb"
      "ea7922c009ebd809039dc9d89c90348c5354c6ff4b403a2c66fe8db91ef74d8e")
    (deb "libs/libsgx-dcap-ql/libsgx-dcap-ql_1.23.100.0-noble1_amd64.deb"
      "5805406c1819e495240e7111caf7775bbd1623016ec3db5db5931bac6728248a")
    (deb "libs/libsgx-dcap-default-qpl/libsgx-dcap-default-qpl_1.23.100.0-noble1_amd64.deb"
      "6c58ca0b3e7aeaaebd6d1b8e440a9fd7b728c337bca40eacf8e4f95c3e3e021e")
  ];
in
stdenv.mkDerivation {
  pname = "intel-sgx-dcap-runtime";
  version = "2.26.100.0-dcap1.23.100.0";

  srcs = debs;
  nativeBuildInputs = [ dpkg autoPatchelfHook ];
  buildInputs = [ stdenv.cc.cc.lib ];

  dontConfigure = true;
  dontBuild = true;
  # The signed enclaves must stay byte-identical: no stripping, no generic
  # ELF patching; autoPatchelf runs on the plain libraries only (postFixup).
  dontStrip = true;
  dontPatchELF = true;
  dontAutoPatchelf = true;

  unpackPhase = ''
    runHook preUnpack
    mkdir root
    for d in $srcs; do dpkg-deb -x "$d" root; done
    runHook postUnpack
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/lib $out/etc $out/share/doc
    cp -P root/usr/lib/x86_64-linux-gnu/* $out/lib/
    # The QCNL configuration. It points at a PCCS on localhost:8081;
    # deployments override it by mounting their own file over
    # /etc/sgx_default_qcnl.conf (the path is compiled into the library).
    cp root/etc/sgx_default_qcnl.conf $out/etc/
    cp -r root/usr/share/doc/* $out/share/doc/
    # Link-time names for the host build (-lsgx_urts).
    test -e $out/lib/libsgx_urts.so
    runHook postInstall
  '';

  postFixup = ''
    libs=()
    for f in $out/lib/*.so*; do
      case "$f" in *.signed.so*) continue ;; esac
      [ -L "$f" ] || libs+=("$f")
    done
    # The libraries depend on each other (dcap_ql -> qe3/pce logic -> urts).
    addAutoPatchelfSearchPath $out/lib
    autoPatchelf "''${libs[@]}"
    # The QCNL loads libcurl.so.4 with dlopen(), which searches the
    # caller's RUNPATH: add curl to it (auto-patchelf only covers NEEDED).
    test -e ${curl.out}/lib/libcurl.so.4
    qcnl=$(readlink -f $out/lib/libsgx_default_qcnl_wrapper.so.1)
    patchelf --add-rpath ${curl.out}/lib "$qcnl"
    patchelf --print-rpath "$qcnl" | grep -q '${curl.out}/lib'
  '';

  # Proof that the architectural enclaves are Intel's bits.
  doInstallCheck = true;
  installCheckPhase = ''
    for d in $srcs; do
      dpkg-deb -x "$d" check
    done
    for f in $out/lib/*.signed.so.*; do
      [ -L "$f" ] && continue
      cmp "$f" "check/usr/lib/x86_64-linux-gnu/$(basename "$f")"
    done
  '';

  meta = {
    description = "Intel SGX untrusted runtime 2.26 and DCAP 1.23 quote generation (prebuilt, Ubuntu 24.04 packages)";
    homepage = "https://github.com/intel/confidential-computing.tee.dcap";
    license = lib.licenses.bsd3;
    platforms = [ "x86_64-linux" ];
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
  };
}

# Intel SGX DCAP 1.23 (tag DCAP_1.23), the version the remote executor runs
# (sgx-playground/containers/Dockerfile.build: DCAP_VERSION=DCAP_1.23).
#
# The enclave itself links nothing from DCAP; the quote format and the
# quoting-library API matter to the untrusted host (sgx-ra-host) and to the
# verifier. `src` is the pinned source tree (fixed-output, hash below);
# `headers` collects the public C headers of the quote generation and
# verification libraries.
{ lib, stdenvNoCC, fetchFromGitHub }:

let
  version = "1.23";
  src = fetchFromGitHub {
    # Formerly intel/SGXDataCenterAttestationPrimitives. Pinned by commit
    # (= tag DCAP_1.23) so a moved tag cannot change the input.
    owner = "intel";
    repo = "confidential-computing.tee.dcap";
    rev = "e880e54c8f35d44a4763e08dff32a046c8ef2230";
    hash = "sha256-1WlJSQ7/WzsRgphBa2hU7xLd0hLWpuYCtdJerCqkCs4=";
  };
in
{
  inherit src version;

  headers = stdenvNoCC.mkDerivation {
    pname = "intel-sgx-dcap-headers";
    inherit version src;
    dontConfigure = true;
    dontBuild = true;
    installPhase = ''
      runHook preInstall
      mkdir -p $out/include
      for d in QuoteGeneration/quote_wrapper/common/inc \
               QuoteGeneration/quote_wrapper/ql/inc \
               QuoteGeneration/pce_wrapper/inc \
               QuoteVerification/QvE/Include \
               QuoteVerification/dcap_quoteverify/inc; do
        [ -d "$d" ] || { echo "missing $d in DCAP ${version}" >&2; exit 1; }
        cp -n "$d"/*.h $out/include/
      done
      test -f $out/include/sgx_dcap_ql_wrapper.h
      test -f $out/include/sgx_quote_3.h
      runHook postInstall
    '';
    meta = {
      description = "Public headers of Intel SGX DCAP ${version}";
      homepage = "https://github.com/intel/SGXDataCenterAttestationPrimitives";
      license = lib.licenses.bsd3;
    };
  };
}

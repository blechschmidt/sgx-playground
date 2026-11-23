# OCI image of an untrusted host app together with the enclave it serves.
#
#   /app/enclave.signed.so          the enclave (from mkEnclave), WorkingDir
#   /app/MRENCLAVE.txt              its measurement, for operators
#   /etc/sgx_default_qcnl.conf      QCNL config (PCCS URL); mount your own
#   Entrypoint                      the host app: one session on stdin/stdout
#
# Run it with the SGX device nodes (QE3 and our enclave need
# /dev/sgx_enclave; the PCE needs /dev/sgx_provision):
#
#   docker run --rm -i \
#     --device /dev/sgx_enclave --device /dev/sgx_provision \
#     -v /etc/sgx_default_qcnl.conf:/etc/sgx_default_qcnl.conf:ro \
#     --network host  sgx-ra-echo-host:latest
#
# The image is a pure function of its inputs (layer timestamps are the
# epoch), so it is reproducible like everything else in the flake.
{ dockerTools
, runCommand
, cacert
, hostApp
, enclave
, sgxRuntime
, name
, tag ? "latest"
}:

let
  exe = "${hostApp}/bin/${hostApp.meta.mainProgram}";
  root = runCommand "${name}-root" { } ''
    mkdir -p $out/app $out/etc
    cp ${enclave}/enclave.signed.so ${enclave}/MRENCLAVE.txt $out/app/
    cp ${sgxRuntime}/etc/sgx_default_qcnl.conf $out/etc/
  '';
in
dockerTools.buildLayeredImage {
  inherit name tag;
  contents = [ root ];
  # QCNL caches collateral under $HOME; give it a writable /tmp.
  extraCommands = ''
    mkdir -m 1777 tmp
  '';
  config = {
    Entrypoint = [ exe ];
    WorkingDir = "/app";
    Env = [
      "HOME=/tmp"
      "SGX_RA_SGX_LIB_DIR=${sgxRuntime}/lib"
      # libcurl (QCNL -> PCCS) verifies the PCCS certificate when
      # use_secure_cert is true.
      "SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt"
      "CURL_CA_BUNDLE=${cacert}/etc/ssl/certs/ca-bundle.crt"
    ];
    Labels = {
      "org.opencontainers.image.title" = name;
      "org.opencontainers.image.description" =
        "Untrusted SGX host ${hostApp.pname}; the enclave's MRENCLAVE is in /app/MRENCLAVE.txt";
    };
  };
}

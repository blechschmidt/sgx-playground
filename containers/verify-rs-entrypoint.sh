#!/bin/sh
# Entrypoint of the verify-rs compose service: runs echo-client against the
# configured executor, with the expected MRENCLAVE from the nix-build
# service's output. Extra arguments are appended (e.g. `-m TEXT`, `-i`).
#
#   SGX_RA_HOST       executor host      (sgx-playground.blechschmidt.io)
#   SGX_RA_PORT       executor port      (443)
#   SGX_RA_TRANSPORT  --insecure-tls | --plaintext | --tls-ca=PEM | tls
#                     (--insecure-tls: the public executor's certificate
#                     has expired; TLS is transport only, see PROTOCOL.md §1)
#   SGX_RA_GENDATA    enclave.so.gendata of the local build
#                     (/enclave/enclave.so.gendata)
#   SGX_RA_PCCS_URL   collateral service (https://127.0.0.1:8081, the
#                     local PCCS; https://api.trustedservices.intel.com
#                     for Intel's PCS)
#   SGX_RA_PCCS_CA    CA of an HTTPS PCCS (/shared/ca.crt, written by
#                     prepare-pccs); `none` or a missing file: use the
#                     Mozilla roots (Intel's PCS)
set -eu

gendata="${SGX_RA_GENDATA:-/enclave/enclave.so.gendata}"
pccs_ca="${SGX_RA_PCCS_CA:-none}"
transport="${SGX_RA_TRANSPORT:---insecure-tls}"

if [ ! -f "$gendata" ]; then
    echo "verify-rs: $gendata missing; run \`docker compose run --rm nix-build\` first" >&2
    exit 1
fi

set -- --gendata-path "$gendata" "$@"
set -- --pccs-url "${SGX_RA_PCCS_URL:-https://127.0.0.1:8081}" "$@"
if [ -f "$pccs_ca" ]; then
    set -- --pccs-ca "$pccs_ca" "$@"
fi
if [ "$transport" != tls ]; then
    set -- "$transport" "$@"
fi

exec echo-client \
    --host "${SGX_RA_HOST:-sgx-playground.blechschmidt.io}" \
    --port "${SGX_RA_PORT:-443}" \
    "$@"

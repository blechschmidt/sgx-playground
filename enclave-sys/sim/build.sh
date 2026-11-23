#!/usr/bin/env bash
# Builds the simulation-mode enclave and the test host sim_host.
#
#   enclave-sys/sim/build.sh [--sgx-sdk DIR] [--crate NAME] [--staticlib PATH] [--out DIR]
#
# Run inside an environment with the SGX SDK (e.g. the blueprint
# sgx-playground-server image). Produces in --out (default
# target/enclave/NAME-sim): enclave.signed.so (SIM) and sim_host, linked
# against libsgx_urts_sim. See enclave-sys/README.md for running the
# end-to-end test.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
sgx_sdk="${SGX_SDK:-/opt/intel/sgxsdk}"
crate=echo-enclave
out=
args=()
while [ $# -gt 0 ]; do
    case "$1" in
        --sgx-sdk) sgx_sdk="$2"; shift 2 ;;
        --crate) crate="$2"; args+=("$1" "$2"); shift 2 ;;
        --out) out="$2"; shift 2 ;;
        *) args+=("$1" "$2"); shift 2 ;;
    esac
done
[ -n "$out" ] || out="$root/target/enclave/$crate-sim"
"$here/../build.sh" --mode SIM --sgx-sdk "$sgx_sdk" --out "$out" "${args[@]}"
out="$(cd "$out" && pwd)"
"$sgx_sdk/bin/x64/sgx_edger8r" --untrusted "$here/../Enclave.edl" \
    --search-path "$sgx_sdk/include" --untrusted-dir "$out/gen" >&2
"${CC:-cc}" -O2 -Wall -Wextra -I"$sgx_sdk/include" -I"$out/gen" \
    "$here/sim_host.c" "$out/gen/Enclave_u.c" -o "$out/sim_host" \
    -L"$sgx_sdk/lib64" -lsgx_urts_sim -Wl,--disable-new-dtags,-rpath,"$sgx_sdk/lib64:$sgx_sdk/sdk_libs"
echo "sim/build.sh: $out/sim_host" >&2

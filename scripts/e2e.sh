#!/usr/bin/env bash
# End-to-end run of the whole flow, with a PASS / FAIL / BLOCKED verdict per
# check and a Markdown report.
#
#   scripts/e2e.sh [--target HOST:PORT] [--transport tls|insecure-tls|plaintext]
#                  [--pccs-url URL] [--pccs-ca PEM] [--allow-tcb STATUS,...]
#                  [--compose] [--skip-build] [--report FILE]
#
# Stages:
#   1. build     reproducible enclave build (scripts/nix-build-enclave.sh);
#                with --compose via `docker compose run nix-build` as well
#   2. offline   the MITM proxy's attacks work against a software endpoint;
#                a modified enclave source gives another MRENCLAVE, and the
#                client refuses it (needs Docker, no SGX)
#   3. sim       real enclave code in SGX simulation mode: handshake,
#                substituted key, tampered records (skipped when the
#                simulation build or the sgx-playground-server image is
#                missing)
#   4. live      against the executor (default: the public one): positive
#                flow with DCAP verification, MRENCLAVE match, report_data
#                binding and encrypted echo; then MRENCLAVE mismatch from
#                modified sources, a substituted public key, tampered
#                records (MITM proxy in examples/echo-client/tests/e2e.rs)
#   5. compose   with --compose: `docker compose run verify-rs` against the
#                same target (with --pccs-ca it uses the pccs service's CA
#                from the `shared` volume)
#
# BLOCKED means the executor sent a DCAP error text instead of a quote
# (client exit code 3): nothing was verified, so it is not a pass.
# Exit code: 0 all passed, 1 something failed, 3 nothing failed but some
# checks were blocked.
#
# A local SGX host: `docker compose --profile local-sgx up -d host-app`,
# then `scripts/e2e.sh --target 127.0.0.1:7000 --transport plaintext
# --pccs-url https://127.0.0.1:8081 --pccs-ca <ca.crt>`.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
export PATH="$HOME/.cargo/bin:$PATH"
# Without buildx, compose can only build with the classic builder.
docker buildx version >/dev/null 2>&1 || export DOCKER_BUILDKIT=0

target="sgx-playground.blechschmidt.io:443"
transport=insecure-tls
pccs_url=
pccs_ca=
allow_tcb=
use_compose=0
skip_build=0
report="$root/target/e2e/report.md"

while [ $# -gt 0 ]; do
    case "$1" in
        --target) target="$2"; shift 2 ;;
        --transport) transport="$2"; shift 2 ;;
        --pccs-url) pccs_url="$2"; shift 2 ;;
        --pccs-ca) pccs_ca="$2"; shift 2 ;;
        --allow-tcb) allow_tcb="$2"; shift 2 ;;
        --compose) use_compose=1; shift ;;
        --skip-build) skip_build=1; shift ;;
        --report) report="$2"; shift 2 ;;
        -h|--help) sed -n '2,/^set -uo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "e2e.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
done

logs="$root/target/e2e/logs"
mkdir -p "$logs"
rm -f "$logs"/*.log
results=()
failed=0
blocked=0

# record NAME VERDICT DETAIL
record() {
    results+=("| $1 | **$2** | $3 |")
    echo "e2e: [$2] $1 - $3" >&2
    case "$2" in
        FAIL) failed=1 ;;
        BLOCKED) blocked=1 ;;
    esac
}

# run_test LOGNAME CARGO_TEST_ARGS... : runs one cargo test, records it.
run_test() {
    local name="$1"; shift
    local log="$logs/$name.log"
    if "$@" >"$log" 2>&1; then
        record "$name" PASS "log: target/e2e/logs/$name.log"
    elif grep -q "BLOCKED:" "$log"; then
        record "$name" BLOCKED "executor returned no quote (log: target/e2e/logs/$name.log)"
    else
        record "$name" FAIL "log: target/e2e/logs/$name.log"
    fi
}

host="${target%:*}"
port="${target##*:}"
export SGX_RA_E2E_HOST="$host" SGX_RA_E2E_PORT="$port" SGX_RA_E2E_TRANSPORT="$transport"
[ -n "$pccs_url" ] && export SGX_RA_E2E_PCCS_URL="$pccs_url"
[ -n "$pccs_ca" ] && export SGX_RA_E2E_PCCS_CA="$pccs_ca"
[ -n "$allow_tcb" ] && export SGX_RA_E2E_ALLOW_TCB="$allow_tcb"

# 1. Build.
enclave_dir="$root/target/nix-enclave/enclave"
if [ "$skip_build" -eq 0 ]; then
    if scripts/nix-build-enclave.sh --out "$enclave_dir" >"$logs/build.log" 2>&1; then
        record build PASS "MRENCLAVE $(cat "$enclave_dir/MRENCLAVE.txt")"
    else
        record build FAIL "log: target/e2e/logs/build.log"
    fi
    if [ "$use_compose" -eq 1 ]; then
        if docker compose run --rm nix-build >"$logs/compose-nix-build.log" 2>&1 \
            && grep -q "MRENCLAVE $(cat "$enclave_dir/MRENCLAVE.txt")" "$logs/compose-nix-build.log"; then
            record compose-nix-build PASS "same MRENCLAVE as scripts/nix-build-enclave.sh"
        else
            record compose-nix-build FAIL "log: target/e2e/logs/compose-nix-build.log"
        fi
    fi
fi
if [ ! -f "$enclave_dir/enclave.so.gendata" ]; then
    record build FAIL "no $enclave_dir/enclave.so.gendata"
    exit 1
fi
export SGX_RA_E2E_GENDATA="$enclave_dir/enclave.so.gendata"

echo "e2e: compiling tests" >&2
cargo test -q -p echo-client -p sgx-ra-client --no-run >"$logs/compile.log" 2>&1 \
    || { record compile FAIL "log: target/e2e/logs/compile.log"; exit 1; }

e2e() { cargo test -q -p echo-client --test e2e -- --ignored --exact "$1" --nocapture; }

# 2. Offline.
run_test mitm-proxy-selftest cargo test -q -p echo-client --test e2e mitm_
run_test offline-modified-source-changes-mrenclave e2e modified_enclave_source_changes_mrenclave

# 3. Simulation.
sim_dir="$root/target/enclave/echo-enclave-sim"
if [ -f "$sim_dir/sim_host" ] && docker image inspect sgx-playground-server:latest >/dev/null 2>&1; then
    run_test sim-enclave env \
        SGX_RA_SIM_HOST="docker run --rm -i -v $sim_dir:/e sgx-playground-server:latest /e/sim_host /e/enclave.signed.so" \
        SGX_RA_SIM_MRENCLAVE="$(cat "$sim_dir/mrenclave.hex")" \
        cargo test -q -p sgx-ra-client --test sim_enclave -- --ignored
else
    record sim-enclave SKIPPED "no simulation build (enclave-sys/README.md#testing-without-sgx-hardware)"
fi

# 4. Live.
for t in live_attested_echo live_relay_without_attack_works live_modified_enclave_source_is_rejected \
         live_substituted_public_key_is_rejected live_tampered_enclave_record_fails_decryption \
         live_tampered_client_record_is_rejected_by_enclave; do
    run_test "${t//_/-}" e2e "$t"
done

# 5. Compose client.
if [ "$use_compose" -eq 1 ]; then
    compose_transport="--$transport"
    [ "$transport" = tls ] && compose_transport=tls
    SGX_RA_HOST="$host" SGX_RA_PORT="$port" SGX_RA_TRANSPORT="$compose_transport" \
        SGX_RA_PCCS_URL="${pccs_url:-https://api.trustedservices.intel.com}" \
        SGX_RA_PCCS_CA="$(if [ -n "$pccs_ca" ]; then echo /shared/ca.crt; else echo none; fi)" \
        docker compose run --rm verify-rs >"$logs/compose-verify-rs.log" 2>&1
    case $? in
        0) record compose-verify-rs PASS "log: target/e2e/logs/compose-verify-rs.log" ;;
        3) blocked=1; record compose-verify-rs BLOCKED "executor returned no quote (log: target/e2e/logs/compose-verify-rs.log)" ;;
        *) record compose-verify-rs FAIL "log: target/e2e/logs/compose-verify-rs.log" ;;
    esac
fi

mkdir -p "$(dirname "$report")"
{
    echo "# sgx-ra end-to-end report"
    echo
    echo "* date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "* target: \`$target\` ($transport), collateral: ${pccs_url:-Intel PCS}"
    echo "* local MRENCLAVE: \`$(cat "$enclave_dir/MRENCLAVE.txt")\`"
    echo
    echo "| check | verdict | detail |"
    echo "|---|---|---|"
    printf '%s\n' "${results[@]}"
} >"$report"
echo "e2e: report in $report" >&2

if [ "$failed" -ne 0 ]; then exit 1; fi
if [ "$blocked" -ne 0 ]; then exit 3; fi
exit 0

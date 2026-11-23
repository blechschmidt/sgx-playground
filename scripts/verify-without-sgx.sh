#!/usr/bin/env bash
# Attests the remote enclave from an environment without any SGX: the
# client runs in a plain Debian container with no SGX device, no AESM, no
# SGX SDK/DCAP library, no local PCCS, no capabilities and its own network
# namespace. It proves that a verifier needs nothing from SGX: quote
# verification is pure Rust against the pinned Intel SGX Root CA, with
# collateral from Intel's PCS over the Internet.
#
#   scripts/verify-without-sgx.sh [--target HOST:PORT] [--gendata FILE]
#                                 [--allow-tcb STATUS]... [--skip-image]
#                                 [-- ECHO_CLIENT_ARGS...]
#
#   --target HOST:PORT  executor (default sgx-playground.blechschmidt.io:443)
#   --gendata FILE      enclave.so.gendata of the reproducible build
#                       (default target/nix-enclave/enclave/enclave.so.gendata;
#                       built with scripts/nix-build-enclave.sh if missing,
#                       which needs only Docker)
#   --allow-tcb STATUS  passed on as --allow-tcb-status (repeatable): accept
#                       only UpToDate and these TCB statuses. By default
#                       echo-client accepts every status except Revoked.
#   --skip-image        reuse sgx-ra-verify-rs:latest instead of rebuilding
#
# Exit code: that of echo-client (0 verified and echoed), or 4 if the
# environment check fails (the container could see SGX after all).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
docker buildx version >/dev/null 2>&1 || export DOCKER_BUILDKIT=0

image=sgx-ra-verify-rs:latest
target="sgx-playground.blechschmidt.io:443"
gendata="$root/target/nix-enclave/enclave/enclave.so.gendata"
build_image=1
client_args=()

while [ $# -gt 0 ]; do
    case "$1" in
        --target) target="$2"; shift 2 ;;
        --gendata) gendata="$2"; shift 2 ;;
        --allow-tcb) client_args+=(--allow-tcb-status "$2"); shift 2 ;;
        --skip-image) build_image=0; shift ;;
        --) shift; client_args+=("$@"); break ;;
        -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "verify-without-sgx.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [ ! -f "$gendata" ]; then
    echo "== $gendata missing: running the reproducible Nix build" >&2
    scripts/nix-build-enclave.sh >&2
fi
if [ "$build_image" -eq 1 ]; then
    echo "== building $image (containers/Dockerfile.verify-rs)" >&2
    docker build -q -f containers/Dockerfile.verify-rs -t "$image" . >&2
fi

# Only the gendata goes in, world-readable (the container runs as nobody).
# Under target/ rather than mktemp: the Docker daemon may not share our /tmp.
work="$root/target/verify-without-sgx"
rm -rf "$work"
mkdir -p "$work"
install -m 0644 "$gendata" "$work/enclave.so.gendata"
chmod 0755 "$work"

# Inside the container: show that there is no SGX, then run the client.
check='
fail() { echo "[FAIL] $*" >&2; exit 4; }
echo "== environment of the verifier" >&2
if ls /dev/sgx* /dev/isgx >/dev/null 2>&1; then fail "an SGX device is visible"; fi
echo "[OK] no SGX device (/dev/sgx*, /dev/isgx)" >&2
if [ -e /var/run/aesmd/aesm.socket ]; then fail "the AESM socket is visible"; fi
echo "[OK] no AESM service (/var/run/aesmd)" >&2
if find / -xdev \( -name "libsgx*" -o -name "libdcap*" -o -name "libsgx_dcap*" \) 2>/dev/null | grep -q .; then
    fail "SGX libraries are installed"
fi
echo "[OK] no SGX SDK / DCAP / quote provider library installed" >&2
if ldd /usr/local/bin/echo-client | grep -i sgx; then fail "echo-client links an SGX library"; fi
echo "[OK] echo-client links only: $(ldd /usr/local/bin/echo-client | sed "s/ (0x.*//; s/=>.*//" | tr -s " \t\n" " ")" >&2
echo "[OK] no capabilities ($(grep CapEff /proc/self/status | tr -s "\t" " ")), own network namespace, read-only root" >&2
echo "== attesting $SGX_RA_HOST:$SGX_RA_PORT" >&2
exec /usr/local/bin/verify-rs "$@"
'

set +e
docker run --rm \
    --network bridge \
    --cap-drop ALL --security-opt no-new-privileges \
    --read-only --tmpfs /tmp \
    -v "$work:/enclave:ro" \
    -e SGX_RA_HOST="${target%:*}" -e SGX_RA_PORT="${target##*:}" \
    -e SGX_RA_TRANSPORT=tls \
    -e SGX_RA_PCCS_URL=https://api.trustedservices.intel.com \
    -e SGX_RA_PCCS_CA=none \
    --entrypoint /bin/sh "$image" -c "$check" sh "${client_args[@]}"
status=$?
set -e
echo "== echo-client exit code $status" >&2
exit "$status"

#!/usr/bin/env bash
# Builds an enclave with containers/Dockerfile.nix-build and extracts the
# artifacts; optionally proves bit-for-bit reproducibility.
#
#   scripts/nix-build-enclave.sh [--enclave ATTR] [--out DIR] [--verify]
#
#   --enclave ATTR  flake attribute (default: enclave = echo-enclave)
#   --out DIR       artifact directory (default: target/nix-enclave/ATTR)
#   --verify        build twice from scratch (docker build --no-cache, second
#                   build with a different source directory), compare both
#                   artifact sets byte for byte, keep the first in --out.
#
# Works with the classic builder and with BuildKit (needs only `docker`).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
enclave=enclave
out=
verify=0

while [ $# -gt 0 ]; do
    case "$1" in
        --enclave) enclave="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        --verify) verify=1; shift ;;
        -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "nix-build-enclave.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
done
[ -n "$out" ] || out="$root/target/nix-enclave/$enclave"

# build TAG DEST [docker build args...]: build image TAG and copy its /out
# to DEST.
build() {
    local tag="$1" dest="$2"; shift 2
    docker build -f "$root/containers/Dockerfile.nix-build" \
        --build-arg "ENCLAVE=$enclave" -t "$tag" "$@" "$root" >&2
    local cid
    cid="$(docker create "$tag" /nonexistent)"
    rm -rf "$dest"
    mkdir -p "$(dirname "$dest")"
    docker cp "$cid:/out" "$dest" >&2
    docker rm "$cid" >/dev/null
    (cd "$dest" && sha256sum -c --quiet SHA256SUMS)
}

if [ "$verify" -eq 0 ]; then
    build "sgx-ra-enclave:$enclave" "$out"
else
    work="$(mktemp -d)"
    trap 'rm -rf "$work"; docker rmi -f "sgx-ra-enclave-verify:$enclave-a" "sgx-ra-enclave-verify:$enclave-b" >/dev/null 2>&1 || true' EXIT
    echo "nix-build-enclave.sh: clean build 1/2" >&2
    build "sgx-ra-enclave-verify:$enclave-a" "$work/a" --no-cache
    echo "nix-build-enclave.sh: clean build 2/2" >&2
    build "sgx-ra-enclave-verify:$enclave-b" "$work/b" --no-cache \
        --build-arg SRC_DIR=/var/tmp/elsewhere/src
    if ! diff -r "$work/a" "$work/b" >&2; then
        echo "nix-build-enclave.sh: NOT REPRODUCIBLE" >&2
        exit 1
    fi
    for f in "$work"/a/*; do
        cmp "$f" "$work/b/$(basename "$f")"
    done
    echo "nix-build-enclave.sh: both builds are bit-for-bit identical" >&2
    (cd "$work/a" && sha256sum ./*) >&2
    rm -rf "$out"
    mkdir -p "$(dirname "$out")"
    cp -r "$work/a" "$out"
fi

echo "nix-build-enclave.sh: MRENCLAVE $(cat "$out/MRENCLAVE.txt")" >&2
echo "nix-build-enclave.sh: artifacts in $out" >&2

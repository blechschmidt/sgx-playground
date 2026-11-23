#!/usr/bin/env bash
# Builds the OCI image of the untrusted host (flake output host-app-image:
# echo-host-app + the echo enclave + Intel's SGX/DCAP runtime) with
# containers/Dockerfile.nix-build and loads it into Docker.
#
#   scripts/nix-build-host-image.sh [--attr ATTR] [--out DIR] [--no-load] [--verify]
#
#   --attr ATTR   flake attribute (default: host-app-image)
#   --out DIR     where the image tarball goes (default: target/nix-host/ATTR)
#   --no-load     only build; do not `docker load` the tarball
#   --verify      build twice from scratch (second build with a different
#                 source directory) and compare the tarballs byte for byte
#
# Run the loaded image as described in containers/wrapper.sh.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
attr=host-app-image
out=
load=1
verify=0

while [ $# -gt 0 ]; do
    case "$1" in
        --attr) attr="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        --no-load) load=0; shift ;;
        --verify) verify=1; shift ;;
        -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "nix-build-host-image.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
done
[ -n "$out" ] || out="$root/target/nix-host/$attr"

# build TAG DEST [docker build args...]
build() {
    local tag="$1" dest="$2"; shift 2
    docker build -f "$root/containers/Dockerfile.nix-build" \
        --build-arg "ENCLAVE=$attr" -t "$tag" "$@" "$root" >&2
    local cid
    cid="$(docker create "$tag" /nonexistent)"
    rm -rf "$dest"
    mkdir -p "$(dirname "$dest")"
    docker cp "$cid:/out" "$dest" >&2
    docker rm "$cid" >/dev/null
    docker rmi "$tag" >/dev/null
}

if [ "$verify" -eq 0 ]; then
    build "sgx-ra-build:$attr" "$out"
else
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    echo "nix-build-host-image.sh: clean build 1/2" >&2
    build "sgx-ra-build-verify:$attr-a" "$work/a" --no-cache
    echo "nix-build-host-image.sh: clean build 2/2" >&2
    build "sgx-ra-build-verify:$attr-b" "$work/b" --no-cache \
        --build-arg SRC_DIR=/var/tmp/elsewhere/src
    if ! diff -r "$work/a" "$work/b" >&2; then
        echo "nix-build-host-image.sh: NOT REPRODUCIBLE" >&2
        exit 1
    fi
    echo "nix-build-host-image.sh: both builds are bit-for-bit identical" >&2
    rm -rf "$out"
    mkdir -p "$(dirname "$out")"
    cp -r "$work/a" "$out"
fi

tarball="$(find "$out" -maxdepth 1 -name '*.tar.gz' | head -n 1)"
[ -n "$tarball" ] || { echo "nix-build-host-image.sh: no image tarball in $out" >&2; exit 1; }
(cd "$out" && sha256sum ./*.tar.gz) >&2
if [ "$load" -eq 1 ]; then
    docker load -i "$tarball" >&2
fi
echo "nix-build-host-image.sh: image tarball $tarball" >&2

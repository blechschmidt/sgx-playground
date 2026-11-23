#!/usr/bin/env bash
# Links a Rust enclave staticlib into an Intel SGX SDK enclave image, then
# measures and signs it.
#
#   enclave-sys/build.sh [--crate NAME] [--staticlib PATH] [--out DIR]
#                        [--sgx-sdk DIR] [--mode HW|SIM] [--key PEM]
#                        [--config XML] [--edl EDL]
#
# Steps (mirroring the blueprint Makefile, sgx-playground/server/Makefile):
#   1. cargo build --release --locked --target x86_64-unknown-none -p NAME
#      (skipped with --staticlib, e.g. when cargo runs in another container)
#   2. sgx_edger8r --trusted Enclave.edl            -> Enclave_t.{c,h}
#      (--edl: another EDL named Enclave.edl, e.g.
#      enclave-sys/sealed-storage/Enclave.edl, which adds the sealed-storage
#      OCALLs; imports resolve against enclave-sys/ and the SDK)
#   3. cc  Enclave_t.c                              -> Enclave_t.o
#   4. ld  Enclave_t.o + staticlib + SDK trusted libs, Enclave.lds
#                                                   -> enclave.so
#   5. sgx_sign gendata                             -> enclave.so.gendata
#      MRENCLAVE (gendata[188..220])                -> mrenclave.hex
#   6. sgx_sign sign -key PEM                       -> enclave.signed.so
#
# Outputs in --out (default: target/enclave/NAME[-sim]): enclave.so,
# enclave.so.gendata, enclave.signed.so, mrenclave.hex, SHA256SUMS.
#
# Reproducibility: enclave.so and mrenclave.hex depend only on the sources,
# Cargo.lock, the toolchain (rust-toolchain.toml), the SGX SDK version and
# Enclave.config.xml. sgx_sign writes the current date into SIGSTRUCT
# (gendata offset 20). If SOURCE_DATE_EPOCH is set and libfaketime's
# `faketime` is on PATH, sgx_sign runs with its clock fixed to that instant,
# so gendata is reproducible too and, with a fixed --key, enclave.signed.so
# as well (PKCS#1 v1.5 signatures are deterministic). The fully pinned build
# runs in the Nix container (flake.nix, containers/Dockerfile.nix-build).
#
# --mode SIM links the SDK simulation libraries (sgx_trts_sim,
# sgx_tservice_sim) for testing without SGX hardware; such an image is never
# accepted by a verifier (its reports are not signed by real hardware).
#
# Without --key a throwaway RSA-3072 key (exponent 3) is generated in the
# output directory, like the blueprint does: MRSIGNER is then random, which
# is fine because clients pin MRENCLAVE. Deployments sign with the
# operator's key.

set -euo pipefail
export LC_ALL=C TZ=UTC

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"

crate=echo-enclave
staticlib=
out=
sgx_sdk="${SGX_SDK:-/opt/intel/sgxsdk}"
mode=HW
key=
config="$here/Enclave.config.xml"
edl="$here/Enclave.edl"

die() { echo "build.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --crate) crate="$2"; shift 2 ;;
        --staticlib) staticlib="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        --sgx-sdk) sgx_sdk="$2"; shift 2 ;;
        --mode) mode="$2"; shift 2 ;;
        --key) key="$2"; shift 2 ;;
        --config) config="$2"; shift 2 ;;
        --edl) edl="$2"; shift 2 ;;
        -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

case "$mode" in
    HW) trts=sgx_trts; tservice=sgx_tservice; suffix= ;;
    SIM) trts=sgx_trts_sim; tservice=sgx_tservice_sim; suffix=-sim ;;
    *) die "--mode must be HW or SIM" ;;
esac
[ -n "$out" ] || out="$root/target/enclave/$crate$suffix"

edger8r="$sgx_sdk/bin/x64/sgx_edger8r"
signer="$sgx_sdk/bin/x64/sgx_sign"
[ -x "$edger8r" ] && [ -x "$signer" ] || die "SGX SDK not found at $sgx_sdk (set --sgx-sdk or SGX_SDK)"
[ -f "$config" ] || die "enclave config not found: $config"
[ -f "$edl" ] || die "EDL not found: $edl"
# The bridge file names (Enclave_t.c) and the host's ocall table symbol
# follow the EDL's file name.
[ "$(basename "$edl")" = Enclave.edl ] || die "--edl must be a file named Enclave.edl"

CC="${CC:-cc}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
gen="$out/gen"
rm -rf "$gen"
mkdir -p "$gen"

# 1. Rust staticlib -----------------------------------------------------------
if [ -z "$staticlib" ]; then
    lib_name="lib${crate//-/_}.a"
    # Panic locations embed source paths; remap the machine-specific ones
    # (workspace checkout, cargo registry) so MRENCLAVE does not depend on
    # where the build runs. `--config` arrays are appended to the target
    # rustflags of .cargo/config.toml (RUSTFLAGS would replace them).
    cargo_home="${CARGO_HOME:-$HOME/.cargo}"
    remap="target.x86_64-unknown-none.rustflags=[\"--remap-path-prefix=$cargo_home=/cargo\", \"--remap-path-prefix=$root=/src\"]"
    cargo build --manifest-path "$root/Cargo.toml" --release --locked \
        --config "$remap" --target x86_64-unknown-none -p "$crate" >&2
    target_dir="$(cargo metadata --manifest-path "$root/Cargo.toml" --format-version 1 --no-deps \
        | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')"
    staticlib="$target_dir/x86_64-unknown-none/release/$lib_name"
fi
[ -f "$staticlib" ] || die "staticlib not found: $staticlib"

# 2./3. Trusted bridge ----------------------------------------------------------
"$edger8r" --trusted "$edl" --search-path "$sgx_sdk/include" --search-path "$here" \
    --trusted-dir "$gen" >&2

enclave_cflags=(
    -m64 -O2 -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections
    -fstack-protector-strong
    "-ffile-prefix-map=$gen=enclave-sys" "-ffile-prefix-map=$sgx_sdk=sgxsdk"
    -I"$sgx_sdk/include" -I"$sgx_sdk/include/tlibc" -I"$gen"
)
"$CC" "${enclave_cflags[@]}" -c "$gen/Enclave_t.c" -o "$gen/Enclave_t.o"

# 4. Link -------------------------------------------------------------------------
# sgx_trts as whole archive; the Rust staticlib and the other trusted
# libraries in one group, since they reference each other (malloc, abort,
# sgx_read_rand, sgx_create_report, memcpy). Only enclave_entry and the
# runtime globals stay exported (Enclave.lds).
"$CC" -m64 "$gen/Enclave_t.o" -o "$out/enclave.so" \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
    -L"$sgx_sdk/lib64" \
    -Wl,--whole-archive -l"$trts" -Wl,--no-whole-archive \
    -Wl,--start-group "$staticlib" -lsgx_tstdc -lsgx_tcrypto -l"$tservice" -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
    -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
    -Wl,-z,relro,-z,now,-z,noexecstack \
    -Wl,--build-id=none \
    -Wl,--version-script="$here/Enclave.lds"

symbols="$(nm "$out/enclave.so")"
for sym in enclave_create_report enclave_message; do
    grep -q " $sym\$" <<< "$symbols" || die "linked enclave lacks ECALL $sym"
done

# 5. Measure ----------------------------------------------------------------------
sign_cmd=("$signer")
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
    if command -v faketime >/dev/null; then
        sign_cmd=(faketime -f "@$(date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%d %H:%M:%S')" "$signer")
    else
        echo "build.sh: SOURCE_DATE_EPOCH set but faketime not found; SIGSTRUCT gets today's date" >&2
    fi
fi
"${sign_cmd[@]}" gendata -enclave "$out/enclave.so" -config "$config" \
    -out "$out/enclave.so.gendata" >&2
gendata_len="$(wc -c < "$out/enclave.so.gendata")"
[ "$gendata_len" -eq 256 ] || die "unexpected gendata size $gendata_len"
od -An -tx1 -v -j188 -N32 "$out/enclave.so.gendata" | tr -d ' \n' > "$out/mrenclave.hex"
echo >> "$out/mrenclave.hex"

# 6. Sign -------------------------------------------------------------------------
if [ -z "$key" ]; then
    key="$out/throwaway-signing-key.pem"
    if [ ! -f "$key" ]; then
        echo "build.sh: no --key given; generating a throwaway signing key" >&2
        openssl genrsa -out "$key" -3 3072 2>/dev/null
    fi
fi
"${sign_cmd[@]}" sign -key "$key" -enclave "$out/enclave.so" -config "$config" \
    -out "$out/enclave.signed.so" >&2

(cd "$out" && sha256sum enclave.so mrenclave.hex > SHA256SUMS)
echo "build.sh: $crate ($mode) MRENCLAVE $(cat "$out/mrenclave.hex")" >&2
echo "build.sh: artifacts in $out" >&2

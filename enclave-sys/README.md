# enclave-sys: turning a Rust enclave crate into `enclave.signed.so`

An sgx-ra enclave application is a `#![no_std]` Rust `staticlib` that
implements `sgx_ra_enclave::EnclaveApp` and calls
`sgx_ra_enclave::export_enclave!` (see `examples/echo-enclave`). This
directory has everything needed to link that library with the Intel SGX SDK
(2.26) trusted runtime into a standard enclave image. The existing remote
executor host (`App.cpp`) and our Rust host can both load that image.

| File | Purpose |
|------|---------|
| `Enclave.edl` | ECALL interface. **Byte-identical to the blueprint** (`sgx-playground/server/Enclave/Enclave.edl`), so the operator-fixed C++ host can load our enclave (docs/PROTOCOL.md §1.1). |
| `Enclave.config.xml` | Measured layout (stack 256 KiB, heap 1 MiB, 1 TCS) plus `ProdID = 1`, `ISVSVN = 1`, `DisableDebug = 1`. |
| `Enclave.lds` | Version script: only `enclave_entry` and the tRTS globals are exported. |
| `build.sh` | cargo → edger8r → cc → ld → `sgx_sign gendata` → `sgx_sign sign`. |
| `reproducible-signing-key.pem` | **Published on purpose.** The fixed RSA-3072 (e = 3) key the Nix build signs with, so that `enclave.signed.so` is reproducible. It protects nothing: MRSIGNER carries no trust in this framework, and clients pin MRENCLAVE. Never use it for MRSIGNER-based sealing or policy. |
| `sealed-storage/Enclave.edl` | `Enclave.edl` imported unchanged (same ECALL numbers) plus two OCALLs for storing and loading sealed blobs on the host. Link enclaves that use `sgx_ra_enclave::storage::OcallStorage` with `build.sh --edl enclave-sys/sealed-storage/Enclave.edl` (flake: `mkEnclave { edl = …; }`). `sgx-ra-host` builds its bridge from this file, so it serves both kinds of enclave. See [docs/SEALING.md](../docs/SEALING.md). |
| `sim/` | Simulation-mode build and a minimal layer-1 test host (`sim_host.c`), for testing without SGX hardware. |

## The ECALL ABI

The EDL is unchanged. `export_enclave!(App)` emits the two functions the
edger8r bridge `Enclave_t.c` calls. They are implemented in
`sgx_ra_enclave::runtime`:

| ECALL | Behaviour |
|-------|-----------|
| `uint32_t enclave_create_report(const sgx_target_info_t*, sgx_report_t*)` | On the first call it generates the identity key `EK` (X25519, from `sgx_read_rand`) and runs `App::init()`. Every call returns an `EREPORT` for the given target whose report_data is `SHA-256("SGXRA-v1/report-data" ‖ 0 ‖ 1 ‖ ek_pub) ‖ 0³²`. The key stays the same across calls. |
| `sgx_status_t enclave_message(const uint8_t[4096], uint32_t len, uint8_t[4096], uint32_t*)` | One SGXRA v1 step. It handles `HELLO` → `HELLO_REPLY` (once per instance), then each `RECORD` → decrypt → `App::handle` → encrypt. Any failure ends the session, wipes its keys and returns a non-zero status, which the host forwards as status byte `0x02`. Output never exceeds 4096 bytes. Unused output bytes are zeroed. |

Status codes the host can see: `0x0002` invalid pointer or length,
`0x0005` message before report (or a re-entrant call), `0x0001` any
protocol or application error. Reports pass the `sgx_create_report` status
through. Error details never leave the enclave.

No extra ECALL (for example "get public key") is needed. `ek_pub` travels in
`HELLO_REPLY` and is checked against the attested report_data
(PROTOCOL §6.4). Keeping the EDL identical means MRENCLAVE is the only thing
that differs from the blueprint enclave.

## Rust build settings

The staticlib is compiled for `x86_64-unknown-none` (`rust-toolchain.toml`).
That target has these properties:

* precompiled `core`/`alloc` with `panic = "abort"`, no unwinding, no `std`;
* position-independent code (`relocation-model = pic`), no red zone,
  soft-float (no SSE state assumptions), inline stack probes;
* `.cargo/config.toml` forces the portable crypto backends (no CPUID).
  CPUID raises `#UD` inside an enclave.

`build.sh` adds `--remap-path-prefix` for the checkout and `CARGO_HOME`
(panic locations embed paths). It also links with `--build-id=none`. The
release profile uses `lto = "fat"`, `codegen-units = 1`, `opt-level = 3` and
`panic = "abort"`. The linked image needs only `R_X86_64_RELATIVE` and one
`GLOB_DAT` relocation (the SDK's weak `pcl_entry`), and it has no text
relocations. The only `cpuid`/`rdtsc` instructions come from Intel's IPP
inside `libsgx_tcrypto`, the same as in C enclaves.

Runtime support comes from the SDK's trusted libraries:

* `malloc`/`free`/`memalign`: `libsgx_tstdc`. This is the Rust global
  allocator (`SgxAllocator`), limited by `HeapMaxSize`.
* `abort`: `libsgx_trts`. The panic handler calls it, which puts the enclave
  into the crashed state, so later ECALLs fail.
* `sgx_read_rand` (`SgxRng`), `sgx_create_report` (`SgxAttester`),
  `sgx_seal_data_ex`/`sgx_unseal_data` (`sealing`, MRENCLAVE policy).

## Building

The canonical build is the Nix one: `nix build .#enclave`, or
`scripts/nix-build-enclave.sh` (Docker only, `containers/Dockerfile.nix-build`).
It runs this same `build.sh` with the pinned toolchain, and every artifact is
bit-for-bit reproducible, including `enclave.signed.so` and gendata
(see `nix/enclave.nix`, [ARCHITECTURE §6](../docs/ARCHITECTURE.md#6-reproducible-build)).
The measurements are listed in the top-level README. Other enclave crates
use `lib.x86_64-linux.mkEnclave { crate = "..."; }` from `flake.nix`.

Outside Nix, `build.sh` needs the SGX SDK (`--sgx-sdk`, default `$SGX_SDK` or
`/opt/intel/sgxsdk`), a C compiler, binutils and `openssl`. It also needs
`cargo` with the pinned toolchain, unless `--staticlib` is given. The fully
pinned build runs in the Nix container (`containers/`). Without Nix, the
blueprint image `sgx-playground-server` provides the SDK:

```sh
# 1. Rust staticlib (on a host with the pinned rustup toolchain). Use the
#    same remap flags as build.sh, so the result matches a build.sh-driven
#    cargo run bit for bit.
cargo build --release --locked --target x86_64-unknown-none -p echo-enclave \
  --config "target.x86_64-unknown-none.rustflags=[\"--remap-path-prefix=$HOME/.cargo=/cargo\", \"--remap-path-prefix=$PWD=/src\"]"

# 2. Link, measure and sign inside the SDK image
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/src" -w /src sgx-playground-server:latest \
  enclave-sys/build.sh --staticlib target/x86_64-unknown-none/release/libecho_enclave.a
```

Outputs in `target/enclave/echo-enclave/`:

| File | Reproducible? |
|------|---------------|
| `enclave.so` | yes, bit for bit |
| `mrenclave.hex` | yes. This is what clients pin. |
| `enclave.so.gendata` | everything except the date field (offset 20). Fully reproducible when `SOURCE_DATE_EPOCH` is set and `faketime` is on PATH. |
| `enclave.signed.so` | only with a fixed `--key` and the fixed date above (as in the Nix build). Its MRENCLAVE always equals `mrenclave.hex`. |
| `SHA256SUMS` | over `enclave.so` and `mrenclave.hex` |

Pass `--key operator.pem` (RSA-3072, e = 3) to sign with a real key. Without
it, a throwaway key is generated, so MRSIGNER is random, as in the blueprint.

## Testing without SGX hardware

```sh
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/src" -w /src sgx-playground-server:latest \
  enclave-sys/sim/build.sh --staticlib target/x86_64-unknown-none/release/libecho_enclave.a

SGX_RA_SIM_HOST="docker run --rm -i -v $PWD/target/enclave/echo-enclave-sim:/e \
    sgx-playground-server:latest /e/sim_host /e/enclave.signed.so" \
SGX_RA_SIM_MRENCLAVE=$(cat target/enclave/echo-enclave-sim/mrenclave.hex) \
cargo test -p sgx-ra-client --test sim_enclave -- --ignored
```

This runs the same Rust code, linked against the simulation tRTS, behind
`sim_host`. `sim_host` speaks the layer-1 protocol but announces the raw
report instead of a quote. The test checks the report (MRENCLAVE equals
gendata, ProdID/ISVSVN, report_data layout) and then runs the real
handshake, echo up to the maximum record size, replay and bit-flip
rejection, the single-handshake rule, and one key per instance. A SIM
image has a different MRENCLAVE from the HW image, and no verifier accepts it.

The same test runs against the Rust host (`examples/echo-host-app`). Build
it against the SDK's simulation runtime. `--quoter unattested-report` makes
it announce the raw report, like `sim_host`:

```sh
SGX_SDK=/opt/intel/sgxsdk SGX_MODE=SIM CARGO_TARGET_DIR=target/sim-host \
  cargo build -p echo-host-app --features sgx
SGX_RA_SIM_HOST="LD_LIBRARY_PATH=/opt/intel/sgxsdk/lib64 target/sim-host/debug/echo-host-app \
    --quoter unattested-report --enclave target/enclave/echo-enclave-sim/enclave.signed.so" \
SGX_RA_SIM_MRENCLAVE=$(cat target/enclave/echo-enclave-sim/mrenclave.hex) \
cargo test -p sgx-ra-client --test sim_enclave -- --ignored
```

This exercises the host's real FFI path: `sgx_create_enclave`, the
edger8r bridge built by `crates/sgx-ra-host/build.rs`, both ECALLs and the
session loop.

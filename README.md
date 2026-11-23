# sgx-ra: reproducible Rust SGX enclaves with attested channels

A Rust framework for Intel SGX enclaves that run on the remote executor of
[sgx-playground](https://github.com/blechschmidt/sgx-playground). Clients
rebuild an enclave bit for bit, check a DCAP quote against that
measurement, and talk to the enclave over a channel whose key exists only
inside it.

* `crates/`: the framework. `sgx-ra-core` (protocol and the reusable
  `Attester` / `Verifier` / `Policy` / `SecureChannel` interfaces, no_std),
  `sgx-ra-enclave` (enclave runtime, `EnclaveApp`), `sgx-ra-host`
  (untrusted host), `sgx-ra-verifier` (DCAP), `sgx-ra-client`.
* `examples/`: the echo enclave, host and client, and the sealing
  enclave and client, all built on the framework.
* `enclave-sys/`: EDL, enclave config and the link/sign script
  ([README](enclave-sys/README.md)).
* `extra/sequence.wsd`: the sequence diagram below (PlantUML).

> **Status (2026-11-23).** The public executor at
> `sgx-playground.blechschmidt.io:443` currently sends a DCAP error instead
> of a quote, because its PCCS is unreachable. It also still runs the
> blueprint's C++ enclave. The Rust client therefore stops with exit code 3
> today. Everything that runs without SGX hardware is tested, including
> simulation runs of the real enclave and host, but no run on SGX hardware
> has been made yet ([THREAT_MODEL.md TM-10](docs/THREAT_MODEL.md#tm-10-no-end-to-end-run-on-sgx-hardware)).

## Documentation

| Document | Read it to |
|---|---|
| [QUICKSTART.md](docs/QUICKSTART.md) | prepare a PCCS, run the reproducible Nix build and run the Rust client against `sgx-playground.blechschmidt.io` |
| [NEW_ENCLAVE_APP.md](docs/NEW_ENCLAVE_APP.md) | write your own enclave on the framework: implement `EnclaveApp`, define a `Policy`, reuse the host, `Attester` / `Verifier` / `SecureChannel` |
| [REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md) | reproduce MRENCLAVE bit for bit on another host, and debug a mismatch |
| [PROTOCOL.md](docs/PROTOCOL.md) | the wire protocol spec: the executor framing, quote layout, key binding (§6.2), handshake (§6.4), records |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | the trust assumptions, the security review and the open issues |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | the crate layout, trait boundaries, reproducible build design |
| [SEALING.md](docs/SEALING.md) | sealing, storage OCALLs and the optional long-term enclave identity |

## How the key binding works

![Remote attestation with key binding](extra/sequence.svg)

The enclave generates its channel key `EK` inside the enclave and writes
`SHA-256(label ‖ ek_pub)` into the report_data of its quote. The client
trusts that value only after the quote has been verified up to Intel's
root and MRENCLAVE matches the client's own reproducible build. In the
handshake, the client checks that the `ek_pub` it receives hashes to
exactly that report_data. It also checks a key confirmation that only the
holder of `ek_sk` can compute. The channel key therefore exists only
inside an enclave running the code the client built. The untrusted host,
the operator and the TLS terminator see only public keys and ciphertext.
Details are in [PROTOCOL.md §6](docs/PROTOCOL.md#6-attested-channel-protocol-layer-2-framework-sgxra-v1).

## Blueprint TODOs

The [blueprint](https://github.com/blechschmidt/sgx-playground) README
lists six TODOs. All of them are implemented here:

- [x] **Rust implementation**: the enclave, host and client are Rust
  (`crates/`, `examples/`). The enclave is `no_std` on Intel's trusted
  runtime and keeps the blueprint's EDL, so the operator's existing host
  can load it.
- [x] **Sealing PoC**: `examples/sealing-enclave` and `sealing-client`
  seal client data to MRENCLAVE and keep a sealed long-term identity key
  ([SEALING.md](docs/SEALING.md)).
- [x] **Secure channel into the enclave, with report_data pinning a hash
  of the public key**: SGXRA v1. It uses X25519, HKDF-SHA256 and
  ChaCha20-Poly1305, with key confirmation
  ([PROTOCOL.md §6](docs/PROTOCOL.md#6-attested-channel-protocol-layer-2-framework-sgxra-v1)).
- [x] **Improved reproducibility with Nix**: `flake.nix` with a
  digest-pinned build container. All artifacts, including
  `enclave.signed.so`, are bit-for-bit reproducible
  ([REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md)).
- [x] **MRSIGNER verification**: `EnclavePolicy::with_mr_signer` /
  `echo-client --mrsigner`, alongside ISVPRODID and ISVSVN checks. Our
  builds are signed with a published key, so MRENCLAVE remains the pin
  that carries trust. MRSIGNER is useful when you re-sign with a private
  key.
- [x] **Server app containerization**: `nix build .#host-app-image` builds
  a reproducible OCI image of the Rust host, the enclave and Intel's
  runtime. Use it with `compose.yaml` (`host-app`) and
  `containers/wrapper.sh` for stunnel.

## Reproducible enclave build

`flake.nix` pins everything that reaches the enclave:

| Input | Pinned by |
|-------|-----------|
| nixpkgs `nixos-26.05` @ `94c3211b`, crane v0.24.0, fenix | revision + narHash (`flake.lock`) |
| Rust 1.100.0 (`rust-toolchain.toml`, incl. `x86_64-unknown-none`) | sha256 of the rustup channel manifest |
| Intel SGX SDK 2.26.100.0 (Intel's prebuilt release) | sha256 (fixed-output derivation, `nix/sgx-sdk.nix`) |
| Intel SGX DCAP 1.23 (source + headers, for the host) | commit + hash (`nix/dcap.nix`) |
| crates | `Cargo.lock` checksums (crane vendoring, `--offline --locked`) |
| build container | `nixos/nix:2.36.0@sha256:74628055…` |

Build in the container (needs only Docker):

```sh
scripts/nix-build-enclave.sh            # -> target/nix-enclave/enclave/
scripts/nix-build-enclave.sh --verify   # two clean builds, compared byte for byte
```

or with Nix directly: `nix build .#enclave`. Both produce
`enclave.signed.so`, `enclave.so`, `enclave.so.gendata`, `MRENCLAVE.txt`,
`MRSIGNER.txt` and `SHA256SUMS`. All of them are bit-for-bit
reproducible, including the signed image: `sgx_sign` runs with its clock
fixed to `SOURCE_DATE_EPOCH`, and it signs with a key that is published on
purpose (`enclave-sys/reproducible-signing-key.pem`). Clients pin
**MRENCLAVE**, which does not depend on the signer at all. See
[ARCHITECTURE.md §6](docs/ARCHITECTURE.md#6-reproducible-build) for the
full list of determinism measures.

## Untrusted host app and its container

`examples/echo-host-app` is the Rust port of the blueprint's
`server/App/App.cpp`, built on `crates/sgx-ra-host`. It loads
`enclave.signed.so` through `libsgx_urts`, gets a DCAP quote through
`libsgx_dcap_ql` (in-process QE3/PCE, like `App.cpp`) and speaks the same
framed protocol on stdin/stdout, so it runs unchanged behind the
executor's `stunnel` `exec`. Unlike `App.cpp` it bounds every read and logs
to stderr only: fd 1 is redirected to stderr, so no library can write to
the wire. `--listen ADDR` serves TCP instead, with one enclave per
connection. The host is untrusted: it handles only the quote and
ciphertext, never a key.

```sh
nix build .#host-app          # bin/echo-host-app, linked to Intel's runtime
nix build .#host-app-image    # OCI image: host + echo enclave + SGX/DCAP runtime
scripts/nix-build-host-image.sh            # same, in the Nix container, then `docker load`
scripts/nix-build-host-image.sh --verify   # two clean builds, compared byte for byte
```

The image `sgx-ra-echo-host:latest` has `/app/enclave.signed.so` (working
directory) and Intel's runtime 2.26 / DCAP 1.23. The runtime comes from the
Ubuntu 24.04 packages that the blueprint installs, pinned by sha256
(`nix/sgx-runtime.nix`). The signed QE3/PCE/IDE images are Intel's
unmodified bits. Run it with the SGX device nodes and your QCNL config:

```sh
docker run --rm -i \
  --device /dev/sgx_enclave \      # our enclave, QE3, ID enclave
  --device /dev/sgx_provision \    # the PCE (PROVISION_KEY attribute)
  -v /etc/sgx_default_qcnl.conf:/etc/sgx_default_qcnl.conf:ro \   # PCCS URL
  --network host \                 # if the PCCS listens on localhost
  sgx-ra-echo-host:latest
```

For the remote executor, point stunnel's `exec` at
[`containers/wrapper.sh`](containers/wrapper.sh), which runs exactly that
for each connection. Without SGX hardware,
`cargo build -p echo-host-app --features sgx` with `SGX_MODE=SIM` links the
simulation runtime, and `--quoter unattested-report` lets the simulation
end-to-end test run against the real host (see
[`crates/sgx-ra-host/build.rs`](crates/sgx-ra-host/build.rs) and
[`enclave-sys/README.md`](enclave-sys/README.md#testing-without-sgx-hardware)).

### Measurements of the echo enclave

| | |
|-|-|
| **MRENCLAVE** | `bdd7e7862557e60ed2db5c01aa6bc46f6ede0483209fa39680caf7b889a09263` |
| MRSIGNER (published key, carries no trust) | `8b1beba60b7c004561b8eb5e8384ff03f988e3914e5c845ee3362b786b34efa6` |
| ProdID / ISVSVN / debug | 1 / 1 / disabled |

These values come from `nix build .#enclave` at this commit. Any change
to the sources, `Cargo.lock`, `flake.lock`, `rust-toolchain.toml` or
`enclave-sys/` gives a new MRENCLAVE. Update this table whenever that
happens. A mismatch with your own build means the input trees differ.

## Compose, end-to-end tests and CI

`compose.yaml` keeps the blueprint's `prepare-pccs` and `pccs` services
and adds `nix-build` (the reproducible build, output in the `enclave`
volume), `host-app` (the Nix-built host image with the SGX devices,
profile `local-sgx`) and `verify-rs` (the Rust client, host networking so
it reaches the local PCCS). See the comments at the top of the file.

```sh
docker compose run --rm nix-build                     # prints MRENCLAVE
SGX_RA_PCCS_URL=https://api.trustedservices.intel.com SGX_RA_PCCS_CA=none \
  docker compose run --rm verify-rs                   # public executor
```

`scripts/e2e.sh [--compose]` runs the whole flow and writes
`target/e2e/report.md` with PASS / FAIL / BLOCKED per check: build;
modified enclave source → MRENCLAVE mismatch (Docker only); SGX simulation
(substituted key → report_data mismatch, tampered records → decryption
failure); and against the executor the positive flow plus the same attacks
through a man-in-the-middle proxy (`examples/echo-client/tests/e2e.rs`).
BLOCKED means the executor sent a DCAP error text instead of a quote, so
nothing was verified. For a local SGX host:
`docker compose --profile local-sgx up -d host-app`, then
`scripts/e2e.sh --target 127.0.0.1:7000 --transport plaintext --pccs-url https://127.0.0.1:8081 --pccs-ca sgx-playground/config/pccs/tls/ca.crt`.

`.github/workflows/ci.yml` runs everything that needs no SGX hardware: tests,
rustfmt, clippy, `cargo deny` (`deny.toml`), `cargo audit`
(`.cargo/audit.toml`), two clean Nix builds whose `enclave.signed.so` and
`enclave.so.gendata` sha256 must match (and MRENCLAVE must equal the table
above), the offline and simulation E2E tests, and the compose files.

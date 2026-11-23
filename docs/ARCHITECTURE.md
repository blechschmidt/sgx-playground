# Architecture

This is a reusable Rust framework for **remotely attested, confidential
channels into Intel SGX enclaves**, plus example applications (echo, sealing)
built on it. The wire protocol and its quirks are specified in
[PROTOCOL.md](PROTOCOL.md). This document covers the structure: trust model,
crates, trait boundaries, build, and data flow.

## 1. Goals and constraints

| # | Requirement | Design consequence |
|---|-------------|--------------------|
| G1 | The Rust enclave must load on the existing remote executor (`sgx-playground.blechschmidt.io`) | Keep the **`Enclave.edl` ABI** (`enclave_create_report`, `enclave_message` with 4096-byte buffers) and the Intel SGX SDK enclave format (`sgx_create_enclave`). Fortanix EDP is ruled out: it uses a different loader and ABI. |
| G2 | Bit-for-bit reproducible build on any host | Nix-pinned toolchain (Rust, SGX SDK 2.26 trusted libs, `sgx_sign`, binutils) inside a container. MRENCLAVE is the reproducibility target. Signature and gendata date are not. |
| G3 | The client rebuilds from the Dockerfile, verifies, and opens a channel whose key provably lives only in the enclave | Client drives `docker build` on the Nix Dockerfile and reads MRENCLAVE from the artifacts. It verifies the DCAP quote with a pinned Intel root and runs the SGXRA v1 handshake (PROTOCOL §6), which binds `ek_pub` to report_data. |
| G4 | Reusable framework, keys tied to an implementation | Generic crates with trait boundaries. The application supplies only an `EnclaveApp` impl plus its expected measurement. Keys are generated in the enclave and bound via report_data to MRENCLAVE, and sealed keys use the MRENCLAVE policy. |
| C1 | The remote enclave is chosen by the operator, not the client (PROTOCOL §1.1) | The client never assumes which enclave is running. It accepts only a quote whose MRENCLAVE equals its own rebuild. Deploying our enclave remotely is an operator step. |
| C2 | No client input before the quote, so no nonce in report_data | Freshness comes from the in-enclave key plus TCB evaluation at verification time (PROTOCOL §6.4). |
| C3 | Remote executor currently fails quote generation (PROTOCOL §5) | Tests use recorded fixtures and the local Rust host. The client gives a clear diagnostic for text-on-the-wire errors. |

## 2. Trust model

| Party | Trusted for |
|-------|-------------|
| Intel (root CA, QE/PCE, CPU) | Quote authenticity and platform TCB. The root key is **pinned** in the verifier. |
| Client machine + local reproducible build | Computing the expected MRENCLAVE from the source |
| Enclave code (our source) | Holding `ek_sk`, enforcing the channel |
| Remote host OS, `app`, stunnel, wrapper, network, TLS CA, PCCS | **Nothing** (availability only). The PCCS is only a collateral cache, and every collateral item is checked against the pinned root. |

## 3. Workspace and crate layout

```
.
├── Cargo.toml                    # workspace; Cargo.lock committed; rust-toolchain.toml pinned
├── crates/
│   ├── sgx-ra-core/              # no_std + alloc — shared by enclave and client
│   ├── sgx-ra-enclave/           # no_std — trusted runtime (ECALL glue, RNG, alloc, panic, sealing)
│   ├── sgx-ra-host/              # std — untrusted host lib + `sgx-ra-host` bin (urts + DCAP QL FFI)
│   ├── sgx-ra-verifier/          # std — DCAP v3 quote verification + collateral + policy
│   └── sgx-ra-client/            # std — reproducible-build driver, transport, attested channel
├── examples/
│   ├── echo-enclave/             # staticlib → enclave.so; EnclaveApp = echo
│   ├── echo-host-app/            # bin: untrusted host for the echo enclave (sgx-ra-host)
│   ├── echo-client/              # bin: build → attest → handshake → echo
│   ├── sealing-enclave/          # staticlib: seal/unseal PoC (task 9)
│   └── sealing-client/
├── fixtures/                     # quote / gendata / SIGSTRUCT test vectors (see fixtures/README.md)
├── enclave-sys/                  # Enclave.edl, Enclave.config.xml, Enclave.lds, link script (shared by enclaves)
├── nix/ + flake.nix + flake.lock # pinned toolchain, SGX SDK/DCAP FODs, mkEnclave (enclave.signed.so, gendata, MRENCLAVE)
├── scripts/nix-build-enclave.sh  # runs the Nix container, extracts /out, --verify = two clean builds + bitwise diff
├── containers/
│   ├── Dockerfile.nix-build      # reproducible Nix build container (the client consumes this)
│   └── wrapper.sh                # stunnel exec target: runs the host image (nix .#host-app-image)
├── compose.yaml
├── docs/ (PROTOCOL.md, ARCHITECTURE.md, …)
└── sgx-playground/               # blueprint (reference only, not built)
```

Dependency direction (no cycles, enclave side never depends on std crates):

```
            sgx-ra-core  (no_std)
            ▲         ▲          ▲
 sgx-ra-enclave   sgx-ra-verifier   sgx-ra-host
     ▲                 ▲
 examples/*-enclave  sgx-ra-client ◀── examples/*-client
```

### 3.1 `sgx-ra-core` (no_std + alloc)

Pure logic, no I/O, fully unit-testable on the build host.

* `wire`: layer-1 framing constants and codec (`MAX_PAYLOAD = 4096`,
  status codes, `MAX_QUOTE_LEN = 64 KiB`, text-diagnostic detection).
* `sgx`: strict parsers for `Quote` (DCAP v3 and v4, SGX TEE type; both
  normalised into `QuoteSignature`), `ReportBody`, `Report`, `TargetInfo`,
  `Gendata` and the full `Sigstruct` (with `mr_signer()`). Offsets are in
  PROTOCOL §3. Parsing uses explicit offsets, not `repr(C)` transmutes.
* `attestation`: the framework traits `Attester`, `Verifier`, `Policy`, plus
  `VerifiedClaims`, `TcbStatus` and the standard `EnclavePolicy` (§4).
* `channel`: the `SecureChannel` / `AttestedChannel` traits (§4).
* `binding`: `report_data_for(ek_pub) -> ReportData` and `check_report_data`
  (constant time, all 64 bytes).
* `handshake`: `Hello`, `HelloReply`, `Record`, `Message` encode/decode;
  `IdentityKey` (enclave X25519 identity, optionally restorable from sealed
  bytes); `ClientHandshake::start(&VerifiedClaims, rng)` / `finish(reply)`;
  enclave-side `respond(identity, report_body, hello, rng)`.
* `record`: `Session::{seal, open}`: per-direction ChaCha20-Poly1305 keys,
  counter nonces, strict next-`seq` check, keys wiped on any receive error.
* `session`: transport-agnostic endpoints. `MessageTransport` (send/recv one
  SGXRA message); `EnclaveEndpoint` (enclave state machine fed by
  `enclave_message`: one `HELLO`, then `RECORD`s, closure-based app hook);
  `ClientChannel<T>` (implements `SecureChannel` + `AttestedChannel`).
* `Rng` trait (`fill_bytes`) so the enclave plugs in `sgx_read_rand` and the
  client plugs in `getrandom`.

### 3.2 `sgx-ra-enclave` (no_std, links against Intel tRTS)

The enclave is built as a **`#![no_std]` Rust `staticlib`**. It is linked with
the edger8r-generated `Enclave_t.c` and the SDK trusted libraries
(`sgx_trts` whole-archive, `sgx_tstdc`, `sgx_tcrypto`, `sgx_tservice`), using
the same flags and version script as the blueprint Makefile, then measured and
signed with `sgx_sign`. The output is a standard `enclave.signed.so`, loadable
by the blueprint `app` or by our host.

Provides:

* `#[global_allocator]` backed by tlibc `malloc`/`free`, `#[panic_handler]` →
  `abort()`, `panic = "abort"`.
* FFI to `sgx_create_report`, `sgx_read_rand`, and `sgx_seal_data`/`sgx_unseal_data`
  (`sgx_get_key` for task 9).
* `IdentityKey`: lazily generated X25519 identity key `EK`, never exported (one
  per enclave instance).
* `export_enclave!(MyApp)` macro emitting the two `extern "C"` ECALL entry
  points that `Enclave_t.c` calls:
  * `enclave_create_report(target, report) -> u32`: idempotent. Creates `EK`,
    sets report_data, and stores `rb_hash`.
  * `enclave_message(in, len, out, out_len) -> sgx_status_t`: dispatches
    `HELLO`/`RECORD` and calls `MyApp::handle` on decrypted plaintext. It
    clamps output to 4096 bytes, and on any error it wipes the session and
    returns an error.
* `sealing::{seal, unseal}` (MRENCLAVE key policy) for task 9.

The ECALL glue and the link/sign tooling are described in
[`enclave-sys/README.md`](../enclave-sys/README.md). `enclave-sys/build.sh`
produces `enclave.so`, `enclave.so.gendata`, `mrenclave.hex` and
`enclave.signed.so`. `enclave-sys/sim/` builds an SGX-simulation variant and a
minimal test host for hardware-free end-to-end tests.

### 3.3 `sgx-ra-host` (std, untrusted)

A Rust replacement for `App.cpp` that speaks the same layer-1 protocol.
`examples/echo-host-app` is only `sgx_ra_host::cli::main("echo-host-app")`.

* Hardware-free core (always built, unit-tested with mock backends):
  `serve::{attest, serve_session, run_session}` over any `Read`/`Write`,
  `stdio::claim()`, `tcp::serve_tcp` (one enclave per connection, a cap on
  concurrent sessions, an idle timeout, and the quoter shared behind a mutex),
  and `cli` (option parsing and the shared `main`).
* Feature `sgx` (`sgx::SgxEnclave`, `sgx::DcapQuoter`): hand-written FFI.
  `build.rs` runs `sgx_edger8r --untrusted` on `enclave-sys/Enclave.edl` and
  compiles `Enclave_u.c` with `cc`. It links `libsgx_urts`, or
  `libsgx_urts_sim` with `SGX_MODE=SIM`. `libsgx_dcap_ql` is `dlopen`ed
  (`sgx_qe_set_enclave_load_policy`, `sgx_ql_set_path` for QE3/PCE/IDE/QPL,
  `sgx_qe_get_target_info`, `sgx_qe_get_quote_size`, `sgx_qe_get_quote`), so
  a simulation build never loads the hardware runtime and a missing DCAP
  install gives a clear error. Requests go to the enclave in a full
  4096-byte buffer, because the bridge always copies `count=4096`.
* Fixes the blueprint quirks. Reads are bounded: a payload over 4096 bytes
  or an empty one closes the session. EOF handling is correct. **fd 1 is
  redirected to stderr** after the wire takes a private duplicate, so
  neither DCAP's logger nor `printf` can corrupt the stream (Q5/Q6). There
  are no `report.dat`/`quote.dat` side files, and write errors are
  propagated. Enclave failures still produce status `0x02`, and the session
  continues.
* `--quoter unattested-report` announces the raw report, as
  `enclave-sys/sim/sim_host` does. It is for SGX simulation tests only:
  `sim_enclave.rs` passes against the Rust host built with `SGX_MODE=SIM`.
* Packaging (`flake.nix`): `.#host-app` (`mkHostApp`) links Intel's runtime
  from `nix/sgx-runtime.nix`: the Ubuntu 24.04 debs of urts 2.26 and DCAP
  1.23, pinned by sha256, with the signed QE3/PCE/IDE images unmodified.
  `.#host-app-image` (`mkHostImage`, `dockerTools.buildLayeredImage`) adds
  the echo enclave at `/app/enclave.signed.so` and the QCNL config.
  `containers/wrapper.sh` is the stunnel `exec` target. It runs the image
  with `--device /dev/sgx_enclave --device /dev/sgx_provision` and the
  host's `/etc/sgx_default_qcnl.conf`.

### 3.4 `sgx-ra-verifier` (std)

* `verify_quote(quote, &Collateral, &VerifierOptions) -> Result<VerifiedQuote>`
  implements PROTOCOL §6.6 steps 1–6 and closes every gap in PROTOCOL §4.2.
  The Intel SGX Root CA is pinned as a compiled-in DER
  (`INTEL_SGX_ROOT_CA_DER`, SHA-256 `44a0196b…74d3`). Roots in the quote or in
  issuer-chain headers must be byte-equal to it.
  * Modules: `pki` (P-256/ECDSA-SHA256 only, validity, basic constraints and
    key usage, unknown critical extensions rejected, CRLs, DER/PEM/hex CRL
    normalisation), `pck` (strict DER parser for the SGX extension: FMSPC,
    PCE-ID, 16 TCB components, PCE SVN), `tcb` (signed TCB Info v3 / QE
    Identity v2; the signature covers the raw JSON body bytes; level
    matching; QVL-style QE/platform status convergence), `verify`
    (orchestration, `DcapVerifier`).
  * The platform TCB status `Revoked` is always rejected, whatever the policy.
  * `VerifierOptions { collateral_grace, fixed_time }`: no grace by default.
    Certificates never get grace. Up to 300 s of clock skew is tolerated, and
    only for not-yet-valid checks.
* `CollateralSource` trait (`fetch(&CollateralRequest{fmspc, pck_ca})`),
  `StaticCollateral` for recorded collateral. `collateral_request(quote)`
  derives the request from the (not yet verified) PCK leaf.
* `DcapVerifier<S: CollateralSource>` implements `sgx_ra_core::Verifier`. It
  fetches collateral, verifies, then applies the `Policy` (normally
  `EnclavePolicy`: `mr_enclave`, optional `mr_signer`, `isv_prod_id`,
  `min_isv_svn`, allowed TCB statuses, no debug). `verify_detailed` also
  returns platform/QE status, FMSPC, TCB date and collateral expiry.
* The verifier does no I/O. The PCCS/PCS HTTP client is in `sgx-ra-client`
  (`pccs` module).
* Tests: the recorded quote `fixtures/quote_v3.dat` plus Intel PCS collateral
  recorded on 2026-11-22 (`fixtures/dcap/`), verified at a fixed time, with
  tampering of every signed part. A synthetic Intel-shaped PKI (rcgen, dev
  only) covers revocation, foreign roots, QE identity mismatches and revoked
  TCB levels.
* No DCAP QVL FFI fallback is provided. The native verifier covers every
  check the QVL performs for SGX ECDSA quotes, and linking Intel's C++
  library would add a large unaudited native dependency to the client.

### 3.5 `sgx-ra-client` (std)

* `MeasurementSource` trait (expected MRENCLAVE) with these implementations:
  * `ReproducibleBuild::new(engine, dockerfile, context).run(dir) -> BuildOutput`
    (module `build`): runs `docker`/`podman build` on
    `containers/Dockerfile.nix-build` and exports the artefacts. It uses
    `--output type=local` when the engine supports it (podman, or docker with
    buildx), otherwise the classic builder with `-t` followed by
    `docker create` + `docker cp …:/out` (`ExportMethod`). It then reads
    `enclave.so.gendata` → `enclave_hash`, cross-checked against
    `MRENCLAVE.txt`.
  * `GendataFile(path)` and `FixedMeasurement` (`--gendata-path`,
    `--expected-mrenclave`).
* `Transport` trait (`Read + Write` with a read timeout; module `transport`):
  `TcpStream`, and `TlsStream` from `connect_tls(host, port, &TlsVerification)`
  (rustls + ring with `WebPki` Mozilla roots, a `CustomCa` PEM, or `Insecure`;
  the last is needed because the remote certificate has expired, and TLS is not
  a trust anchor).
* `ExecutorConnection<T: Transport>` (module `executor`): layer-1 client.
  `read_quote()` waits up to 120 s (the remote host can spend ~60 s in DCAP,
  PROTOCOL §2.4 Q7) and reports text in place of a quote as
  `ExecutorError::RemoteDiagnostic`. It implements `MessageTransport`
  (requests ≤ 4096 bytes, never empty; any failure status is fatal).
* `EnclaveChannel::establish(conn, VerifiedClaims, &mut Rng)` (module
  `connect`) wraps `sgx_ra_core::ClientChannel`. It implements
  `SecureChannel` + `AttestedChannel` and exposes the attested
  `enclave_public_key()`. `attest_and_connect(transport, &impl Verifier,
  &dyn Policy, &mut Rng)` runs quote → verify + policy → handshake in one
  call.
* `OsRng` (getrandom), `PccsClient`/`dcap_verifier` (collateral, §3.4).
* CLI (`examples/echo-client`, see its README): `--host/--port`,
  `--dockerfile/--build-context/--build-arg/--container-engine`,
  `--gendata-path`, `--expected-mrenclave`, `--mrsigner`, `--isv-prod-id`,
  `--min-isv-svn`, `--allow-tcb-status`, `--pccs-url/--pccs-ca`,
  `--insecure-tls/--tls-ca/--plaintext`, `-m`, `-i`, `--loglevel`. Exit codes:
  0 OK, 1 failure, 2 usage, 3 remote cannot produce a quote.

## 4. Trait boundaries

These are the public interfaces as implemented in the workspace. Signatures
are abbreviated; the rustdoc in each crate is authoritative.

```rust
// sgx-ra-core::attestation: the reusable attestation interfaces
pub trait Attester {                       // runs inside the TEE
    type Evidence;                         // SGX: sgx::Report targeted at the QE
    type Error: Debug + Display;
    fn attest(&mut self, report_data: &ReportData /* 64 bytes */) -> Result<Self::Evidence, Self::Error>;
}
pub trait Verifier {                       // runs on the relying party
    type Error: Debug + Display + From<PolicyViolation>;
    /// Ok only if the evidence is authentic AND policy.check() accepted it.
    fn verify(&self, evidence: &[u8], policy: &dyn Policy) -> Result<VerifiedClaims, Self::Error>;
}
pub trait Policy { fn check(&self, claims: &VerifiedClaims) -> Result<(), PolicyViolation>; }
// VerifiedClaims { report_body, tcb_status, advisory_ids } (private fields, accessors)
// EnclavePolicy::new(mr_enclave).with_mr_signer(..).with_isv_prod_id(..)
//     .with_min_isv_svn(..).allow_tcb_status(..)
//   always rejects DEBUG and non-MODE64BIT enclaves; default TCB set = {UpToDate}

// sgx-ra-core::channel
pub trait SecureChannel {
    type Error: Debug + Display;
    fn max_message_len(&self) -> usize;    // 4071 for SGXRA v1
    fn send(&mut self, plaintext: &[u8]) -> Result<(), Self::Error>;
    fn recv(&mut self) -> Result<Vec<u8>, Self::Error>;
    fn request(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Self::Error>; // send + recv
}
pub trait AttestedChannel: SecureChannel { fn peer_claims(&self) -> &VerifiedClaims; }

// sgx-ra-core::rng
pub trait Rng { fn fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), RngError>; }

// sgx-ra-enclave: the only thing an enclave application implements
pub trait EnclaveApp: Sized + 'static {
    fn init() -> Self;                     // once per enclave instance
    fn handle(&mut self, request: &[u8], response: &mut Vec<u8>) -> Result<(), AppError>;
}
// export_enclave!(EchoApp);  // emits enclave_create_report / enclave_message (backed by
//                            // sgx_ra_enclave::Runtime) and installs allocator + panic handler
// sgx-ra-enclave also provides: SgxRng (sgx_read_rand), SgxAttester: Attester<Evidence = Report>
// (sgx_create_report), sealing::{seal, unseal} (MRENCLAVE key policy)

// sgx-ra-host: what the host needs from an enclave + quoting stack (mockable)
pub trait EnclaveBackend {
    fn create_report(&mut self, qe_target: &TargetInfo) -> Result<Report, HostError>;
    fn message(&mut self, input: &[u8], output: &mut [u8; 4096]) -> Result<usize, HostError>;
}
pub trait Quoter {
    fn target_info(&mut self) -> Result<TargetInfo, HostError>;
    fn quote(&mut self, report: &Report) -> Result<Vec<u8>, HostError>;
}

// sgx-ra-verifier: DcapVerifier<S: CollateralSource>: Verifier
pub trait CollateralSource {
    fn fetch(&self, request: &CollateralRequest) -> Result<Collateral, SourceError>;
}
// sgx-ra-client::pccs: PccsClient (PCCS, default http://127.0.0.1:8080, or
// Intel PCS; HTTPS with Mozilla roots or a custom CA): CollateralSource

// sgx-ra-client
pub trait MeasurementSource { fn mr_enclave(&self) -> Result<Measurement, ClientError>; }
// impls: GendataFile, FixedMeasurement, BuildOutput (from ReproducibleBuild::run)
pub trait Transport: Read + Write { fn set_read_timeout(&mut self, t: Option<Duration>) -> io::Result<()>; }
```

Mock implementations of `EnclaveBackend` and `Quoter` (an "enclave"
running `sgx-ra-core`'s `EnclaveEndpoint` in-process with a synthetic quote)
let the host and client be tested end-to-end without SGX hardware.

## 5. End-to-end flow

The full diagram, including the key binding, is in
[`extra/sequence.wsd`](../extra/sequence.wsd) (rendered in the README).

```
Client                                    Remote (untrusted host)                 Enclave (MRENCLAVE = M)
------                                    -----------------------                 -----------------------
docker build Dockerfile.nix-build ───▶ enclave.so, gendata ─▶ M_local
TLS connect ───────────────────────────▶ stunnel exec app
                                          sgx_qe_get_target_info
                                          sgx_create_enclave ───────────────────▶ load
                                          ECALL enclave_create_report ──────────▶ EK ← rand; report_data = H(EK_pub)
                                          sgx_qe_get_quote(report)
◀──────────────── u32 len ‖ quote ────────
verify quote (pinned Intel root, CRLs, TCB, QE id)
policy: mr_enclave == M_local, !DEBUG, TCB ok
HELLO(c_pub, c_nonce) ──────────────────▶ ECALL enclave_message ────────────────▶ se ← rand; derive keys
◀────────────── 00 ‖ len ‖ HELLO_REPLY ◀──────────────────────────────────────── (ek_pub, se_pub, s_nonce, confirm)
check H(ek_pub) == report_data, confirm
RECORD(seq, AEAD(req)) ─────────────────▶ ECALL enclave_message ────────────────▶ open → App::handle → seal
◀──────────── 00 ‖ len ‖ RECORD(seq, AEAD(resp))
```

## 6. Reproducible build

Implemented by `flake.nix`, `nix/` and `containers/Dockerfile.nix-build`. The
README lists the resulting MRENCLAVE.

* **Pinned inputs.** nixpkgs (`nixos-26.05` by revision), crane (v0.24.0) and
  fenix are locked by narHash in `flake.lock`. The Rust toolchain is
  `fenix.fromToolchainFile ./rust-toolchain.toml` (1.100.0 with
  `x86_64-unknown-none`), pinned by the sha256 of the rustup channel manifest,
  which in turn pins each component. The **Intel SGX SDK 2.26.100.0** is
  Intel's prebuilt Ubuntu 24.04 installer (the same file the blueprint uses),
  fetched as a fixed-output derivation by sha256 and unpacked without the
  interactive installer (`nix/sgx-sdk.nix`). Only `sgx_edger8r` and `sgx_sign`
  are patched; the trusted `.a` libraries are Intel's bits, unmodified.
  **DCAP 1.23** (`nix/dcap.nix`) is the source tree pinned by commit and hash,
  plus a headers package for the host (tasks 6/7). The enclave links nothing
  from DCAP. crane vendors every crate of `Cargo.lock` by checksum, and
  cargo runs `--offline --locked`.
* **Determinism knobs.** `SOURCE_DATE_EPOCH=315532800`;
  `--remap-path-prefix` for the source tree and vendored crates;
  `codegen-units = 1`, fat LTO, no debuginfo, no incremental (release
  profile); `-ffile-prefix-map` for the edger8r bridge; `--build-id=none`.
  Linking uses *unwrapped* gcc/binutils, so the Nix cc-wrapper adds no
  hardening flags or rpaths, and PT_INTERP is set to the FHS path, so no
  store path is measured. The `Enclave.config.xml` is fixed (blueprint layout
  values with `DisableDebug = 1`, `ProdID = 1`, `ISVSVN = 1`; see PROTOCOL
  §2.4 Q9). The Nix fixup phase is disabled, because it would otherwise
  patchelf the already-signed image.
* **Signing.** MRENCLAVE never depends on the signer. To make the *signed*
  image reproducible too, `sgx_sign` runs under libfaketime at
  `SOURCE_DATE_EPOCH`, which fixes the SIGSTRUCT date at 1980-01-01. It signs
  with the published key `enclave-sys/reproducible-signing-key.pem`, and
  PKCS#1 v1.5 signatures are deterministic. MRSIGNER therefore carries no
  trust, and clients pin MRENCLAVE. An operator who wants their own MRSIGNER
  signs `enclave.so.gendata` offline and runs `sgx_sign catsig`; MRENCLAVE
  stays the same.
* **Outputs** (`nix build .#enclave`, or `/out` of the Dockerfile's final
  `scratch` stage): `enclave.signed.so`, `enclave.so`, `enclave.so.gendata`,
  `MRENCLAVE.txt`, `MRSIGNER.txt`, `SHA256SUMS`. Before installing, the
  derivation checks that the dumped SIGSTRUCT has the gendata MRENCLAVE and
  header and the fixed date. `lib.x86_64-linux.mkEnclave { crate; }` builds
  any other enclave crate the same way (task 9).
* **Container.** `containers/Dockerfile.nix-build` is
  `FROM nixos/nix:2.36.0@sha256:…` and runs `nix build .#enclave`. It works
  with the classic builder (`docker create` + `docker cp /out`) and with
  BuildKit (`--output type=local`). Nix's own sandbox needs namespaces that
  `docker build` does not grant, so it is off, and the container is the
  isolation boundary.
* **Verification.** `scripts/nix-build-enclave.sh --verify` runs two
  `--no-cache` builds (the second from a different source directory) and
  compares **all** artifacts byte for byte, including `enclave.signed.so` and
  gendata.

## 7. Sealing (task 9)

Full design and trade-offs: [SEALING.md](SEALING.md).

* `sgx-ra-enclave::sealing` wraps `sgx_seal_data_ex`/`sgx_unseal_data` with
  the MRENCLAVE (default) or MRSIGNER key policy. On unseal it insists on the
  expected policy.
* `sgx-ra-enclave::storage` persists blobs through two OCALLs that the host
  serves from `--sealed-dir` (`enclave-sys/sealed-storage/Enclave.edl`, which
  imports the unchanged blueprint EDL). The host only sees sealed bytes and
  is trusted for availability only. It can roll blobs back.
* `sgx-ra-enclave::identity` adds an optional **long-term identity key**
  `LK`. It is sealed and persisted, and proven inside each attested session
  by a challenge-response bound to that session's `ek_pub`. Clients pin it
  with `sgx-ra-client::identity_pin`.
* The channel key `EK` is **never** sealed and stays per instance. A stable
  `EK` would make every old quote vouch for it forever, so one leak of
  `ek_sk` would allow permanent impersonation.
* `examples/sealing-enclave` + `examples/sealing-client` implement IDENTITY,
  SEAL and UNSEAL.

The echo enclave keeps the plain EDL, and its MRENCLAVE is unchanged.

## 8. Decisions and rejected alternatives

| Decision | Alternatives considered | Rationale |
|----------|-------------------------|-----------|
| no_std staticlib + Intel tRTS | Teaclave SGX SDK; Fortanix EDP; Gramine/Occlum | EDP is incompatible with the remote loader (G1). Teaclave needs a pinned nightly and a large vendored std, which is harder to make reproducible in Nix. LibOS approaches change MRENCLAVE semantics and are heavy. |
| Keep `Enclave.edl` ABI unchanged | New EDL with nonce/session ids | The remote `app` is operator-fixed (C1). Changing the EDL would break loading through the existing host. |
| X25519 + HKDF + ChaCha20-Poly1305, custom 1-RTT NK-like handshake | RA-TLS (X.509 cert with quote extension); `snow` (Noise) | The quote is sent before any client input and the 4096-byte frames are tiny, so a TLS stack in the enclave is overkill. The custom handshake is ~200 lines of `no_std` code that is easy to audit and test on both sides. |
| report_data = SHA-256(label ‖ ek_pub) ‖ 0³² | Raw key in report_data | Domain separation and versioning. The zero half is reserved for a future nonce or app id. |
| MRENCLAVE as primary identity, MRSIGNER optional | MRSIGNER-based | Reproducible builds make MRENCLAVE meaningful, and the operator's signing key is not under our control. |
| Pinned Intel root, PCCS untrusted | Trust PCCS (blueprint) | Closes the main verifier gap (PROTOCOL §4.2). |

## 9. Mapping to upcoming tasks

| Task | Scope in this design |
|------|----------------------|
| 2 | Workspace, crates of §3, traits of §4, toolchain pin |
| 3 | `sgx-ra-core`: `binding`, `handshake`, `record`, plus test vectors |
| 4 | `sgx-ra-enclave` + `examples/echo-enclave`, EDL-compatible link |
| 5 | `flake.nix`, `containers/Dockerfile.nix-build`, reproducibility check |
| 6 | `sgx-ra-host`, `.#host-app`, `.#host-app-image` (OCI, `dockerTools`), `containers/wrapper.sh` for stunnel |
| 7 | `sgx-ra-verifier` (PROTOCOL §6.6 steps 1–6) |
| 8 | `sgx-ra-client` + `examples/echo-client` |
| 9 | Sealing helpers + example |
| 10 | Compose with mock/real SGX; remote E2E (expect the §5 "PCCS unreachable" diagnostic until fixed) |
| 11 | Review against PROTOCOL §4.2 and §6 |
| 12 | User-facing docs |

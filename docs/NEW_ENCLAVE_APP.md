# Writing a new enclave application

The framework handles attestation, the key binding and the secure channel,
so you write only the application. This guide builds a hypothetical
`counter` service step by step: the enclave, its reproducible build, the
host, and a client with its own policy. The two examples in `examples/`
are complete references:

| Example | Shows |
|---|---|
| `echo-enclave` / `echo-client` | the minimum: one `EnclaveApp`, the default EDL, a full CLI client |
| `sealing-enclave` / `sealing-protocol` / `sealing-client` | a request/response protocol crate shared by enclave and client, sealing, the storage OCALLs, a long-term identity bound to the session ([SEALING.md](SEALING.md)) |

## What the framework gives you, and what you write

```
             you write                         the framework provides
 ┌──────────────────────────────┐   ┌───────────────────────────────────────────────┐
 │ enclave:  impl EnclaveApp    │   │ sgx-ra-enclave: ECALLs, identity key EK,      │
 │           export_enclave!    │   │   report_data = H(EK_pub), handshake, records,│
 │                              │   │   allocator, panic handler, SgxRng, sealing   │
 │ build:    mkEnclave {crate}  │   │ flake.nix + Dockerfile.nix-build: pinned,     │
 │                              │   │   bit-for-bit reproducible enclave.signed.so  │
 │ host:     nothing (reuse)    │   │ sgx-ra-host / echo-host-app: loads any        │
 │                              │   │   enclave with this EDL, quotes, relays bytes │
 │ client:   a Policy + your    │   │ sgx-ra-client: ReproducibleBuild, Transport,  │
 │           request format     │   │   DcapVerifier, attest_and_connect,           │
 │                              │   │   EnclaveChannel (SecureChannel)              │
 └──────────────────────────────┘   └───────────────────────────────────────────────┘
```

The reusable interfaces are defined in `sgx-ra-core` and described in
[ARCHITECTURE.md §4](ARCHITECTURE.md#4-trait-boundaries):

* `Attester`: produces evidence over 64 bytes of report data. Inside the
  enclave, `SgxAttester` implements it with `sgx_create_report`.
* `Verifier`: authenticates evidence and applies a `Policy`. It returns
  `VerifiedClaims` only if both succeed. `DcapVerifier` implements it for
  DCAP quotes.
* `Policy`: decides whether verified claims are acceptable. `EnclavePolicy`
  covers the common case.
* `SecureChannel` / `AttestedChannel`: `send`, `recv`, `request`, and the
  claims of the peer. `EnclaveChannel` implements them on the client.

You rarely implement `Attester` or `Verifier` yourself. They are the seams
for another TEE or another evidence format. Applications implement
`EnclaveApp` and usually construct or compose a `Policy`.

## 1. The enclave crate

`examples/counter-enclave/Cargo.toml`:

```toml
[package]
name = "counter-enclave"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[lib]
# staticlib: linked with Intel's trusted runtime into enclave.so.
# rlib: lets ordinary `cargo test` run the application logic on the host.
crate-type = ["staticlib", "rlib"]
doctest = false

[dependencies]
sgx-ra-enclave = { workspace = true }

[lints]
workspace = true
```

`examples/counter-enclave/src/lib.rs`:

```rust
#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;

use sgx_ra_enclave::{AppError, EnclaveApp};

/// Adds each request's 8-byte big-endian value to a running total and
/// returns the total.
#[derive(Debug, Default)]
pub struct CounterApp {
    total: u64,
}

impl EnclaveApp for CounterApp {
    fn init() -> Self {
        Self::default()
    }

    fn handle(&mut self, request: &[u8], response: &mut Vec<u8>) -> Result<(), AppError> {
        let value: [u8; 8] = request
            .try_into()
            .map_err(|_| AppError::new("request must be 8 bytes"))?;
        self.total = self
            .total
            .checked_add(u64::from_be_bytes(value))
            .ok_or(AppError::new("overflow"))?;
        response.extend_from_slice(&self.total.to_be_bytes());
        Ok(())
    }
}

sgx_ra_enclave::export_enclave!(CounterApp);
```

Add the crate to `members` in the root `Cargo.toml`.

`export_enclave!` emits the two ECALLs of `enclave-sys/Enclave.edl`
(`enclave_create_report`, `enclave_message`). It also installs the
allocator and the panic handler. The ECALLs are implemented by
`sgx_ra_enclave::Runtime`, which:

1. on the first report request, generates the identity key `EK` from
   `sgx_read_rand`, calls `CounterApp::init()`, and puts
   `SHA-256("SGXRA-v1/report-data" ‖ 0 ‖ 1 ‖ EK_pub) ‖ 0³²` into
   report_data;
2. answers the client's `HELLO` with `EK_pub`, a fresh ephemeral key and a
   key confirmation;
3. decrypts each `RECORD`, calls `handle`, and encrypts the response.

Your code never sees a key, a quote or a ciphertext.

### Rules inside the enclave

| Rule | Why |
|---|---|
| `#![no_std]` + `alloc`. Dependencies must build for `x86_64-unknown-none`. | No OS inside the enclave; the target has no `std`. |
| No `cpuid`/`rdtsc`; crypto crates must use their portable backends (`.cargo/config.toml` already forces this for the RustCrypto crates). | Both instructions fault (`#UD`) in an SGX enclave. |
| Requests and responses are at most `MAX_RESPONSE_LEN` (4071) bytes. Chunk larger data in your own request format. | One record must fit the executor's 4096-byte buffers ([PROTOCOL.md §6.3](PROTOCOL.md#63-message-types-first-byte-of-every-layer-1-payload)). |
| Returning `Err` from `handle` ends the session. The client sees only a failure status; the message stays inside. Return application-level errors *in the response* if the client should keep the session. | Error details could leak secrets; a failing session is wiped. |
| A panic aborts the enclave. | `panic = "abort"`, nothing unwinds across the FFI boundary ([THREAT_MODEL.md §4.11](THREAT_MODEL.md#411-panicabort-across-the-ffi-boundary--ok)). |
| State lives as long as one enclave instance. The executor creates one instance per connection, and each instance accepts one handshake. To keep data across connections, seal it ([SEALING.md](SEALING.md)). | A fresh `EK` per instance gives forward secrecy and makes old quotes useless. |
| The default heap is 1 MiB and the stack 256 KiB (`enclave-sys/Enclave.config.xml`). Pass `enclaveConfig = ./my/Enclave.config.xml;` to `mkEnclave` to change them. | The layout is measured, so any change is a new MRENCLAVE. |
| Do not invent a "get public key" ECALL. Keep the EDL unchanged, or use `enclave-sys/sealed-storage/Enclave.edl` if you need sealed storage. | The operator's existing host only knows this ABI, and `EK_pub` already travels in the handshake. |

If a response must be bound to the attested session (for example a
signature that a third party will check), override
`EnclaveApp::handle_with_context`. Its `SessionContext` exposes the
session's `EK_pub`. `sealing-enclave` uses it for its long-term identity
proof.

### Unit tests

Because the crate is also an `rlib` and `no_std` applies only outside
`cfg(test)`, plain `cargo test -p counter-enclave` runs the logic on the
host:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds() {
        let mut app = CounterApp::init();
        let mut out = Vec::new();
        app.handle(&5u64.to_be_bytes(), &mut out).unwrap();
        assert_eq!(out, 5u64.to_be_bytes());
    }
}
```

For tests through the real ECALLs without SGX hardware, see
[enclave-sys/README.md](../enclave-sys/README.md#testing-without-sgx-hardware).

## 2. The reproducible build

Add one line to `packages` in `flake.nix`:

```nix
counter-enclave = mkEnclave { crate = "counter-enclave"; };
# with sealed storage:   mkEnclave { crate = "…"; edl = "enclave-sys/sealed-storage/Enclave.edl"; }
# with another layout:   mkEnclave { crate = "…"; enclaveConfig = ./path/Enclave.config.xml; }
```

Build it in the pinned Nix container, and check that two clean builds are
bit-for-bit identical:

```sh
scripts/nix-build-enclave.sh --enclave counter-enclave           # -> target/nix-enclave/counter-enclave/
scripts/nix-build-enclave.sh --enclave counter-enclave --verify
```

The client selects the same attribute with the build argument
`ENCLAVE=counter-enclave` (`containers/Dockerfile.nix-build`). Publish the
resulting MRENCLAVE next to your source, as the README does for the echo
enclave. [REPRODUCIBILITY.md](REPRODUCIBILITY.md) explains how others
reproduce it.

## 3. The host: reuse it

The untrusted host is application-independent. It loads an
`enclave.signed.so`, sends the quote and forwards opaque bytes. Use
`echo-host-app` as is:

```sh
echo-host-app --enclave target/nix-enclave/counter-enclave/enclave.signed.so --listen 127.0.0.1:7000
```

To get a container image of your enclave with the host and Intel's
runtime, add to `flake.nix`:

```nix
counter-host-image = mkHostImage {
  hostApp = echo-host-app;
  enclave = counter-enclave;
  name = "counter-host";
};
```

Then run `scripts/nix-build-host-image.sh --attr counter-host-image`, or
`nix build .#counter-host-image`. The blueprint's C++ `app` also loads the
enclave unchanged, because the EDL is the same. Write your own host (a
binary calling `sgx_ra_host::cli::main`, built with `mkHostApp`) only if
you need different storage or transport.

## 4. The client

Add `sgx-ra-client = { workspace = true }` to a binary crate. The whole
trust decision fits in a few lines:

```rust
use std::path::Path;

use sgx_ra_client::sgx_ra_core::{EnclavePolicy, SecureChannel};
use sgx_ra_client::transport::connect_tls;
use sgx_ra_client::{
    ContainerEngine, OsRng, PccsConfig, ReproducibleBuild, TlsVerification, VerifierOptions,
    attest_and_connect, dcap_verifier,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. What must run remotely: MRENCLAVE from our own reproducible build.
    let engine = ContainerEngine::detect().ok_or("docker or podman is required")?;
    let build = ReproducibleBuild::new(engine, "containers/Dockerfile.nix-build", ".")
        .build_arg("ENCLAVE", "counter-enclave")
        .run(Path::new("target/counter-build"))?;

    // 2. What we accept. Baseline (always enforced): no DEBUG, 64-bit.
    let policy = EnclavePolicy::new(build.mr_enclave())
        .with_isv_prod_id(1)
        .with_min_isv_svn(1);

    // 3. How quotes are authenticated: DCAP, collateral from Intel's PCS,
    //    everything checked against the pinned Intel SGX Root CA.
    let verifier = dcap_verifier(PccsConfig::intel_pcs(), VerifierOptions::default())?;

    // 4. Untrusted transport. TLS is not part of the trust chain.
    let tls = connect_tls("enclave.example.org", 443, &TlsVerification::WebPki)?;

    // 5. Quote -> verify -> policy -> handshake bound to report_data.
    let mut channel = attest_and_connect(tls, &verifier, &policy, &mut OsRng)?;

    let total = channel.request(&5u64.to_be_bytes())?;
    println!("total = {}", u64::from_be_bytes(total.as_slice().try_into()?));
    Ok(())
}
```

`attest_and_connect` returns a channel only if all of these hold: the
quote verifies up to Intel's root, the policy accepts the claims, the
enclave's channel key hashes to the attested report_data, and the enclave
proved it holds that key. Any other outcome is an error, so a returned
channel is always safe to use.

Sources of the expected measurement, all implementing
`MeasurementSource`:

* `BuildOutput` from `ReproducibleBuild::run`: the client builds the
  enclave itself. This is the strongest option.
* `GendataFile`: an `enclave.so.gendata` from an earlier build of your own.
* `FixedMeasurement`: a hex MRENCLAVE you got from a source you trust.

For a local PCCS, use
`PccsConfig::pccs("https://127.0.0.1:8081").with_ca_pem(pem)`. For a plain
TCP host, use `sgx_ra_client::transport::connect_tcp(host, port)`. For
step-by-step control and diagnostics (for example, rejecting a wrong
MRENCLAVE before fetching any collateral), use `ExecutorConnection`,
`DcapVerifier::verify_detailed` and `EnclaveChannel::establish` the way
`examples/echo-client/src/run.rs` does.

### Defining the policy

`EnclavePolicy` pins MRENCLAVE and, optionally, MRSIGNER
(`with_mr_signer`), ISVPRODID, a minimum ISVSVN, and the accepted TCB
statuses (default: only `UpToDate`; widen with `allow_tcb_status`). Pin
MRENCLAVE. MRSIGNER alone is not enough with this framework's builds,
because they are signed with a published key
([THREAT_MODEL.md §2](THREAT_MODEL.md#2-actors-and-trust-assumptions)). If
you re-sign with a private key, MRSIGNER is useful as an additional pin.

For anything else, implement `Policy`. The verifier always runs the
baseline (no DEBUG, 64-bit) before your policy, so a custom policy cannot
admit a debug enclave by mistake. For example, during a rollout you may
want to accept either of two reproducibly built releases:

```rust
use sgx_ra_client::sgx_ra_core::{EnclavePolicy, Policy, PolicyViolation, VerifiedClaims};

/// Accepts the claims if any of the policies does.
struct AnyOf(Vec<EnclavePolicy>);

impl Policy for AnyOf {
    fn check(&self, claims: &VerifiedClaims) -> Result<(), PolicyViolation> {
        let mut first_error = None;
        for policy in &self.0 {
            match policy.check(claims) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    first_error.get_or_insert(e);
                }
            }
        }
        Err(first_error.expect("AnyOf needs at least one policy"))
    }
}
```

### Designing the request format

The channel carries opaque byte strings of up to 4071 bytes, in strict
request/response order. Put the message types in a small `no_std` crate
that both the enclave and the client depend on, as `sealing-protocol` does.
Keep in mind:

* The enclave does not know who the client is: authentication is one-way,
  like server-only TLS. If the application needs client identity, send a
  credential in the first request
  ([THREAT_MODEL.md TM-11](THREAT_MODEL.md#tm-11-one-way-authentication)).
* The host sees the length and timing of every record. Pad messages if
  their length reveals something.
* The quote carries no client nonce. Freshness comes from the handshake
  and from evaluating TCB status against current collateral
  ([THREAT_MODEL.md TM-4](THREAT_MODEL.md#tm-4-quotes-carry-no-client-freshness)).

## 5. Checklist

- [ ] `EnclaveApp` implemented, `export_enclave!` called, unit tests pass.
- [ ] Crate added to the workspace, `mkEnclave` entry added to `flake.nix`.
- [ ] `scripts/nix-build-enclave.sh --enclave <attr> --verify` reports identical builds.
- [ ] MRENCLAVE published next to the source.
- [ ] Client pins MRENCLAVE from a build of its own, through `EnclavePolicy` or a `Policy` that delegates to it.
- [ ] Request format fits 4071 bytes per message; errors that should not end the session are returned in the response.
- [ ] Deployment: the operator puts `enclave.signed.so` behind the executor (`containers/wrapper.sh` or their own host). The client never has to trust this step.

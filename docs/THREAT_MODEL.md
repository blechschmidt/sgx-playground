# Threat model and security review

This document states what the `sgx-ra` framework protects, against whom, and
on which assumptions. It also records the security review of the trust chain
and the attested channel (task 11, 2026-11-23): each item that was checked,
the evidence for it, the fixes made, and the issues that remain open.

Related documents: [PROTOCOL.md](PROTOCOL.md) (wire formats, handshake,
acceptance policy), [ARCHITECTURE.md](ARCHITECTURE.md) (components,
reproducible build), [SEALING.md](SEALING.md) (sealing and the long-term
identity key, with its own host-threat table in §2.1).

> **Hardware coverage.** The review was first done without a working
> executor; the statements below were backed by code review, unit tests,
> the recorded real quote `fixtures/quote_v3.dat` with recorded Intel
> collateral, synthetic PKIs and SGX simulation runs. Since 2026-11-24 the
> full flow also passes against the public executor on real SGX hardware
> ([TM-10](#tm-10-no-end-to-end-run-on-sgx-hardware), resolved).

---

## 1. Assets

| Asset | Where it lives | Must never |
|---|---|---|
| `ek_sk`, the enclave channel identity key (X25519, one per enclave instance) | Enclave heap (`Runtime` static) | leave the enclave, be sealed, or be reused across instances |
| `se_sk`, the per-handshake enclave ephemeral | Enclave stack, dropped after the handshake | leave the enclave |
| Session keys `k_c2e`, `k_e2c` (ChaCha20-Poly1305) | Enclave `Session` / client `Session` | leave either endpoint |
| Application plaintext (requests/responses) | Client and enclave only | be visible to the host, operator, TLS terminator or network |
| `lk_sk`, the optional long-term identity key | Enclave; on disk only as a sealed blob | leave the enclave unsealed |
| Client-sealed data (sealing example) | Sealed blob held by the client | be unsealed by anyone without the blob |
| Client's decision "this is the enclave I built" | Client verifier and policy | be made on unauthenticated data |

## 2. Actors and trust assumptions

| Actor | Trusted for | Not trusted for |
|---|---|---|
| **Client machine** and the person running it | Everything on the client side (build, verifier, policy) | — |
| **Intel**: CPU, microcode, QE3/PCE, the SGX Root CA and the PCS signing keys | Enclave isolation and attestation signatures, to the extent the platform's TCB status says | Being free of side channels on a platform whose TCB is not `UpToDate` |
| **Enclave code** (this repository, at the MRENCLAVE the client rebuilt) | Doing what its source says | — (it is the thing being verified) |
| **Build inputs**: Nix flake inputs, `Cargo.lock` crates, Rust toolchain, Intel SGX SDK tarball, `nixos/nix` image (all pinned by hash) | Producing the binary that the source describes | — see [TM-12](#tm-12-build-supply-chain) |
| **Operator / untrusted host**: the machine, OS, hypervisor, the host app (`app` or `echo-host-app`), stunnel, `wrapper.sh` | Nothing but availability | Confidentiality, integrity, freshness of anything |
| **Network and TLS** (stunnel's certificate, Let's Encrypt) | Nothing | Anything. TLS is an outer pipe; it ends outside the enclave (PROTOCOL.md §1) |
| **PCCS / Intel PCS transport** | Availability of collateral | Authenticity: every document is verified against the pinned Intel root |
| **Enclave signer** (holder of the SIGSTRUCT key) | Nothing. The signing key is published on purpose (`enclave-sys/reproducible-signing-key.pem`) | MRSIGNER carries no trust; clients pin MRENCLAVE |

The attacker we design against is the **operator with root on the SGX host**,
who can also sit on the network path, run arbitrary enclaves (including
re-signed copies of ours), call our ECALLs in any order with any arguments,
replay old quotes, and serve stale or forged collateral. They cannot break
SGX's memory encryption and isolation on a platform whose TCB status the
client accepts, nor forge Intel signatures.

Out of scope: denial of service (the operator can always refuse service),
physical attacks beyond SGX's threat model, and attacks on the client
machine.

## 3. The trust chain, end to end

```
source tree ──Nix container (pinned)──▶ enclave.so ──sgx_sign gendata──▶ MRENCLAVE_expected      (client, local)
                                                                              │
remote:  enclave (MRENCLAVE) ── EREPORT(report_data = H(label‖0‖ver‖ek_pub)) ─┤
          QE3 signs report  ── PCK cert ── PCK CA ── Intel SGX Root CA ◀── pinned in the client
          TCB Info / QE Identity / CRLs ── TCB signing cert ── same pinned root
                                                                              │
client:  verify quote + collateral + TCB status + baseline + policy ──▶ VerifiedClaims
         HELLO(c_pub, c_nonce) ──▶ enclave
         ◀── HELLO_REPLY(ek_pub, se_pub, s_nonce, confirm)
         require report_data == H(label‖0‖ver‖ek_pub)   (exact, 64 bytes, constant time)
         th = H(label ‖ SHA-256(report_body) ‖ c_pub ‖ c_nonce ‖ ek_pub ‖ se_pub ‖ s_nonce)
         keys = HKDF(th, DH(c,ek) ‖ DH(c,se));  require confirm == HMAC(k_conf, label ‖ th)
         records: ChaCha20-Poly1305, per-direction keys, strict sequence numbers
```

Each arrow is checked by code in this repository; the review items in §4
reference that code.

## 4. Review findings

Verdicts: **OK** (meets the requirement, no change), **FIXED** (changed in
this review), **OPEN** (filed in §6), **ACCEPTED** (documented residual risk).

### 4.1 report_data binding: full key, version, domain separation — OK

`crates/sgx-ra-core/src/binding.rs:41`:

```
report_data[0..32]  = SHA-256("SGXRA-v1/report-data" ‖ 0x00 ‖ PROTOCOL_VERSION ‖ ek_pub[32])
report_data[32..64] = 0
```

* The **whole** 32-byte X25519 public key is hashed; there is no truncation.
  X25519 public keys are exactly 32 bytes, so there is no encoding ambiguity.
* The label and the `0x00` terminator separate this use of REPORTDATA from
  any other (e.g. the blueprint's constant `SHA-256(0^64)`), and the version
  byte separates protocol versions. The label is fixed-length and comes
  first, so the hash input is prefix-free.
* The client compares all 64 bytes, including the reserved zero half, in
  constant time (`binding.rs:66`), and does so **before** it derives any key
  (`handshake.rs:604`). A known-answer test pins the construction
  (`binding.rs` tests, independently computed with Python `hashlib`).
* `respond()` also checks the binding on the enclave side before answering
  (`handshake.rs:651`), so a framework bug that paired the wrong key with a
  report would fail closed instead of producing an unverifiable session.

### 4.2 No TOCTOU between quote and key — OK

* `ek` is generated **once**, on the first `enclave_create_report`, and every
  later call reuses it (`crates/sgx-ra-enclave/src/runtime.rs:162`). A host
  cannot obtain reports for two different keys from one instance, and no
  ECALL rotates or replaces the key. Test:
  `report_commits_to_a_stable_identity_key`.
* After `sgx_create_report` the runtime re-checks that the report it got
  back carries exactly the expected report_data (`runtime.rs:188`), and stores
  that very report body for the transcript.
* The enclave answers at most **one** `HELLO` per instance; the state moves
  to `Closed` before the handshake runs, so even a failing handshake burns it
  (`crates/sgx-ra-core/src/session.rs`, `EndpointState`).
* On the client, the quote is verified once and the result is a value
  (`VerifiedClaims` holds a copy of the authenticated report body). The
  handshake uses that copy; the raw quote is never re-parsed after
  verification, so there is no window in which the checked bytes and the used
  bytes can differ.
* The key is sent one message *after* the quote (`HELLO_REPLY`), not in the
  host-built announcement frame. That is not a TOCTOU: the client requires
  `report_data == report_data_for(ek_pub)` before using `ek_pub`
  (PROTOCOL.md §6.4, "Why `ek_pub` travels in `HELLO_REPLY`").
* Calling `enclave_create_report` again with a different `TARGETINFO`
  changes only the MAC of the local report, not its body; the transcript
  hash is unaffected.

### 4.3 Transcript binding, MITM and the untrusted host — OK

The host relays every message and can drop, reorder, replay, modify or inject
any of them, and can call the ECALLs itself. Analysis of each move:

| Host action | Result |
|---|---|
| Replace `c_pub` in `HELLO` with its own key | The enclave's `confirm` is over a transcript with the host's key; the client's `th` differs, so `confirm` fails (constant-time compare). The host cannot compute a valid `confirm` for the client's `c_pub` without `ek_sk`. |
| Replace `ek_pub` / `se_pub` / `s_nonce` in `HELLO_REPLY` | `ek_pub` must match report_data. Changing `se_pub` or `s_nonce` changes `th` and the DH output, so `confirm` fails. |
| Replay a `HELLO_REPLY` from an earlier session | `th` contains the client's fresh `c_pub` and `c_nonce`; `confirm` fails. |
| Replay an old quote of a genuine enclave | The quote commits to that instance's `ek_pub`. Only the instance holding `ek_sk` can answer; if it is still running, the client is talking to a genuine enclave. TCB status is evaluated against **current** collateral, not the quote's age ([TM-4](#tm-4-quotes-carry-no-client-freshness)). |
| Present a quote of a *different* genuine enclave (other MRENCLAVE, other platform) | Rejected by policy (MRENCLAVE) or by the binding check (different `ek_pub`). `rb_hash` in `th` binds the channel to the exact attested report body (MRENCLAVE, attributes, SVNs, report_data). |
| Run the handshake itself before the client does | The instance's one handshake is consumed; the real client's `HELLO` fails. Denial of service only. The host has then established a channel *as a client*, which one-way authentication permits ([TM-11](#tm-11-one-way-authentication)). |
| Splice records between directions or sessions | Separate keys per direction and per session; AAD contains type and sequence number. |
| Drop, reorder or replay records | Strict next-sequence check in both directions; any failure wipes the session (`record.rs`, `session.rs`) and the enclave returns one opaque error code. |
| Truncate the session | Detectable only at the application layer (as in TLS without close_notify); request/response lockstep means the client always knows whether it got the reply. |
| Downgrade to plaintext | No such mode exists. A non-zero layer-1 status is fatal to the session. |
| Feed the enclave malformed messages | Strict fixed-length decoding; unknown types and versions are rejected; a failed pre-handshake message does not burn the handshake, any later failure closes the session. |

Key confirmation is enclave → client only, and the client's first record
implicitly authenticates the client's possession of `c_sk`. Both DH results
(`DH(c, ek)` for authentication, `DH(c, se)` for forward secrecy) enter the
KDF, and low-order points are rejected (`was_contributory`,
`handshake.rs:524`).

### 4.4 Nonce handling — OK

* **Handshake nonces.** `c_nonce` (client OS RNG via `getrandom`) and
  `s_nonce` (`sgx_read_rand`, i.e. RDRAND inside the enclave) are 32 random
  bytes each and both enter `th`. Fresh ephemeral keys on both sides already
  make `th` unique; the nonces are defence in depth against a weak RNG on
  either side.
* **AEAD nonces.** `nonce = 00000000 ‖ seq` (4 zero bytes, then `seq` as a
  big-endian u64; `record.rs:248`) under keys
  that are unique per direction and per session, with `seq` strictly
  incrementing from 0. A key/nonce pair can therefore never repeat. The
  sequence counter refuses to wrap (`MAX_SEQ`), closing the session.
* RNG failure in the enclave aborts the operation and leaves the runtime
  uninitialised (`rng_failure_leaves_runtime_uninitialised`); the code never
  falls back to a weaker source.

### 4.5 Key zeroization inside the enclave — OK, hardened (FIXED), residue ACCEPTED

| Secret | Mechanism |
|---|---|
| `ek_sk`, `se_sk`, `c_sk`, `lk_sk` (`StaticSecret`) | `x25519-dalek` with feature `zeroize`: zeroed on drop |
| DH outputs (`SharedSecret`) | zeroed on drop (same feature) |
| HKDF input `ikm`, `k_c2e`, `k_e2c`, `k_conf` | `Zeroizing<[u8; N]>` (`handshake.rs:524`) |
| Cipher instances | `chacha20poly1305 0.10.1` zeroes its key on drop (unconditional `Drop` impl); `chacha20` keystream state with its `zeroize` feature |
| Session on error or close | `Session::close()` drops the ciphers immediately (wipe-on-error) |
| Random bytes for keys | `Zeroizing` buffer in `random_secret` |
| Sealing plaintext buffers, `lk_sk` bytes | `Zeroizing` (`crates/sgx-ra-enclave/src/sealing.rs`, `identity.rs`) |

**Fixed in this review:** the enclave allocator returned freed blocks to the
heap without wiping them, so decrypted requests, responses, sealing
plaintexts and the old buffers of grown `Vec`s stayed in enclave memory. The
`SgxAllocator` now zeroes every block with volatile writes before `free`
(`crates/sgx-ra-enclave/src/allocator.rs:43`). A plain `memset` would not do:
LLVM deletes stores to memory that is freed right after.

**Accepted residue:** byte copies on the **stack** are not scrubbed. These
include the `[u8; 32]` temporaries that `StaticSecret::from` and
`to_bytes` move, and the keyed HMAC/HKDF states (`hmac 0.12` has no
`zeroize` support). The stack lies in EPC memory, is never copied out (the
ECALL glue writes only the reply and zeroes the rest of the 4096-byte
output buffer, `runtime.rs:309`), and the enclave has one TCS. Reading it
requires a memory-disclosure bug in enclave code, which would expose the
live keys anyway. The keys that live longest (`ek_sk`, `lk_sk`) are never
dropped before the instance ends; on `sgx_destroy_enclave` the EPC pages are
removed by the hardware.

### 4.6 Debug enclave rejection — OK, hardened (FIXED)

Three independent layers:

1. **Launch.** `Enclave.config.xml` sets `DisableDebug = 1`. The generated
   SIGSTRUCT has `ATTRIBUTES.FLAGS = 0x4` with mask `0xff00ffffffffffff`
   (checked in `target/nix-enclave/*/enclave.so.gendata` at offsets
   156/172), so EINIT refuses a DEBUG launch of the image we sign. The Rust
   host also always launches with `debug = 0`
   (`crates/sgx-ra-host/src/sgx/enclave.rs:19`).
2. **Verifier (new).** Anyone can re-sign our `enclave.so` with a permissive
   mask: MRENCLAVE stays the same, only MRSIGNER changes. So the decisive
   check is on the quote. Until this review it lived only in
   `EnclavePolicy::check`; a caller passing a custom `Policy` to
   `DcapVerifier` could accept a DEBUG enclave by mistake. It is now a
   separate `check_baseline` (`crates/sgx-ra-core/src/attestation.rs:396`,
   DEBUG clear and MODE64BIT set) that `DcapVerifier` applies **before**
   any caller policy (`crates/sgx-ra-verifier/src/verify.rs:311`). Test:
   `debug_enclave_is_rejected_even_by_a_permissive_policy`.
3. **Policy.** `EnclavePolicy` starts with the same baseline check and has no
   switch to relax it.

Other attributes (`PROVISION_KEY`, `KSS`, XFRM, MISCSELECT, CONFIGID) are not
checked by the client. Our SIGSTRUCT pins them; a re-signed copy could change
them, but none of them weakens confidentiality: the enclave never reads
CONFIGID or uses the provisioning key. Tracked as hardening
[TM-6](#tm-6-attributes-beyond-debug-are-not-pinned).

### 4.7 TCB status policy defaults — OK

* Library default: **`UpToDate` only** (`EnclavePolicy::new`,
  `attestation.rs`, `TcbStatusSet::up_to_date_only()`). Statuses are added
  only through explicit `allow_tcb_status` calls.
* `echo-client` default: every status except `Revoked`, so that it works
  against the public executor, a KVM guest whose operator cannot update
  the platform TCB (`OutOfDateConfigurationNeeded`). A non-`UpToDate`
  platform is reported with a warning naming the Intel advisories.
  `--strict-tcb` restores `UpToDate` only, and `--allow-tcb-status` narrows
  the set to `UpToDate` plus the listed statuses. Accepting an out-of-date
  platform means trusting that the listed advisories are not exploited
  against it.
* `Revoked` is a hard verifier error (`verify.rs`, `VerifyError::TcbRevoked`)
  that no policy can allow.
* The QE's TCB status is merged with the platform's like Intel's QVL does
  (`converge_tcb_status`, `crates/sgx-ra-verifier/src/tcb.rs:403`): an
  out-of-date QE makes the result `OutOfDate`.
* TCB levels are selected by comparing all 16 CPUSVN components and the PCE
  SVN of the **PCK certificate** (from the quote, chained to Intel) against
  the signed TCB Info. FMSPC and PCE-ID must match the PCK certificate.
* Advisory IDs are surfaced in `VerifiedClaims::advisory_ids`.
* Collateral freshness: no grace by default (`--collateral-grace 0`);
  certificates never get grace.

Operational note: many deployed platforms report `SWHardeningNeeded` (for
example INTEL-SA-00334, LVI) and will be rejected by default. Accepting that
status is a real risk decision for this framework, because our enclave is
**not** built with LVI mitigations ([TM-1](#tm-1-enclave-not-built-with-lvi-mitigations)).

### 4.8 PCCS trust: HTTP vs HTTPS, Intel root pinning — OK, residue ACCEPTED

* The only trust anchor is the compiled-in Intel SGX Root CA
  (`crates/sgx-ra-verifier/src/pki.rs`, SHA-256
  `44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3`). The
  root in the quote's certification data must be **byte-identical** to it
  (`verify.rs:133`), and the TCB-signing chains of TCB Info and QE Identity
  must chain to it too. Nothing from the PCCS or the quote can replace the
  anchor. This closes the blueprint gap of trusting whatever root the PCCS
  serves (PROTOCOL.md §4.2).
* Every collateral document is signature-checked: Root CA CRL, PCK CRL
  (signed by the issuing PCK CA, which must match), TCB Info and QE Identity
  JSON signatures. The PCK **leaf** and the intermediate are checked against
  the CRLs.
* Default collateral source: Intel PCS over HTTPS with WebPKI roots
  (`--pccs-url https://api.trustedservices.intel.com`). Plain HTTP is
  accepted for a PCCS (the blueprint uses `http://127.0.0.1:8080`) because
  transport security adds no authenticity here.
* **Residual risk (ACCEPTED, inherent to DCAP):** whoever controls the
  collateral path can serve **older but still valid** collateral: a TCB
  Info, QE Identity or CRL issued before a TCB recovery or a revocation, as
  long as its `nextUpdate` has not passed (Intel's documents are typically
  valid for about 30 days). This delays the effect of a revocation; it cannot
  make an unsigned document acceptable. Mitigations: use Intel PCS over
  HTTPS (the default), keep `--collateral-grace 0`, and optionally require a
  minimum `tcbEvaluationDataNumber` (reported in `VerifiedQuote`)
  ([TM-7](#tm-7-collateral-rollback-within-its-validity-window)).
* `--pccs-ca` pins the PCCS's TLS CA, and `insecure_skip_tls_verify` exists
  for self-signed PCCS deployments. Both affect only availability and
  privacy (the FMSPC identifies the platform model).

### 4.9 Side channels of the crypto crates inside SGX — OK, residue OPEN

* The enclave target `x86_64-unknown-none` is forced onto the **portable,
  constant-time backends**: `curve25519_dalek_backend="serial"`,
  `chacha20_force_soft`, `poly1305_force_soft` (`.cargo/config.toml`) and
  `sha2`'s soft backend (`sgx-ra-core/force-soft`). This also avoids CPUID,
  which raises `#UD` inside SGX.
* All four primitives run without secret-dependent branches or memory
  accesses: X25519 uses a Montgomery ladder with constant-time swaps and
  clamped scalars; ChaCha20, Poly1305 and SHA-256 are ARX/arithmetic only.
  An SGX attacker who single-steps the enclave (SGX-Step) or observes page
  faults or cache lines (controlled channel, Prime+Probe) sees the same
  trace for every key.
* MAC, tag and binding comparisons use `subtle::ConstantTimeEq`;
  ChaCha20-Poly1305 verifies tags in constant time.
* Error handling leaks only one bit, success or failure: every protocol
  failure maps to the single status `SGX_ERROR_UNEXPECTED`
  (`EcallError::status`), so the host cannot tell a bad tag from a bad
  sequence number.
* Sealing uses the SDK's `sgx_seal_data_ex` / `sgx_unseal_data` (AES-GCM via
  AES-NI in `sgx_tcrypto`), which is constant time.
* Message **lengths** and timing between messages are visible to the host;
  the record layer does not pad. Applications whose message sizes are
  secret must pad themselves.
* **Not mitigated:** transient-execution attacks against the enclave code
  itself (LVI, MMIO stale data). These require compiler hardening, which the
  Rust enclave build does not have ([TM-1](#tm-1-enclave-not-built-with-lvi-mitigations)),
  or a platform whose TCB is `UpToDate` for them.

The client-side `p256 0.13` dependency (RUSTSEC-2026-0387 via
`crypto-bigint`) is used only to verify **public** ECDSA signatures over
public data, so its timing behaviour leaks nothing secret
([TM-3](#tm-3-p256-advisory-rustsec-2026-0387)).

### 4.10 Private keys never leave the enclave: EDL audit — OK

The enclave's entire interface with the untrusted world:

| Interface | Direction | What crosses | Can it carry a secret? |
|---|---|---|---|
| ECALL `enclave_create_report`, `[in] p_qe3_target` | in | QE TARGETINFO (512 B) | — |
| ECALL `enclave_create_report`, `[out] p_report` | out | `sgx_report_t`: body (public) and a MAC keyed for the QE | No: report_data is a **hash of the public key** |
| ECALL `enclave_message`, `[in,count=4096] p_data`, `data_size` | in | layer-2 message | — |
| ECALL `enclave_message`, `[in,out,count=4096] p_response` | out | `HELLO_REPLY` (public keys, nonce, MAC) or a sealed `RECORD`. The unused tail is zeroed by the enclave before every return (`runtime.rs:309`), so the 4096 bytes copied out hold nothing else | No |
| ECALL `enclave_message`, `[out] p_response_size` | out | reply length | No |
| return value of both ECALLs | out | `sgx_status_t`; protocol errors collapse to one code | No |
| OCALL `sgx_ra_ocall_store_sealed` (sealed-storage EDL only), `[in, size=blob_len] p_blob` | out | `sgx_sealed_data_t` blob from `sgx_seal_data_ex` | No: AES-GCM under a CPU-derived key |
| OCALL `sgx_ra_ocall_store_sealed`, `[in,count=32] p_namespace`, `slot`, `replace` | out | a hash of policy and MRENCLAVE/MRSIGNER, a slot number, a flag | No |
| OCALL `sgx_ra_ocall_load_sealed` | in | blob copied into enclave memory by the bridge before parsing; reported length bounded by `capacity` (`storage.rs:202`) | — |

* The plain `enclave-sys/Enclave.edl` (echo enclave) declares **no OCALLs**
  and imports no SDK EDLs, so the edger8r bridge contains no OCALL stubs at
  all. The sealed-storage EDL adds exactly the two above.
* No `[user_check]` pointers exist. The ECALL glue still re-checks that all
  pointers lie inside the enclave (`sgx_is_within_enclave`), so a future
  EDL change to `user_check` would fail closed.
* There is no logging, no `printf`, and no debug output from the enclave.
  `Debug` impls of key types print public halves only
  (`finish_non_exhaustive`).
* `ek_sk` is never sealed, exported or exposed to `EnclaveApp`:
  applications receive only `SessionContext::identity_public_key()`.
  `IdentityKey::secret_bytes()` is public API, used only to seal `lk_sk`
  ([TM-2](#tm-2-unchecked-constructors-in-the-public-api)).
* The sealing example's UNSEAL request refuses any blob whose authenticated
  additional data is not `CLIENT_DATA_AAD`
  (`examples/sealing-enclave/src/lib.rs:140`), so it cannot be used as an
  oracle to unseal the identity blob. The identity blob's AAD names purpose,
  policy, slot and `lk_pub`, and MRSIGNER-policy identities are refused while
  the enclave is signed with the published key (`identity.rs:173`).

### 4.11 panic=abort across the FFI boundary — OK

* The enclave staticlib is built for `x86_64-unknown-none`, where `panic =
  "abort"` is the only strategy, and the workspace sets `panic = "abort"`
  for `dev` and `release` (`Cargo.toml:72`). No unwinding frame can reach
  the C bridge.
* `export_enclave!` installs a `#[panic_handler]` that calls the tRTS
  `abort()` (`crates/sgx-ra-enclave/src/lib.rs:149`). This puts the enclave
  into the crashed state, and every later ECALL fails with
  `SGX_ERROR_ENCLAVE_CRASHED`, so no half-updated secret state is ever
  observable. The panic message is discarded, so nothing leaks through it.
* Allocation failure (heap exhausted; `HeapMaxSize` 1 MiB) ends in the same
  abort. This is a denial of service only, which the host can cause anyway.
* The `Runtime` busy flag turns re-entrant or concurrent ECALLs into
  `Busy` errors instead of aliasing `&mut` state (`TCSNum = 1` makes this
  unreachable with the shipped config).
* On the untrusted side, OCALL implementations in `sgx-ra-host` are
  `extern "C"` Rust functions. With `panic = "abort"`, and since Rust 1.81
  aborts on any unwind out of an `extern "C"` function anyway, a host panic
  cannot unwind into the SGX bridge. That is host-side availability only.

### 4.12 Bounds on the 4096-byte ECALL buffers — OK

| Place | Check |
|---|---|
| Enclave glue (`runtime.rs:294`) | `data_size > 4096` → `INVALID_PARAMETER` before any read; the input slice is `p_data[..data_size]` only |
| Enclave runtime | input > 4096 rejected again; reply > 4096 rejected (unreachable: the record layer caps plaintext at 4071 bytes) |
| Enclave reply | written to `p_response[..len]`, the tail zeroed, `*p_response_size = len ≤ 4096` |
| Record decoding (`handshake.rs`) | length ≥ 25 and ≤ 4096; `HELLO`/`HELLO_REPLY` exact lengths; version byte checked |
| Rust host, request (`crates/sgx-ra-host/src/serve.rs:109`) | `0` and `> 4096` end the session before allocating; payload copied into a 4096-byte heap buffer |
| Rust host, ECALL wrapper (`sgx/enclave.rs:97`, `:132`) | request length in `1..=4096`; enclave-reported response size > 4096 is an error, not a slice |
| Client (`sgx-ra-core/src/wire.rs:257`, `sgx-ra-client/src/executor.rs`) | refuses to send > 4096; response length > 4096 and quote length > 64 KiB rejected; text diagnostics detected; read timeouts |
| Blueprint C++ `app` (operator's, not ours) | Has **no** bounds check (PROTOCOL.md Q2), so a request over 4096 bytes overflows its stack. Our client never sends one. This is a bug in the operator's host and cannot affect the enclave, whose bridge copies exactly 4096 bytes |

## 5. Changes made in this review

| Change | Files |
|---|---|
| `check_baseline` (DEBUG clear, MODE64BIT set) factored out of `EnclavePolicy`, and enforced by `DcapVerifier` before any caller policy | `crates/sgx-ra-core/src/attestation.rs`, `crates/sgx-ra-verifier/src/verify.rs`, test in `crates/sgx-ra-verifier/src/tests_dcap.rs` |
| Enclave allocator zeroes freed blocks with volatile writes | `crates/sgx-ra-enclave/src/allocator.rs` |
| This document; MRENCLAVE in `README.md` updated, because the allocator change alters the enclave binary | `docs/THREAT_MODEL.md`, `README.md` |

## 6. Open issues

The repository has no issue tracker, so issues are filed here. Each has a
severity under the threat model of §2.

### TM-1: Enclave not built with LVI mitigations

*Severity: medium (platform dependent).* The SGX SDK ships LVI-hardened
variants of its trusted libraries, and C/C++ enclaves are built with
`-mlvi-hardening`. Our Rust code is built for `x86_64-unknown-none` without
the LLVM `lvi-load-hardening`/`lvi-cfi` features, and links the unhardened
tRTS. On platforms vulnerable to LVI, Intel reports `SWHardeningNeeded`,
which the library's default policy **rejects** (as does `echo-client
--strict-tcb`). Users who accept that status, including `echo-client`'s
default policy, accept that a co-located attacker
may inject values into transient loads in our enclave.
*Fix:* build with `-C target-feature=+lvi-load-hardening,+lvi-cfi` (an
unstable target feature on the pinned toolchain) and link
`lib64/cve_2020_0551_load/` SDK libraries. Both change MRENCLAVE and need a
measured performance check.

### TM-2: Unchecked constructors in the public API

*Severity: low (API misuse).* `VerifiedClaims::new` is `pub` (the verifier
lives in another crate), so code can build "verified" claims from an
unauthenticated report, as the explicit simulation paths
(`--simulation-host`) do. `IdentityKey::secret_bytes` is `pub` for sealing
`lk_sk`. Neither is reachable from the network; both rely on reviewers.
*Fix:* rename to `VerifiedClaims::assume_verified` / gate behind a
`dangerous` module or a sealed constructor token owned by `sgx-ra-core`;
make `secret_bytes` `pub(crate)` plus a sealing-specific API.

### TM-3: p256 advisory RUSTSEC-2026-0387

*Severity: low.* The client-side verifier uses `p256 0.13` (via
`crypto-bigint`), affected by RUSTSEC-2026-0387. It only verifies public
signatures over public data, so the advisory's timing issue exposes no
secret. The advisory is ignored with that reasoning in `deny.toml` and
`.cargo/audit.toml`. *Fix:* upgrade to `p256 0.14` when `x509` tooling
allows.

### TM-4: Quotes carry no client freshness

*Severity: low (by design of the deployed executor).* The executor sends the
quote before reading any client input (PROTOCOL.md §2.1), so no client nonce
can enter report_data. A replayed quote is useless without the instance's
`ek_sk` (§4.3), and platform status is evaluated against current collateral.
What a fresh quote would add is proof that the instance is running
*now*, which matters only if the client wants to bound how long a session
may outlive the attestation evidence. Microcode or TCB recovery on the
platform requires a reboot, which ends the instance and its `ek_sk`.
*Fix (needs a protocol change):* a "re-attest" request inside the channel in
which the enclave produces a report over `H(th ‖ client nonce)` for the QE.
That requires the host's cooperation to obtain a quote.

### TM-5: Stack residues not scrubbed

*Severity: informational.* See §4.5. *Fix:* if the threat model ever
includes enclave memory-disclosure bugs, add a stack-scrubbing epilogue to
the ECALL glue (write zeros over the used stack depth) and wrap HMAC/HKDF
states in `Zeroizing` containers.

### TM-6: Attributes beyond DEBUG are not pinned

*Severity: informational.* The client does not compare
`attributes.flags`, `xfrm`, `misc_select`, `config_id`, `config_svn`,
`isv_ext_prod_id` and `isv_family_id` with the locally built SIGSTRUCT. A
re-signed copy launched with `KSS` or `PROVISION_KEY` behaves identically,
because our code uses neither. *Fix:* optionally derive an
`(attributes, mask)` expectation from the local `enclave.so.gendata`
(offsets 156/172) and add it to `EnclavePolicy`. Mask out `INIT`, which
EREPORT sets but SIGSTRUCT never does.

### TM-7: Collateral rollback within its validity window

*Severity: low, inherent to DCAP.* See §4.8. *Fix:* expose a
`min_tcb_evaluation_data_number` policy option and default the CLI to the
value current at release time.

### TM-8: Sealed state has no rollback protection

*Severity: low, documented in SEALING.md §2.1.* The host can roll back or
fork sealed blobs. Pinned clients detect a rollback of the long-term key to
a key other than the pinned one.

### TM-9: Sealing example is a bearer oracle

*Severity: informational.* The enclave does not authenticate clients
([TM-11](#tm-11-one-way-authentication)), so **anyone** who holds a
client-data blob, including the operator running their own attested
session, can have the same enclave on the same CPU unseal it. The blob
therefore must be treated like the secret itself: keep it on the client,
never hand it to the host. Applications needing per-client access control
must authenticate clients inside the channel and bind the client identity
into the sealed AAD.

### TM-10: No end-to-end run on SGX hardware

*Severity: process.* The remote executor's PCCS is down (PROTOCOL.md §5), so
the full path from real quote to real channel has only been exercised in
pieces: a recorded real quote with recorded collateral, SGX simulation,
synthetic PKI. Re-run `scripts/e2e.sh --skip-build` when the remote recovers;
its live checks report `BLOCKED` until then.

*Resolved 2026-11-24.* The executor runs the Rust host and enclave on real
SGX hardware; all `scripts/e2e.sh` stages pass against it, and
`scripts/verify-without-sgx.sh` attests it from a container without any
SGX device, service or library.

### TM-11: One-way authentication

*Severity: informational, by design.* Like server-only TLS, the client
authenticates the enclave, not vice versa. Any party, including the
operator, can open a session with a genuine enclave. Enclave applications
must not assume that the peer is "the" client; those that need client
identity must check a credential inside the record layer.

### TM-12: Build supply chain

*Severity: informational.* Reproducibility lets every client check that the
deployed MRENCLAVE corresponds to the source tree. It does not show that the
source tree and its pinned inputs are benign. The trust in Rust toolchain
1.100.0, `Cargo.lock` crates (exact pins for enclave crypto), the Intel SGX
SDK 2.26 tarball (sha256-pinned), nixpkgs (`flake.lock`) and the
`nixos/nix` builder image (digest-pinned) is transitive. `cargo deny` and
`cargo audit` run over the workspace. Clients should review changes to
these pins like code changes.

## 7. How to re-check

```sh
export PATH=$HOME/.cargo/bin:$PATH
cargo test --locked --workspace                # protocol, binding, MITM, bounds, verifier
cargo clippy --locked --workspace --all-targets
cargo deny check && cargo audit                # dependency advisories (TM-3)
scripts/nix-build-enclave.sh --verify          # bit-for-bit reproducibility, prints MRENCLAVE
scripts/e2e.sh                                 # offline/sim/MITM stages; live stages BLOCKED while the remote PCCS is down
```

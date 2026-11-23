# Sealing and the long-term enclave identity

This document covers the framework's sealing API, the host storage for
sealed blobs, the optional **long-term identity key** built on both, and the
security trade-offs of each choice. The example applications are
`examples/sealing-enclave` and `examples/sealing-client`.

| Piece | Where |
|-------|-------|
| Seal / unseal, MRENCLAVE or MRSIGNER key policy | `sgx_ra_enclave::sealing` |
| Storage trait, host-storage OCALLs, in-memory store | `sgx_ra_enclave::storage` (feature `sealed-storage` for the OCALLs) |
| OCALL contract (status codes, size limit, namespaces) | `sgx_ra_core::storage`, `enclave-sys/sealed-storage/Enclave.edl` |
| Long-term identity: load or create, migrate, prove | `sgx_ra_enclave::identity` |
| Identity proof format (shared by enclave and client) | `sgx_ra_core::identity` |
| Host side: directory store behind the OCALLs | `sgx_ra_host::sealed_store`, host CLI `--sealed-dir DIR` |
| Client side: verify the proof, pin the key | `sgx_ra_client::identity_pin` |

## 1. Sealing API

```rust
use sgx_ra_enclave::sealing::{self, KeyPolicy};

let blob = sealing::seal(b"secret", b"purpose label")?;          // MRENCLAVE
let back = sealing::unseal(&blob)?;                               // MRENCLAVE only
let blob = sealing::seal_with(KeyPolicy::MrSigner, data, aad)?;
let back = sealing::unseal_with(KeyPolicy::MrSigner, &blob)?;     // MRSIGNER only
assert_eq!(back.additional_data, aad);                            // check the purpose!
```

The wrappers call `sgx_seal_data_ex` and `sgx_unseal_data` with the SDK's
default attribute mask. The DEBUG bit is in that mask, so a debug launch of
the same image cannot unseal production blobs. The wrappers add these checks:

* **The policy is checked on unseal.** The key policy is written into the blob
  by whoever sealed it. `unseal_with(P, …)` refuses a blob sealed under any
  other policy (`SealError::WrongPolicy`). Without this check, an enclave that
  keeps a secret under MRENCLAVE could be handed a blob that *another* enclave
  of the same signer sealed under MRSIGNER. Our enclave would open that blob
  and treat attacker-chosen contents as its own secret.
* **The blob is length-checked before the SDK parses it.** The SDK trusts the
  length fields in the header. The wrapper checks that they describe exactly
  the bytes it holds.
* **The output is typed.** `Unsealed` carries the authenticated policy and the
  sealer's ISVSVN. Its plaintext is wiped on drop.
* **The purpose must be checked.** Additional data is authenticated but not
  encrypted. Put a purpose label into it and compare it after unsealing.
  Otherwise any blob of the same enclave is accepted wherever a blob is
  expected. The sealing example refuses to UNSEAL anything that is not a
  client-data blob, so it cannot be turned into an oracle that decrypts the
  sealed identity key.

### 1.1 Key policy trade-offs

| | `MrEnclave` (default) | `MrSigner` |
|---|---|---|
| Who can unseal | Exactly this enclave build (same MRENCLAVE) on this CPU | Any enclave signed with the same key and the same ISVPRODID, with ISVSVN ≥ the sealer's, on this CPU |
| Code update | **Data is lost**: any change to code, toolchain, `Enclave.config.xml` or EDL gives a new MRENCLAVE and a different key | **Data migrates**: the signer ships new code with the same ISVPRODID and an ISVSVN ≥ the old one |
| Trust needed | Only the measured code, which clients verify from a reproducible build | **The signing key holder**, who can sign an enclave that unseals and leaks everything. Reproducible builds do not help: the leaking enclave is a different build |
| Fits | Reproducible, client-verified enclaves (this framework's model) | Operator-signed products with planned upgrades and a well-protected signing key |
| Rollback of the code | Old code reads only its own old blobs | An old **vulnerable** version (lower ISVSVN) can read blobs sealed at its ISVSVN or lower. It cannot read blobs sealed by a newer ISVSVN |

Both policies are bound to the **CPU**: a blob never opens on another
machine, and it stops opening if the CPU's TCB (CPUSVN) drops below the
sealer's. Sealing is therefore not a backup or migration mechanism between
machines. Moving a secret to another machine requires the application to
attest the target enclave and transfer the secret over an attested channel.

**MRSIGNER with a published signing key protects nothing.**
`enclave-sys/reproducible-signing-key.pem` is in the repository so that
`enclave.signed.so` is reproducible. Its private key is public, so anyone can
sign an enclave that unseals MRSIGNER blobs. `LongTermIdentity` refuses the
MRSIGNER policy when the enclave's MRSIGNER is that key
(`identity::PUBLISHED_SIGNERS`, error `PublishedSigner`). Deployments that
want MRSIGNER sealing must re-sign `enclave.so` with a private key, using
`sgx_sign` with gendata and catsig. MRENCLAVE does not change, so clients'
pins on the measurement stay valid.

**Migrating to a new ISVSVN.** When `LongTermIdentity` opens a blob sealed at
a lower ISVSVN, it re-seals the key at its own ISVSVN and replaces the stored
copy (origin `Migrated`). From then on the stored copy is out of reach of the
old version. Any copy the host kept is still readable by the old version,
because sealing cannot revoke a key that an old version already derived. If
the old version was vulnerable, assume that key is compromised and rotate it:
delete the blob and let the enclave create a new one.

## 2. Storage OCALLs

The enclave cannot persist anything by itself. The host keeps the blobs:

```c
// enclave-sys/sealed-storage/Enclave.edl  (imports ../Enclave.edl unchanged)
uint32_t sgx_ra_ocall_load_sealed (const uint8_t ns[32], uint32_t slot,
                                   uint8_t* blob /*[out, capacity]*/, size_t capacity,
                                   size_t* blob_len /*[out]*/);
uint32_t sgx_ra_ocall_store_sealed(const uint8_t ns[32], uint32_t slot,
                                   const uint8_t* blob /*[in, blob_len]*/, size_t blob_len,
                                   uint32_t replace);
```

* **The ABI is compatible.** The file imports the blueprint `Enclave.edl`, so
  the ECALLs and their numbers do not change. The echo enclave keeps the plain
  EDL, and its MRENCLAVE is not affected by any of this (see §6). Enclaves
  using `OcallStorage` must be linked with the sealed-storage EDL. Linking
  them with the plain one fails with an undefined reference to
  `sgx_ra_ocall_load_sealed`, which is the intended result.
* **The host serves both kinds of enclave.** `sgx-ra-host` builds its bridge
  from the sealed-storage EDL by default. One host binary therefore loads
  enclaves of either kind. `--sealed-dir DIR` (env `SGX_RA_SEALED_DIR`)
  enables storage. Without it, the OCALLs answer `Unavailable`. A host built
  for the plain EDL, such as the blueprint C++ `app` on the remote executor,
  has no such OCALLs, and the transition fails with
  `SGX_ERROR_INVALID_FUNCTION`. The enclave maps both cases to
  `StorageError::Unavailable`.
* **The layout makes names safe.** Blobs live at
  `DIR/<namespace hex>/slot-<n>.sealed`. Names are derived from a fixed-size
  namespace and an integer only, so the enclave cannot steer the host into
  path traversal. Directories are created with mode `0700` and files with
  `0600`.
* **Writes are atomic.** The host writes a synced temporary file, then calls
  `link()` for create-new (which fails if the slot exists) or `rename()` for
  replace. Readers see the whole old blob or the whole new one. Blob sizes
  are capped at 16 KiB.
* **Namespaces follow the key derivation.** The enclave computes
  `SHA-256("SGXRA-v1/sealed-storage" ‖ 00 ‖ policy ‖ MRENCLAVE)` for the
  MRENCLAVE policy, or `… ‖ MRSIGNER ‖ ISVPRODID` for MRSIGNER, from its own
  report (`sgx_self_report`). After a code change under MRENCLAVE, the new
  enclave therefore finds an empty namespace and does not trip over blobs it
  cannot open. The old blob stays available for the old code. Under
  MRSIGNER, every version looks in the same place, which is what makes
  migration work. The namespace is only a hint to the host. Lying about it
  gains the host nothing, because the enclave authenticates every blob.
* **Host answers are untrusted.** The bridge copies the load buffer into
  enclave memory after the host returns, so the host cannot race the parsing.
  `OcallStorage` rejects a reported length beyond the buffer
  (`StorageError::Malformed`). Unknown status codes count as I/O errors.

### 2.1 What the untrusted host can still do

Sealing provides confidentiality and integrity. It provides **no freshness
and no availability**.

| Host action | Effect | Mitigation |
|---|---|---|
| Read, modify, forge a blob | Nothing: the data is AES-GCM under a CPU-derived key, and modification fails authentication | Built in |
| Swap in a genuine blob of another slot or purpose | Refused: the additional data names purpose, policy, slot and the key's own public half | `IdentityConfig`, purpose labels |
| Delete or withhold a blob | The enclave creates a **new** identity, and pinned clients see a mismatch | Client pinning (§4); availability is out of scope |
| **Roll back** to an older blob (for example a key that was later rotated away) | The enclave accepts it. The blob is genuine; sealing cannot tell old from new | Not solvable with sealing alone. It needs a monotonic counter or an external freshness service (SGX monotonic counters are deprecated). Clients' pins detect a rollback to a key other than the pinned one |
| Fork the state: run two instances, or keep two storage directories | Both can hold the same identity key | Inherent: an identity key proves "code X on CPU Y", not "one instance" |
| Refuse service | Always possible | Out of scope |

## 3. The long-term identity key

### 3.1 Design: a separate key `LK`, attested per session

The channel identity key `EK` (PROTOCOL.md §6.2) stays **per instance**. It
is generated by `sgx_read_rand` on the first `enclave_create_report`,
committed to in report_data, and never sealed. The long-term identity is a
separate X25519 key `LK`. `LK` is sealed, persisted, and asserted **inside**
an attested session:

```
client → enclave   IDENTITY ‖ chal_pub                      (fresh X25519 key per request)
enclave → client   ver ‖ origin ‖ policy ‖ lk_pub ‖ proof

k     = HMAC-SHA256("SGXRA-v1/long-term-identity", X25519(lk_sk, chal_pub))   // HKDF-Extract
proof = HMAC-SHA256(k, "SGXRA-v1/long-term-identity/key" ‖ "SGXRA-v1/long-term-identity"
                       ‖ ver ‖ origin ‖ policy ‖ ek_pub ‖ lk_pub ‖ chal_pub)
```

The client checks the proof with `X25519(chal_sk, lk_pub)`, the session's
attested `ek_pub` (`EnclaveChannel::enclave_public_key`) and its own
`chal_pub`. A valid proof shows three things:

1. The peer is the attested enclave instance. The answer arrives over the
   channel whose key is in this session's quote, and the proof covers `ek_pub`.
2. That instance holds `lk_sk` **now**. The challenge is fresh, so an old
   answer cannot be replayed into a new session or a new challenge.
3. The origin and policy it reports are the ones it committed to.

**Why not seal `EK` itself?** We rejected that option. With a stable `EK`,
report_data is the same in every instance, so every quote the genuine
enclave ever produced vouches for that key forever. Anyone who once extracts
`ek_sk` could impersonate the enclave indefinitely by replaying an old quote
and completing the handshake, which needs only `ek_sk` and a fresh ephemeral.
`ek_sk` could leak through a side channel, a bug, or a malicious enclave of
the same signer under MRSIGNER. Clients cannot detect this, because the quote
is genuine and the MRENCLAVE is right. With a per-instance `EK`, every
session needs a quote over a key that exists only in a live instance. A
leaked `LK` lets an attacker decrypt data that was encrypted *to* `lk_pub`
and pass an identity check, but only inside a channel that a genuine enclave
instance with the expected MRENCLAVE terminates. A leaked `LK` alone never
gets a client to accept a channel.

### 3.2 What a pin means

A client that pins `lk_pub` (trust on first use) and sees the same key again
learns that it is talking to an instance of the attested code that could
open the sealed key. That means the same storage lineage, with the same code
(MRENCLAVE policy) or the same signer and product (MRSIGNER policy), on the
same CPU. Data the enclave sealed earlier is therefore still reachable, and
an application can encrypt to `lk_pub` offline.

The pin is checked **in addition to** attestation and never replaces it.
`sealing-client` verifies the quote, the MRENCLAVE and the handshake on every
connection before it asks for the identity.

A changed key has one of these causes:

* new code under MRENCLAVE;
* another CPU;
* the CPU TCB went below the sealer's;
* the blob was deleted;
* the host rolled back to an older key.

The client cannot tell these apart, so `IdentityPin::check` reports
`PinError::Mismatch`, and `sealing-client` exits with code 4. The client
never re-pins silently.

### 3.3 Lifecycle and failure handling (`LongTermIdentity::load_or_create`)

| Situation | Result | Origin |
|---|---|---|
| No blob | Generate `LK`, seal, store with create-new | `Created` |
| Another instance created it at the same moment (create-new fails) | Load and use the winner's key, so all instances agree | `Restored` |
| Blob sealed at this ISVSVN opens | Use it | `Restored` |
| Blob from a lower ISVSVN opens | Re-seal at this ISVSVN and replace the stored copy | `Migrated` |
| Host has no storage | Fresh key, not persisted | `Ephemeral` (clients must not pin it; `IdentityPin` will not) |
| Blob exists but does not open (tampered, other CPU, lower CPUSVN, other policy, foreign content) | **Fail closed** (`IdentityError::Unreadable` / `Mismatch`). The blob is not overwritten | — |
| MRSIGNER requested while signed with the published key | Refused (`PublishedSigner`) | — |

Failing closed is deliberate. Silently rotating the key on an unreadable blob
would let a host force a fresh key just by corrupting the file. It would also
destroy a key that becomes readable again, for example after a temporary TCB
downgrade. Rotation is the operator's decision: delete the slot file under
`--sealed-dir`. Clients then see a pin mismatch and must re-establish trust.

The sealed blob's additional data is
`"SGXRA-v1/sealed-long-term-identity" ‖ 00 ‖ policy ‖ slot (BE u32) ‖ lk_pub`.
After unsealing, the enclave recomputes `lk_pub` from the secret and requires
the additional data to match exactly.

## 4. Using it

### 4.1 In an enclave

```rust
use sgx_ra_enclave::identity::{IdentityConfig, LongTermIdentity};
use sgx_ra_enclave::sealing::KeyPolicy;
use sgx_ra_enclave::storage::OcallStorage;
use sgx_ra_enclave::{SessionContext, SgxRng};

let lk = LongTermIdentity::load_or_create(
    IdentityConfig::new(KeyPolicy::MrEnclave), &mut OcallStorage, &mut SgxRng)?;
// in EnclaveApp::handle_with_context(context, request, response):
let assertion = lk.prove(context.identity_public_key(), &challenge)?;
```

`EnclaveApp::handle_with_context` is the hook that gives an application the
session's attested `ek_pub`. Its default calls `handle`, so existing apps
such as echo are unchanged. Enable the `sealed-storage` feature of
`sgx-ra-enclave` and link with `--edl enclave-sys/sealed-storage/Enclave.edl`
(`enclave-sys/build.sh`), or with `mkEnclave { edl = …; }` (flake).

### 4.2 In a client

```rust
let challenge = IdentityChallenge::new(&mut OsRng)?;
// send challenge.public_key() over the EnclaveChannel, receive an IdentityAssertion
sgx_ra_client::verify_assertion(challenge, channel.enclave_public_key(), &assertion)?;
match IdentityPin::new("enclave.pin").check(&assertion)? { /* Pinned | Matches | NotPersistent */ }
```

### 4.3 The example

```sh
# Reproducible build (Nix container): flake attribute `sealing-enclave`
docker build -f containers/Dockerfile.nix-build --build-arg ENCLAVE=sealing-enclave -t sealing .
# Host on an SGX machine, with storage
echo-host-app --enclave enclave.signed.so --listen 127.0.0.1:7000 --sealed-dir /var/lib/sgx-ra/sealed
# Client: rebuilds the enclave (or --gendata-path / --expected-mrenclave), attests, then
sealing-client --plaintext identity --pin sealing-enclave.pin     # prints and pins lk_pub
sealing-client --plaintext seal   --input secret.txt --output secret.blob
sealing-client --plaintext unseal --input secret.blob
```

`nix build .#sealing-enclave` at this commit gives **MRENCLAVE
`76ae010076babacb00e7fdae2fcc2f5f98d2f135e3609eabb754ca84d5057327`**
(ProdID 1, ISVSVN 1, debug disabled, signed with the published key). Two
`docker build --no-cache` runs (`scripts/nix-build-enclave.sh --enclave
sealing-enclave --verify`) produced bit-for-bit identical `enclave.signed.so`,
`enclave.so` and `enclave.so.gendata`. As with echo, any change to the
inputs gives a new value.

Exit codes: 0 means success, 1 a failure (including attestation), 3 an
application error reported by the enclave, and 4 a pin mismatch.

The remote executor (`sgx-playground.blechschmidt.io`) runs the blueprint C++
host, which has no storage OCALLs. The sealing enclave works there, but its
identity is always `Ephemeral`. Persistence needs the Rust host with
`--sealed-dir`.

## 5. Tests

* `sgx-ra-enclave` unit tests (`cargo test -p sgx-ra-enclave --features
  sealed-storage`) run against a software stand-in of the SDK. The stand-in
  models key derivation from policy, MRENCLAVE, MRSIGNER, ISVPRODID, ISVSVN
  and CPU. The tests cover both policies, the policy check, tamper detection,
  a code change losing an MRENCLAVE identity, MRSIGNER migration and
  re-sealing, a refused published signer, failing closed, ephemeral fallback,
  the create race, and the OCALL glue, including a host lying about lengths.
* `sgx-ra-core` covers the proof format and its bindings: session, challenge,
  every field, low-order points, and strict decoding. `sgx-ra-host` covers
  the directory store: atomic create-new under 8 threads, permissions and
  size caps. `sgx-ra-client` covers pin semantics.
* `examples/sealing-client/tests/sealing.rs` runs end to end against a real
  enclave image:
  * `sim_*` tests use the SGX simulation runtime. They are always
    `#[ignore]`d; the module docs show how to run them.
  * `hw_*` tests need SGX hardware and DCAP. They are `#[ignore]`d when the
    build machine has no `/dev/sgx_enclave` (the `cfg(sgx_hw)` set by
    `build.rs`).

## 6. Effect on existing enclaves

None of this changes the echo enclave's EDL. The new runtime code (sealing,
storage, identity, `handle_with_context`) is either unused by echo or
inlines away, so echo's MRENCLAVE is unchanged (checked by rebuilding it
before and after these changes: the Ubuntu-toolchain build stays
`c4984b76…`, and the Nix build stays `b27bca50…`, the value in the README).

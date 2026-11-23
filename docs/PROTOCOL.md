# Remote executor protocol

This document pins down the wire protocol of the SGX remote executor at
`sgx-playground.blechschmidt.io:443`. It also specifies the attested-channel
protocol (v1) that this framework layers on top of it.

Sources: the blueprint repository
[`blechschmidt/sgx-playground`](https://github.com/blechschmidt/sgx-playground)
at commit `0532c29` (`server/App/App.cpp`, `server/Enclave/*`,
`config/server/stunnel.conf`, `sgx-client/main.py`), the verifier library
[`blechschmidt/intel-sgx-ra`](https://github.com/blechschmidt/intel-sgx-ra) at
commit `c253216`, and live probes of the remote executor on 2026-11-22 and
2026-11-23 (see [§5](#5-live-observations-2026-11-222026-11-23)).

All multi-byte integers on the wire are **big-endian** unless stated
otherwise. All integers inside SGX structures (quote, report, CSS) are
**little-endian**.

---

## 1. Deployment topology (layer 0)

```
client ──TLS 1.3──▶ stunnel :443 ──exec (one process per connection)──▶ wrapper.sh ──▶ app
                                     stdin/stdout = decrypted TLS stream               │ sgx_create_enclave("enclave.signed.so")
                                                                                       ▼
                                                                         enclave (ECALLs) + QE3/PCE via DCAP QL
```

* `config/server/stunnel.conf` accepts on `0.0.0.0:443` using a Let's Encrypt
  certificate for `sgx-playground.blechschmidt.io`. For **every TCP
  connection** it runs `exec = /path/to/wrapper.sh`, with the decrypted TLS
  stream wired to the child's stdin/stdout. The real wrapper script is not
  published.
* The host binary (`app`, built from `server/App/App.cpp`) opens
  `ENCLAVE_PATH = "enclave.signed.so"`, a path **relative to its working
  directory**. It passes `SGX_DEBUG_FLAG`, which is `0` in the release build
  (`SGX_DEBUG=0` → `-DNDEBUG -UEDEBUG`).
* Each connection therefore gets a new process, a new enclave instance, a new
  quote, and a new in-enclave key pair. There is no state between connections.
* TLS gives transport confidentiality only. It ends at stunnel, **outside** the
  enclave, so the remote operator can see and modify everything inside it. In
  the security model the TLS layer is an untrusted pipe.

### 1.1 Which enclave does the executor load?

**The enclave is fixed by the operator. Clients cannot choose or upload it.**

* The protocol has no client-to-server message before the quote. `App.cpp`
  sends the quote before it reads anything from stdin. A live probe with **zero
  bytes sent** reached quote generation, so `wrapper.sh` also waits for nothing
  from the client (see §5).
* The enclave image is whatever `enclave.signed.so` sits in the wrapper's
  working directory. According to the README it is built from `server/` of the
  blueprint, i.e. today it is the C++ echo enclave.
* Consequence for this project: to run our Rust enclave remotely, the
  operator must deploy our `enclave.signed.so` (and optionally our Rust host,
  which keeps the same wire protocol) behind the wrapper. Our enclave therefore
  **keeps the ABI of `Enclave.edl`**, so it works unchanged with the existing
  C++ `app`. The client never trusts this deployment step. It only trusts the
  MRENCLAVE it rebuilds locally.

---

## 2. Executor wire protocol (layer 1, "compat v0")

Everything below runs inside the TLS stream. Names follow `App.cpp`.

### 2.1 Quote announcement (server → client, unsolicited, exactly once)

```
+-------------------+-------------------------------+
| quote_len: u32 BE | quote: quote_len bytes        |
+-------------------+-------------------------------+
```

`quote` is a DCAP **v3** ECDSA quote (`sgx_quote3_t`, see §3) for the
application enclave's report. Before sending it, the host runs:

1. `sgx_qe_set_enclave_load_policy(SGX_QL_PERSISTENT)`, `sgx_ql_set_path` for
   PCE/QE3/IDE/QPL (in-proc mode, unless `SGX_AESM_ADDR` is set)
2. `sgx_qe_get_target_info(&qe_target_info)` (needs the server-side PCCS)
3. `sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, …)`
4. ECALL `enclave_create_report(&qe_target_info, &app_report)`
5. `sgx_qe_get_quote_size` → `sgx_qe_get_quote(&app_report, …)`
6. It also writes `report.dat` and `quote.dat` to its working directory. This is
   a side effect only, not part of the protocol.

If any step fails, the process prints a diagnostic and exits. The client then
sees EOF, often after a few bytes of text (see §2.4).

### 2.2 Requests (client → server, repeated)

```
+---------------------+-------------------------------+
| msg_len: u32 BE     | payload: msg_len bytes        |
+---------------------+-------------------------------+
```

The payload is copied into a 4096-byte host buffer and passed to ECALL
`enclave_message(eid, &op_status, input, msg_len, output, &response_size)`.

### 2.3 Responses (server → client, one per request)

Success:

```
+-----------+---------------------+-------------------------------+
| 0x00      | resp_len: u32 BE    | payload: resp_len bytes       |
+-----------+---------------------+-------------------------------+
```

Failure is a **single status byte with no length or payload**:

| status | `App.cpp` name                  | when                                                            |
|--------|---------------------------------|-----------------------------------------------------------------|
| `0x00` | `STATUS_OK`                     | ECALL returned `SGX_SUCCESS` and `op_status == SGX_SUCCESS`     |
| `0x01` | `MESSAGE_TOO_SHORT`             | short read of the payload (unreachable in practice, see below)  |
| `0x02` | `ENCLAVE_COMMUNICATION_FAILURE` | ECALL transport error or the enclave returned non-success       |

After a non-zero status the session stays open and the host waits for the next
request.

### 2.4 Constraints and quirks the framework must respect

These come from reading `App.cpp`, `Enclave.edl`, and `Enclave.cpp`. They are
binding for any client that talks to the **existing** C++ host.

| # | Behaviour | Consequence for our implementation |
|---|-----------|------------------------------------|
| Q1 | The EDL declares `[in,count=4096] p_data` and `[in,out,count=4096] p_response`. The bridge always copies exactly 4096 bytes in both directions. The enclave rejects `data_size > 4096`. | Request payload ≤ **4096** bytes. Response payload ≤ **4096** bytes, and the enclave must never write more. |
| Q2 | The host reads `msg_len` bytes into `uint8_t input[4096]` **without bounds checking**. A request over 4096 bytes overflows the host's stack. | The client **must** reject payloads over 4096 bytes locally. Our Rust host bounds-checks and closes the session. |
| Q3 | `read_all()` misuses `fread` (it treats the item count as a byte count). It "works" only because its `-1` return becomes `SIZE_MAX` in a `size_t`. With `msg_len == 0` it returns 0, which **ends the session** (the process exits and the client sees EOF). | Never send an empty payload. Every v1 message has at least a 1-byte type. |
| Q4 | On EOF mid-payload `read_all` returns 0 and the loop breaks, so `MESSAGE_TOO_SHORT` (0x01) is never actually sent. | Treat EOF at any point as session termination. |
| Q5 | The QPL logger (`qpl_logger`) prints to **stdout**, which is the wire. Error-level DCAP messages (`[QCNL] Error: …`) and `printf("Error in sgx_qe_get_target_info…")` are written into the stream before or instead of the quote. | The client must sanity-check `quote_len` (reject values over 64 KiB) and report the received bytes as a remote diagnostic if they look like ASCII text. Example: `"[QCN"` decodes to `quote_len = 0x5b51434e` ≈ 1.5 GB. |
| Q6 | stdout uses stdio buffering (`printf`) **and** raw `write(1, …)`. Interleaving can be out of order. | Same as Q5. Our Rust host logs to stderr only. |
| Q7 | Return values of `write_all` are ignored. | Client-side timeouts are required. The **quote-read** timeout must be well above the ~60 s the server-side QCNL spends before it gives up (§5). Use ≥ 120 s for the quote and a shorter per-request timeout afterwards. |
| Q8 | `TCSNum = 1`. One enclave thread and one session per process. | Strict request/response lockstep, no pipelining. |
| Q9 | Blueprint `Enclave.config.xml`: `HeapMaxSize = 0x100000` (1 MiB), `StackMaxSize = 0x40000`, `DisableDebug = 0`. | The Rust enclave's allocator must fit in the configured heap. Our config is part of the measured build (layout feeds MRENCLAVE), so it is fixed in the repo and not taken from the blueprint at runtime. `DisableDebug = 0` lets the same signed image be launched in debug mode, so the verifier's DEBUG-bit check is mandatory (§4.2). |

### 2.5 Request sequence (blueprint echo enclave)

```
C → S   TLS handshake (stunnel)
S → C   u32 len || quote
C → S   u32 18 || "Hello, SGX server!"
S → C   00 || u32 18 || "Hello, SGX server!"
…
C       close → app reads EOF → sgx_destroy_enclave → exit
```

---

## 3. Data structures

### 3.1 DCAP v3 quote (`sgx_quote3_t`)

| offset | size | field | expected / note |
|--------|------|-------|-----------------|
| 0   | 2   | `version` | `3` |
| 2   | 2   | `att_key_type` | `2` = ECDSA-256-with-P-256 |
| 4   | 4   | `att_key_data_0` / tee type | `0` (SGX) |
| 8   | 2   | `qe_svn` | |
| 10  | 2   | `pce_svn` | |
| 12  | 16  | `qe_vendor_id` | Intel: `939a7233f79c4ca9940a0db3957f0607` |
| 28  | 20  | `user_data` | first 16 bytes: QE platform id |
| 48  | 384 | `report_body` (`sgx_report_body_t`, §3.2) | application enclave report |
| 432 | 4   | `signature_data_len` (LE) | must equal `len(quote) - 436` |
| 436 | var | `sgx_ql_ecdsa_sig_data_t` | §3.3 |

The README reports a typical quote size of **4734 bytes**.

### 3.2 Report body (`sgx_report_body_t`, 384 bytes; offsets relative to body)

| offset | size | field |
|--------|------|-------|
| 0   | 16 | `cpu_svn` |
| 16  | 4  | `misc_select` |
| 20  | 12 | reserved |
| 32  | 16 | `isv_ext_prod_id` |
| 48  | 8  | `attributes.flags` (bit 1 = DEBUG, bit 2 = MODE64BIT, bit 4 = PROVISION_KEY, bit 7 = KSS) |
| 56  | 8  | `attributes.xfrm` |
| 64  | 32 | **`mr_enclave`** |
| 96  | 32 | reserved |
| 128 | 32 | **`mr_signer`** (SHA-256 of the signer's RSA-3072 modulus) |
| 160 | 32 | reserved |
| 192 | 64 | `config_id` |
| 256 | 2  | `isv_prod_id` |
| 258 | 2  | `isv_svn` |
| 260 | 2  | `config_svn` |
| 262 | 42 | reserved |
| 304 | 16 | `isv_family_id` |
| 320 | 64 | **`report_data`** |

So within the full quote, MRENCLAVE is at `[112, 144)`, MRSIGNER at
`[176, 208)` and report_data at `[368, 432)`.

### 3.3 ECDSA signature data (`sgx_ql_ecdsa_sig_data_t`)

| size | field |
|------|-------|
| 64  | ECDSA P-256 signature (r‖s, big-endian) over `quote[0..432]` by the attestation key |
| 64  | attestation public key (x‖y, big-endian) |
| 384 | QE report body |
| 64  | QE report signature (by the PCK key) |
| 2   | `qe_auth_data_len` (LE) |
| var | QE auth data |
| 2   | `cert_data_type` (LE). Expected `5` = PCK cert chain (PEM: PCK leaf, Platform/Processor CA, Root CA) |
| 4   | `cert_data_len` (LE) |
| var | cert data |

The QE report binds the attestation key with
`qe_report.report_data[0..32] == SHA-256(att_pub_key || qe_auth_data)`.

### 3.4 Enclave signing gendata (`enclave.so.gendata`, 256 bytes)

`sgx_sign gendata -enclave enclave.so -config Enclave.config.xml -out enclave.so.gendata`
writes the to-be-signed part of SIGSTRUCT:

| offset | size | field |
|--------|------|-------|
| 0   | 12 | header, must be `06000000E100000000000100` |
| 12  | 4  | type (bit 31: debug) |
| 16  | 4  | module vendor (`0` = ISV) |
| 20  | 4  | **date** (yyyymmdd, BCD). `sgx_sign` takes it from the clock, so it changes per build day. The Nix build fixes it to `SOURCE_DATE_EPOCH` (19800101) with libfaketime; compare gendata from other builds only from offset 24 on |
| 24  | 16 | header2 `01010000600000006000000001000000` |
| 40  | 4  | hw_version |
| 44  | 84 | reserved |
| 128 | 4  | misc_select |
| 132 | 4  | misc_mask |
| 136 | 4  | reserved |
| 140 | 16 | isv_family_id |
| 156 | 16 | attributes |
| 172 | 16 | attribute_mask |
| 188 | 32 | **enclave_hash (= MRENCLAVE)** |
| 220 | 16 | reserved |
| 236 | 16 | isvext_prod_id |
| 252 | 2  | isv_prod_id |
| 254 | 2  | isv_svn |

MRENCLAVE depends only on the enclave ELF and on `Enclave.config.xml`
(heap/stack/TCS layout). It does **not** depend on the signing key, so an
operator re-signing with their own key keeps MRENCLAVE but changes MRSIGNER.

---

## 4. What the blueprint client verifies, and what it skips

`sgx-client/main.py` uses `intel_sgx_ra.attest.verify_quote(quote, pccs_url)`
and then compares MRENCLAVE.

### 4.1 Verified

| Check | Where |
|-------|-------|
| Local rebuild of the enclave (`make -C ../server` inside `Dockerfile.build`) produces `enclave.so.gendata` | `CompilationStep` |
| `DEBUG` attribute bit is clear | `verify_quote` |
| PCK chain from the quote's cert data: issuer names, validity periods, ECDSA signatures (Root self-signed → Platform/Processor CA → PCK) | `verify_pck_chain` |
| PCCS-served Root CA and PCK CA are bytewise equal to those in the quote | `retrieve_collaterals` |
| TCB signing certificate chains to the Root CA and is time-valid | `verify_tcb` |
| Quote signature (header ‖ report body) under the attestation key | `verify_quote` |
| QE report signature under the PCK key, and `qe_report.report_data[0..32] == SHA-256(att_key ‖ qe_auth_data)` | `verify_quote` |
| `quote.report_body.mr_enclave == gendata.body.enclave_hash` | `main.py` |
| gendata header magic (via `assert`, which `python -O` strips) | `main.py` |

### 4.2 Not verified (gaps the Rust verifier must close)

| Gap | Risk |
|-----|------|
| **MRSIGNER** is never checked. The Makefile also signs with a key that it generates freshly with `openssl genrsa` when `Enclave_private_sample.pem` is missing, so MRSIGNER is random per build. | Expected for a reproducible-build trust model. MRSIGNER is optional policy only. |
| **report_data** is never checked. The blueprint enclave hashes the public key **before** generating it, so report_data is the constant `SHA-256(64 zero bytes) = f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b` followed by 32 zero bytes. The key is never used. | Nothing binds the session to the enclave, so the operator can read and forge every "enclave" message. This is the main gap our framework fixes. |
| **Intel SGX Root CA is not pinned.** The root comes from the quote and is only compared with the PCCS copy. The PCCS sits behind a local nginx with `proxy_ssl_verify off`, reached over plain HTTP. | Whoever controls the PCCS path can forge the entire chain. Pin the Intel SGX Root CA public key. |
| PCK **leaf** certificate is never checked for revocation (the code checks the Root CRL against the root cert and the PCK CRL against the CA cert). | A revoked platform would still be accepted. |
| TCB Info JSON **signature** is not verified (only the signing cert). The platform's TCB level/status (`UpToDate`, `OutOfDate`, `Revoked`, `SWHardeningNeeded`…) is never evaluated. `nextUpdate` expiry is only logged. | Compromised or out-of-date platforms would be accepted. |
| QE Identity is fetched but **ignored** (QE MRSIGNER, ISVPRODID, ISVSVN, attributes, misc select). | |
| Quote header fields (`version`, `att_key_type`, `qe_vendor_id`) and `cert_data_type` are not checked. | |
| Other report attributes (MODE64BIT, PROVISION_KEY, KSS), `misc_select`, `isv_prod_id`, `isv_svn` are not checked. | |
| `Enclave.config.xml` sets `DisableDebug = 0`, so the signed enclave may also be launched with the DEBUG attribute. The host picks the mode through `SGX_DEBUG_FLAG` (`sgx_urts.h`: `1` unless `NDEBUG` is defined without `EDEBUG`). | Only the verifier's DEBUG-bit check stops a debug launch (operator could then read enclave memory). That check exists in `verify_quote`, but it is the sole safeguard. Our enclave sets `DisableDebug = 1` as defense in depth. This only changes SIGSTRUCT attributes/mask, not MRENCLAVE. |
| No freshness. The quote is generated before any client input, so a client nonce cannot enter report_data. | Mitigated in v1 by the in-enclave key (§6) plus TCB-status evaluation at verification time. |
| `main.py` bugs: its mismatch message prints `mr_signer` instead of the remote `mr_enclave`; `"…" + int(status[0])` raises `TypeError` on non-zero status. The `intel-sgx-ra` dependency is pinned to a branch (`#egg=merge`), not to a commit. | Cosmetic, plus a supply-chain concern. |

---

## 5. Live observations (2026-11-22/2026-11-23)

Probes ran from this build host with Python `ssl` and raw sockets.

1. **TLS certificate expired.** The leaf is `CN=sgx-playground.blechschmidt.io`,
   issuer Let's Encrypt `E7`, valid from 2025-11-15 to **2026-02-13**. Default
   verification fails with `certificate has expired`. The blueprint client would
   abort here. Our client treats TLS as untrusted transport and offers an
   explicit `--insecure-tls` (or a pinned-certificate) option. Attestation still
   provides the security.
2. With verification disabled: TLS 1.3, `TLS_AES_256_GCM_SHA384`.
3. **No quote is delivered.** With **no client bytes sent**, after ~60.3 s the
   server writes this text to the stream and closes it:

   ```
   [QCNL] Error:  Encountered CURL error: (7) Couldn't connect to server
   [QPL] Error: Failed to get quote config. Error code is 0xb006
   Error: [get_platform_quote_cert_data ../qe_logic.cpp:388] Error returned from the p_sgx_get_quote_config API. 0xe019
   Error: [sgx_qe_get_target_info ../sgx_dcap_ql_wrapper.cpp:374] Error in sgx_ql_init_quote. 0xe019
   Error in sgx_qe_get_target_info. 0xe019
   ```

   (388 bytes, then EOF.) The server-side QPL cannot reach its PCCS, so
   `sgx_qe_get_target_info` fails with `0xe019` (`SGX_QL_NETWORK_ERROR`;
   QCNL error `0xb006`) **before the enclave is even created**. This confirms quirk Q5 (diagnostics go to the wire). It also
   confirms that the wrapper starts `app` without waiting for client input.
4. Sending bytes up front (`u32 0`, `"hello\n"`, `u32 18 || "Hello, SGX server!"`)
   changed nothing in the first 20 s. Input is not read before the quote.

A re-probe during the review on the same day gave the identical result: the same
388-byte diagnostic after 60.4 s, and the certificate still expired.

A re-probe on **2026-11-23** gave the same failure after 60.3 s (certificate
still expired, TLS 1.3 / `TLS_AES_256_GCM_SHA384`). The text was now
**385 bytes** and cited different DCAP source locations
(`qe_logic.cpp:357`, `sgx_dcap_ql_wrapper.cpp:378`), so the operator's DCAP
packages changed between the probes. Clients must therefore detect the
diagnostic generically (ASCII text in place of `quote_len`, quirk Q5) and must
not match the exact wording. `fixtures/remote_pccs_error_session.bin` keeps
the 2026-11-22 capture.

**Status:** the remote executor currently cannot produce quotes. End-to-end
tests against it (task 10) must detect this case and report it as
"remote attestation infrastructure unavailable", not as a verification failure.
Verifier development (task 7) must use recorded or test quotes until the
operator fixes the PCCS connection.

---

## 6. Attested channel protocol (layer 2, framework "SGXRA v1")

This protocol runs **inside** `enclave_message` payloads (layer 1). It
therefore works through the unmodified C++ host and through our Rust host. Its
goal is an end-to-end confidential, integrity-protected channel whose server
key provably lives only inside an enclave with the expected MRENCLAVE.

### 6.1 Primitives

| Purpose | Primitive |
|---------|-----------|
| Key agreement | X25519 (RFC 7748). All-zero shared secrets are rejected. |
| Hash | SHA-256 |
| KDF | HKDF-SHA256 (RFC 5869) |
| Key confirmation | HMAC-SHA256 |
| AEAD | ChaCha20-Poly1305 (RFC 8439) |
| Randomness (enclave) | `sgx_read_rand` (RDRAND inside the enclave) |

All of these exist as `no_std` RustCrypto / dalek crates, so the same code runs
in the enclave and in the client.

### 6.2 Enclave identity key and report_data binding

On the first `enclave_create_report` call, the enclave generates the **enclave
identity key** `EK = (ek_sk, ek_pub)`, an X25519 key, from `sgx_read_rand`. It
keeps `ek_sk` in enclave memory only: it is never exported, logged, or sealed
(the sealing PoC uses separate keys). Later calls reuse the same `EK`, so a
host cannot create two reports with different keys for one session.

```
report_data[ 0..32] = SHA-256( "SGXRA-v1/report-data" || 0x00 || version=0x01 || ek_pub )
report_data[32..64] = 0x00 * 32          (reserved, verifier requires zeros)
```

The client compares all 64 bytes in constant time and requires an exact match
(`sgx_ra_core::binding`). Known answer: for `ek_pub = 00×32` the first half is
`ed14eda44c14207ae3d3e792d059607861f877d2ea2d6a34eef4826ab44b7861`.

**Design decision: SHA-256, zero-padded, rather than SHA-512.** Both give a
collision-resistant commitment to `ek_pub`. SHA-256 was chosen because:

* its 128-bit collision resistance matches the security level of X25519 and
  ChaCha20-Poly1305, so SHA-512 would not strengthen the channel;
* it is the only hash the protocol uses (transcript, HKDF, HMAC), so the
  enclave links one hash implementation;
* the upper 32 bytes stay free. They must be zero in v1, so a later version
  can define them (e.g. a configuration hash) without the two versions being
  confusable.

The label, its `0x00` terminator and the version byte separate this value from
any other use of `REPORTDATA` (for example the blueprint's constant
`SHA-256(64 zero bytes)`) and from other protocol versions.

**Long-term identity (optional, [SEALING.md](SEALING.md)).** `EK` is always
fresh per enclave instance and is never sealed. If `EK` were stable, every
old quote would vouch for it, and one leak of `ek_sk` would allow
impersonation forever. An enclave that wants a stable, pinnable identity
holds a separate X25519 key `LK`. `LK` is sealed and persisted through host
storage, and it is proven inside each attested session with a
challenge-response bound to that session's `ek_pub`
(`sgx_ra_core::identity`). We use X25519 for `EK`, not Ed25519. The key only
needs to authenticate key agreement, and the static-ephemeral DH does that
implicitly without a second curve implementation in the enclave.

The enclave also stores `rb_hash = SHA-256(report_body)` of the report it just
created. This report body is identical to `quote[48..432]`.

### 6.3 Message types (first byte of every layer-1 payload)

| type | name | direction | layout | size |
|------|------|-----------|--------|------|
| `0x01` | `HELLO` | C → E | `01 ‖ ver=01 ‖ c_pub[32] ‖ c_nonce[32]` | 66 |
| `0x02` | `HELLO_REPLY` | E → C | `02 ‖ ver=01 ‖ ek_pub[32] ‖ se_pub[32] ‖ s_nonce[32] ‖ confirm[32]` | 130 |
| `0x03` | `RECORD` | both | `03 ‖ seq: u64 BE ‖ ciphertext ‖ tag[16]` | 25 … 4096 |

Every message has at least 1 byte (quirk Q3) and at most 4096 bytes (Q1/Q2).
So a record carries at most **4071 bytes of plaintext**. Applications needing
more must chunk at the application layer.

### 6.4 Handshake (1 round trip, Noise-NK-like with an extra enclave ephemeral)

```
Client                                                    Enclave
  quote  ◀────────────── (layer 1 announcement) ──────────────
  verify quote + policy (§6.6), keep report_data, rb_hash = SHA-256(quote[48..432])
  c_sk, c_pub ← X25519 keygen;  c_nonce ← 32 random bytes
  HELLO(c_pub, c_nonce) ──────────────────────────────────────▶
                                       se_sk, se_pub ← keygen;  s_nonce ← rand
                                       th, keys = derive(...)   (below)
  ◀──────────────────────────── HELLO_REPLY(ek_pub, se_pub, s_nonce, confirm)
  check SHA-256("SGXRA-v1/report-data"||0x00||ek_pub) == report_data[0..32]
  check report_data[32..64] == 0
  derive th, keys; check confirm (constant time)
```

Derivation, computed identically on both sides:

```
th   = SHA-256( "SGXRA-v1/transcript" || rb_hash
              || c_pub || c_nonce || ek_pub || se_pub || s_nonce )
ikm  = X25519(c_sk, ek_pub) || X25519(c_sk, se_pub)        // enclave: X25519(ek_sk,c_pub) || X25519(se_sk,c_pub)
prk  = HKDF-Extract(salt = th, ikm)
k_c2e  = HKDF-Expand(prk, "SGXRA-v1/c2e",     32)
k_e2c  = HKDF-Expand(prk, "SGXRA-v1/e2c",     32)
k_conf = HKDF-Expand(prk, "SGXRA-v1/confirm", 32)
confirm = HMAC-SHA256(k_conf, "SGXRA-v1/enclave-confirm" || th)
```

Security argument, in brief:

* Only code with the attested MRENCLAVE generated `ek_pub` (it is in
  report_data, which Intel's QE signed together with MRENCLAVE). Only that code
  holds `ek_sk`. A correct `confirm` therefore proves the peer can compute
  `X25519(ek_sk, c_pub)`, so the client is talking to the attested enclave.
  This holds even though host, operator, and TLS are untrusted.
* `rb_hash` in `th` binds the channel to the exact attested report (MRENCLAVE,
  attributes, SVNs, report_data).
* `se` (a fresh enclave ephemeral per handshake) plus `c` give forward secrecy
  even though `EK` serves the whole instance. An enclave instance accepts
  only one handshake (see below).
* Authentication is one-way, like server-only TLS: the enclave learns nothing
  about who the client is. Applications that need client identity must add it
  inside the record layer (e.g. a signed token in the first request).
* An old quote replayed by the operator is useless without `ek_sk`. A platform
  whose TCB was later compromised is caught by TCB-status evaluation against
  current collateral (§6.6), not by quote freshness.

The enclave accepts `HELLO` only after `enclave_create_report` has run, and only
once per enclave instance. Any later `HELLO` is an error and also ends the
session that is active (`sgx_ra_core::session::EnclaveEndpoint`).

**Why `ek_pub` travels in `HELLO_REPLY` and not with the quote.** The
announcement frame (§2.1) is built by the untrusted host (`App.cpp` sends
`u32 len ‖ quote`), so the enclave cannot append its key there without
breaking compatibility with the deployed C++ host. Sending `ek_pub` one message
later is just as secure:

* The client verifies the quote and policy **before** it sends `HELLO`
  (`ClientHandshake::start` takes `VerifiedClaims`, which only a verifier
  produces).
* `HELLO` carries only a fresh ephemeral public key and a nonce, nothing
  secret.
* The first thing the client does with `HELLO_REPLY` is require
  `report_data == report_data_for(ek_pub)` exactly. It derives no keys and
  sends no application data until that check and the key confirmation pass.

**What the transcript covers.** `th` contains the client and enclave keys and
`rb_hash`, the hash of the attested report body: MRENCLAVE, MRSIGNER,
attributes, SVNs and report_data. It does not contain the quote's signature
section, which the QE produces outside the enclave and the enclave never
sees. That section authenticates the body and adds no claims about the
enclave.

**Implementation** (`crates/sgx-ra-core`):

| Module | Content |
|--------|---------|
| `binding` | `report_data_for`, `check_report_data` (constant time) |
| `handshake` | messages (§6.3), `IdentityKey`, `ClientHandshake::{start, finish}`, enclave `respond` |
| `record` | `Session::{seal, open}`: per-direction keys, counter nonces, strict sequence check, wipe on any error |
| `session` | `MessageTransport` trait; `EnclaveEndpoint` (enclave state machine: `HELLO` once, then `RECORD`s); `ClientChannel` (`SecureChannel` + `AttestedChannel`) |

Crates, pinned exactly (`=`) because they are linked into the enclave and so
feed MRENCLAVE: `x25519-dalek 2.0.1` (`static_secrets`, `zeroize`),
`sha2 0.10.9`, `hkdf 0.12.4`, `hmac 0.12.1`, `chacha20poly1305 0.10.1`,
`subtle 2.6.1`, `zeroize 1.8.1`. All of them are built without default
features: no `std`, and no `getrandom` (randomness comes from the framework's
`Rng`). In enclave builds the portable backends are forced (no CPUID
detection, no SIMD): `sgx-ra-core/force-soft` for SHA-2 and the
`chacha20_force_soft`, `poly1305_force_soft` and
`curve25519_dalek_backend="serial"` cfgs in `.cargo/config.toml` for
`x86_64-unknown-none`.

### 6.5 Records

```
RECORD = 0x03 || seq (u64 BE) || ChaCha20-Poly1305(key, nonce, aad, plaintext)
nonce  = 0x00000000 || seq (u64 BE)            // 12 bytes
aad    = 0x03 || seq (u64 BE)
key    = k_c2e for client→enclave, k_e2c for enclave→client
```

* The client numbers requests `seq = 0, 1, 2, …`. The enclave accepts **only**
  the next expected `seq`, which gives replay and reorder protection. The
  response carries the same `seq` under `k_e2c`. (Each direction keeps its own
  counter starting at 0. In request/response lockstep the two counters are
  always equal.) Separate keys mean nonces
  never repeat under one key.
* On any failure (bad tag, wrong seq, oversize, unknown type), the enclave
  **destroys the session keys** and returns an error status. The host then sends
  status `0x02` (layer 1). The client must also treat any non-zero status as
  fatal for the session. It must never downgrade to plaintext.
* `seq` must not reach `2^64 − 1`. The session must be re-keyed (by
  reconnecting) first.

### 6.6 Client acceptance policy (minimum)

The client accepts a session only if **all** of these hold:

1. The quote parses strictly (§3.1–3.3). `version == 3`, `att_key_type == 2`,
   `qe_vendor_id` is Intel, `cert_data_type == 5`, and the lengths are exactly
   consistent.
2. The PCK chain ends at the **pinned Intel SGX Root CA**. Every certificate is
   time-valid. Root CA CRL and PCK CRL are signed by their issuers, and the
   intermediate and **leaf** are not revoked.
3. TCB Info and QE Identity signatures are valid under the TCB signing cert,
   which chains to the pinned root. Collateral is not past `nextUpdate`, unless
   policy explicitly allows grace.
4. The QE report matches QE Identity (MRSIGNER, ISVPRODID, ISVSVN ≥ TCB level,
   masked attributes/miscselect). The QE report signature verifies under the
   PCK key. `qe_report.report_data[0..32] == SHA-256(att_pub ‖ qe_auth_data)`.
5. The quote signature verifies under the attestation key.
6. The platform TCB status from TCB Info (matching FMSPC, PCK cpusvn/pcesvn) is
   in the policy's allowed set (default: `UpToDate` only; opt-in for
   `SWHardeningNeeded` / `ConfigurationNeeded`).
7. Enclave report: `DEBUG` clear, `MODE64BIT` set,
   `mr_enclave == expected` (taken from a local reproducible build),
   optional `mr_signer`, `isv_prod_id`, and minimum `isv_svn`.
8. Handshake succeeds as in §6.4, including the report_data binding.

---

## 7. Interoperability summary

| Component | Talks layer 1 | Talks layer 2 |
|-----------|---------------|---------------|
| Blueprint C++ `app` + C++ echo enclave | ✔ | ✘ (plain echo) |
| Blueprint C++ `app` + **our Rust enclave** | ✔ | ✔ (enclave implements it) |
| **Our Rust host** + our Rust enclave | ✔ (same framing, bounded, logs on stderr) | ✔ |
| Blueprint `main.py` → our enclave | ✔ quote check | ✘ (would just see `HELLO` errors) |
| **Our Rust client** → any of the above | ✔ | ✔ when the enclave supports it |

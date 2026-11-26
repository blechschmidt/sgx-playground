# Quickstart: the Rust flow

> **Note (2026-11-26):** `sgx-playground.blechschmidt.io` has been
> decommissioned due to costs. Point the client at your own executor with
> `--host` and `--port` instead.

This walks through the full flow with the echo example. You rebuild the
enclave reproducibly, attest the remote enclave at
`sgx-playground.blechschmidt.io:443`, and exchange a message over the
attested channel. Each step says what it proves. The background is in
[ARCHITECTURE.md](ARCHITECTURE.md) and [PROTOCOL.md](PROTOCOL.md).

> **The public executor** runs the Rust host and echo enclave on real SGX
> hardware. It is a KVM guest whose platform TCB status is
> `OutOfDateConfigurationNeeded` (TCB date 2024-03-13). `echo-client`
> accepts it by default because the status and each of its Intel
> advisories are on explicit allowlists; a platform with any other advisory
> is rejected. `--strict-tcb` accepts only `UpToDate`,
> `--allow-tcb-status STATUS` (repeatable) accepts `UpToDate` plus the
> listed statuses, and `--allow-advisory ID` (repeatable) /
> `--any-advisory` replace / disable the advisory allowlist. Why the status can't be fixed from the VM and what the
> cloud provider has to change is in [TCB_STATUS.md](TCB_STATUS.md).

## Prerequisites

* Docker (or Podman) for the reproducible build. BuildKit/buildx is
  optional: without it the scripts and the client use `docker create` +
  `docker cp`. If plain `docker compose build` fails, set
  `DOCKER_BUILDKIT=0`.
* Docker Compose v2 (`docker compose`) for the compose route.
* For building the client outside Docker: Rust (`rust-toolchain.toml` pins
  1.100.0; `rustup` picks it up).
* About 6 GB of free disk for the Nix build container.
* An SGX machine only for step 5. Verifying the remote enclave (steps
  2–4) works on any host; see
  [Verifying from a host without SGX](#verifying-from-a-host-without-sgx).

Run every command from the repository root. It is the build context of
the Nix container.

## Verifying from a host without SGX

Only the executor needs SGX. The verifying side needs none of it:

| What | Where it comes from on the verifier |
|---|---|
| expected MRENCLAVE | the reproducible Nix build in Docker (step 2): no SGX device, `sgx_sign` runs inside the build container |
| quote | sent by the executor over the (untrusted) TLS connection |
| quote verification | `sgx-ra-verifier`, pure Rust (P-256, X.509, CRLs, TCB Info, QE Identity), Intel SGX Root CA compiled in. No `libsgx_dcap_quoteverify`, no QvE, no AESM |
| collateral | Intel's PCS (`https://api.trustedservices.intel.com`, no API key) by default, also the default of `PccsConfig::default()`. No local PCCS |
| channel | X25519/ChaCha20-Poly1305 in `sgx-ra-core`, no hardware dependency |

`echo-client` links only libc and libgcc. To check this on the real
thing, run the client in a container that has no SGX device, no AESM
socket, no SGX/DCAP library, no capabilities and its own network
namespace:

```sh
scripts/verify-without-sgx.sh
```

It builds the enclave reproducibly if `target/nix-enclave/enclave/` is
missing, builds `containers/Dockerfile.verify-rs`, checks that environment,
then attests `sgx-playground.blechschmidt.io:443` and exchanges a message
over the attested channel. Output from 2026-11-24 (abridged):

```
[OK] no SGX device (/dev/sgx*, /dev/isgx)
[OK] no AESM service (/var/run/aesmd)
[OK] no SGX SDK / DCAP / quote provider library installed
[OK] echo-client links only:  linux-vdso.so.1 libc.so.6 libgcc_s.so.1 /lib64/ld-linux-x86-64.so.2
[OK] no capabilities (CapEff: 0000000000000000), own network namespace, read-only root
[OK] Expected MRENCLAVE from /enclave/enclave.so.gendata: 3f31f232…
[OK] Connected to sgx-playground.blechschmidt.io:443 via TLS (…, certificate verified against the Mozilla roots); …
[OK] PCK certificate chain verified up to the pinned Intel SGX Root CA (…); … PCK certificate not revoked
…
[OK] Remote MRENCLAVE 3f31f232… is identical to the local build: the remote runs exactly the code we built
[OK] Attested report_data binds the enclave's channel public key …
[OK] Handshake complete: the enclave proved possession of the attested private key …
Reply received from server: Hello, SGX server!
```

The same works without the script: `docker compose run --rm verify-rs`
(Intel PCS and verified
TLS are its defaults), or the native binary from step 3 Option B.

## 1. Optional: a PCCS (not needed by anyone; it needs an API key)

Who needs what from Intel, and why no API key is needed
([NO_API_KEY.md](NO_API_KEY.md)):

* **The SGX host** needs the platform's PCK certificate so that the quote
  provider can produce a quote. The host image fetches it straight from
  Intel's PCS v4 (`config/sgx_default_qcnl.conf`), which serves it
  without an API key. If that fetch fails, the host cannot produce a quote
  and clients get a DCAP error text instead (exit code 3).
* **The client** needs TCB Info, QE Identity and CRLs to verify a quote. It
  fetches them from Intel's PCS (`https://api.trustedservices.intel.com`)
  by default, which needs no API key. A local PCCS is only a cache. Either
  way, every document is verified against the Intel SGX Root CA pinned in
  the client, so the PCCS is not trusted
  ([THREAT_MODEL.md §4.8](THREAT_MODEL.md#48-pccs-trust-http-vs-https-intel-root-pinning--ok-residue-accepted)).

The blueprint's PCCS is a cache in front of Intel's PCS for many hosts.
Its stock code always sends an API key header, and PCS rejects an empty or
wrong one (HTTP 401), so it is the one component that still needs a key.
To run it locally, get an API key from the
[Intel PCS portal](https://api.portal.trustedservices.intel.com/provisioning-certification),
then:

```sh
API_KEY=<YOUR_API_KEY> docker compose run --rm prepare-pccs  # config, CA, TLS cert
docker compose up -d pccs                                    # HTTP :8080, HTTPS :8081 (host network)
curl -s '127.0.0.1:8080/sgx/certification/v4/pckcrl?ca=processor&encoding=pem' | head -2
```

`prepare-pccs` saves the key in `sgx-playground/config/pccs/.env`, so the
`up` (which reruns it through `depends_on`) needs no `API_KEY`. It writes its self-signed CA to
`sgx-playground/config/pccs/tls/ca.crt` and to the compose volume `shared`
(`/shared/ca.crt`). The Rust client uses it as `--pccs-ca`.

## 2. Build the enclave reproducibly

```sh
scripts/nix-build-enclave.sh            # -> target/nix-enclave/enclave/
cat target/nix-enclave/enclave/MRENCLAVE.txt
```

or, with compose (output in the `enclave` volume):

```sh
docker compose run --rm nix-build       # prints "MRENCLAVE …"
```

The build runs `nix build .#enclave` inside a digest-pinned `nixos/nix`
image (`containers/Dockerfile.nix-build`). The first run takes about
5–6 minutes. The MRENCLAVE must equal the value in the
[README table](../README.md#measurements-of-the-echo-enclave). If it does not,
your tree differs from the commit the table describes. To prove that the
build is deterministic on your machine, see
[REPRODUCIBILITY.md](REPRODUCIBILITY.md).

You can skip this step: the client in step 3 runs the same build itself.
Doing it once by hand shows the measurement you are about to pin.

## 3. Run the Rust client against the executor

### Option A: compose

```sh
# With Intel's PCS (the default; no local PCCS needed):
docker compose run --rm verify-rs

# With the local PCCS from step 1:
SGX_RA_PCCS_URL=https://127.0.0.1:8081 SGX_RA_PCCS_CA=/shared/ca.crt \
  docker compose run --rm verify-rs
```

`verify-rs` depends on `nix-build`. It reads the expected MRENCLAVE from
the `enclave` volume and runs `echo-client`. TLS is checked against the
Mozilla roots by default; `SGX_RA_TRANSPORT=--insecure-tls` skips that
check (TLS is not part of the trust chain). Extra arguments are passed through, e.g.
`docker compose run --rm verify-rs -m "hi" -i`. All variables are listed in
`containers/verify-rs-entrypoint.sh`.

### Option B: native binary

```sh
cargo build --release -p echo-client
target/release/echo-client
```

Run it from the repository root. From elsewhere it falls back to the
source tree it was compiled from for the Dockerfile and build context.

Without `--gendata-path`, the client itself builds
`containers/Dockerfile.nix-build` (the Dockerfile of the reproducible Nix
container) and takes MRENCLAVE from the exported `enclave.so.gendata`.
It cross-checks that value against `MRENCLAVE.txt`. Useful variants:

```sh
# Reuse the artefacts of step 2 instead of building again:
target/release/echo-client \
  --gendata-path target/nix-enclave/enclave/enclave.so.gendata

# Use the local PCCS for collateral:
target/release/echo-client \
  --pccs-url https://127.0.0.1:8081 \
  --pccs-ca sgx-playground/config/pccs/tls/ca.crt

# Also pin the signer (MRSIGNER verification) and the product/SVN:
target/release/echo-client \
  --mrsigner "$(cat target/nix-enclave/enclave/MRSIGNER.txt)" \
  --isv-prod-id 1 --min-isv-svn 1
```

All options are listed in [examples/echo-client/README.md](../examples/echo-client/README.md).

### What a successful run checks

```
[OK] Expected MRENCLAVE from the local build: 3f31f232…
[OK] Connected to sgx-playground.blechschmidt.io:443 via TLS (…); TLS ends outside the enclave and is treated as an untrusted pipe
[OK] Received quote (… bytes)
[OK] Quote structure valid: DCAP v3 ECDSA-P256 quote from the Intel QE, PCK certificate chain attached
[OK] PCK certificate chain verified up to the pinned Intel SGX Root CA (…); … CRLs checked, PCK certificate not revoked
[OK] TCB Info (FMSPC …) and QE Identity signed by Intel SGX TCB Signing; …
[OK] Quoting enclave report signed by the PCK key and matches QE Identity …
[OK] Quote signature over header and enclave report verified with the attestation key
[OK] Platform TCB status UpToDate (…); allowed by policy
[OK] Enclave is not in debug mode (DEBUG attribute clear) and is 64-bit
[OK] Remote MRENCLAVE 3f31f232… is identical to the local build: the remote runs exactly the code we built
[OK] MRSIGNER … (not pinned)   ISVPRODID 1 = 1 …   ISVSVN 1 >= 1 …
[OK] Attested report_data binds the enclave's channel public key …: report_data = SHA-256("SGXRA-v1/report-data" || 00 01 || key) || 0^32 = …
[OK] Handshake complete: the enclave proved possession of the attested private key (key confirmation verified); …
[OK] Confidential channel established (X25519 + HKDF-SHA256, ChaCha20-Poly1305 records)
[OK] Sent 18 bytes encrypted; reply of 18 bytes decrypted and authenticated
[OK] Echo matches the request
```

(abridged; observed against the public executor on real SGX hardware,
2026-11-24). The important line is the report_data one: the X25519 key of
the channel hashes to the value that Intel's QE signed together with
MRENCLAVE, and the enclave proved during the handshake that it holds the
private key. Only code with that MRENCLAVE could have produced the key
([PROTOCOL.md §6.2](PROTOCOL.md#62-enclave-identity-key-and-report_data-binding)).

### Exit codes and what to do

| code | meaning | typical cause |
|---|---|---|
| 0 | verified, all echoes matched | — |
| 1 | build, verification, policy, handshake or echo failure | MRENCLAVE mismatch (the executor runs a different enclave); TCB status not allowed (with `--strict-tcb` or a narrowed `--allow-tcb-status`); stale collateral |
| 2 | invalid command line | — |
| 3 | the remote sent a DCAP error text instead of a quote | the executor could not fetch its PCK certificate (Intel PCS or its PCCS unreachable) |

## 4. The whole flow as a test report

```sh
scripts/e2e.sh              # or --compose; --skip-build reuses step 2
cat target/e2e/report.md    # PASS / FAIL / BLOCKED per check
```

Besides the positive flow, this runs the negative checks: a modified
enclave source must change MRENCLAVE, and a substituted key, tampered
records and a man-in-the-middle proxy must all be rejected. BLOCKED means
the executor sent no quote, so nothing was verified.

## 5. Optional: run the host on your own SGX machine

On a machine with `/dev/sgx_enclave` and `/dev/sgx_provision` (no PCCS,
no API key, no AESM needed):

```sh
scripts/nix-build-host-image.sh                          # sgx-ra-echo-host:latest (Nix, reproducible)
docker compose --profile local-sgx up -d host-app        # 127.0.0.1:7000, one enclave per connection
SGX_RA_HOST=127.0.0.1 SGX_RA_PORT=7000 SGX_RA_TRANSPORT=--plaintext \
  docker compose run --rm verify-rs
```

`config/sgx_default_qcnl.conf` (also built into the image) points the
host's quote provider at Intel's PCS v4. To use the PCCS from step 1
instead, set `SGX_RA_QCNL_CONF=./config/sgx_default_qcnl.local-pccs.conf`
(`https://localhost:8081`). To expose the host the way the public executor
does, put stunnel in front of it and use
[`containers/wrapper.sh`](../containers/wrapper.sh) as its `exec`.

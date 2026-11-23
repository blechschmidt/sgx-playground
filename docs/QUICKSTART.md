# Quickstart: the Rust flow

This walks through the full flow with the echo example. You rebuild the
enclave reproducibly, attest the remote enclave at
`sgx-playground.blechschmidt.io:443`, and exchange a message over the
attested channel. Each step says what it proves. The background is in
[ARCHITECTURE.md](ARCHITECTURE.md) and [PROTOCOL.md](PROTOCOL.md).

> **Status of the public executor (2026-11-23).** The executor currently
> sends a DCAP error text instead of a quote, because its own PCCS is
> unreachable ([PROTOCOL.md §5](PROTOCOL.md#5-live-observations-2026-11-222026-11-23)).
> The client reports this with exit code 3. In addition, the executor runs
> the operator's enclave, today the blueprint's C++ echo enclave
> ([PROTOCOL.md §1.1](PROTOCOL.md#11-which-enclave-does-the-executor-load)).
> Even with a working PCCS, the client therefore rejects it with an
> MRENCLAVE mismatch until the operator deploys the Rust enclave. That
> rejection is the correct result. To see the positive path, run the
> host yourself on an SGX machine ([step 5](#5-optional-run-the-host-on-your-own-sgx-machine)).
> So far no run has been made on real SGX hardware
> ([THREAT_MODEL.md TM-10](THREAT_MODEL.md#tm-10-no-end-to-end-run-on-sgx-hardware)).

## Prerequisites

* Docker (or Podman) for the reproducible build. BuildKit/buildx is
  optional: without it the scripts and the client use `docker create` +
  `docker cp`. If plain `docker compose build` fails, set
  `DOCKER_BUILDKIT=0`.
* Docker Compose v2 (`docker compose`) for the compose route.
* For building the client outside Docker: Rust (`rust-toolchain.toml` pins
  1.100.0; `rustup` picks it up).
* About 6 GB of free disk for the Nix build container.
* An SGX machine only for step 5.

Run every command from the repository root. It is the build context of
the Nix container.

## 1. Prepare a PCCS (optional for the client)

Who needs collateral, and why:

* **The SGX host** needs a PCCS so that the quote provider can fetch the
  platform's PCK certificate. Without one, the host cannot produce a quote
  at all. This is the failure the public executor has today.
* **The client** needs TCB Info, QE Identity and CRLs to verify a quote. It
  fetches them from Intel's PCS (`https://api.trustedservices.intel.com`)
  by default, which needs no API key. A local PCCS is only a cache. Either
  way, every document is verified against the Intel SGX Root CA pinned in
  the client, so the PCCS is not trusted
  ([THREAT_MODEL.md §4.8](THREAT_MODEL.md#48-pccs-trust-http-vs-https-intel-root-pinning--ok-residue-accepted)).

To run the blueprint's PCCS locally, get an API key from the
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
# With Intel's PCS (no local PCCS needed):
SGX_RA_PCCS_URL=https://api.trustedservices.intel.com SGX_RA_PCCS_CA=none \
  docker compose run --rm verify-rs

# With the local PCCS from step 1 (the default):
docker compose run --rm verify-rs
```

`verify-rs` depends on `nix-build`. It reads the expected MRENCLAVE from
the `enclave` volume and runs `echo-client` with
`--insecure-tls` (the executor's certificate has expired, and TLS is not
part of the trust chain). Extra arguments are passed through, e.g.
`docker compose run --rm verify-rs -m "hi" -i`. All variables are listed in
`containers/verify-rs-entrypoint.sh`.

### Option B: native binary

```sh
cargo build --release -p echo-client
target/release/echo-client --insecure-tls
```

Without `--gendata-path`, the client itself builds
`containers/Dockerfile.nix-build` (the Dockerfile of the reproducible Nix
container) and takes MRENCLAVE from the exported `enclave.so.gendata`.
It cross-checks that value against `MRENCLAVE.txt`. Useful variants:

```sh
# Reuse the artefacts of step 2 instead of building again:
target/release/echo-client --insecure-tls \
  --gendata-path target/nix-enclave/enclave/enclave.so.gendata

# Use the local PCCS for collateral:
target/release/echo-client --insecure-tls \
  --pccs-url https://127.0.0.1:8081 \
  --pccs-ca sgx-playground/config/pccs/tls/ca.crt

# Also pin the signer (MRSIGNER verification) and the product/SVN:
target/release/echo-client --insecure-tls \
  --mrsigner "$(cat target/nix-enclave/enclave/MRSIGNER.txt)" \
  --isv-prod-id 1 --min-isv-svn 1
```

All options are listed in [examples/echo-client/README.md](../examples/echo-client/README.md).

### What a successful run checks

```
[OK] Expected MRENCLAVE from the local build: bdd7e786…
[OK] Connected to sgx-playground.blechschmidt.io:443 via TLS (…); TLS ends outside the enclave and is treated as an untrusted pipe
[OK] Received quote (… bytes)
[OK] Quote structure valid: DCAP v3 ECDSA-P256 quote from the Intel QE, PCK certificate chain attached
[OK] PCK certificate chain verified up to the pinned Intel SGX Root CA (…); … CRLs checked, PCK certificate not revoked
[OK] TCB Info (FMSPC …) and QE Identity signed by Intel SGX TCB Signing; …
[OK] Quoting enclave report signed by the PCK key and matches QE Identity …
[OK] Quote signature over header and enclave report verified with the attestation key
[OK] Platform TCB status UpToDate (…); allowed by policy
[OK] Enclave is not in debug mode (DEBUG attribute clear) and is 64-bit
[OK] Remote MRENCLAVE bdd7e786… is identical to the local build: the remote runs exactly the code we built
[OK] MRSIGNER … (not pinned)   ISVPRODID 1 = 1 …   ISVSVN 1 >= 1 …
[OK] Attested report_data binds the enclave's channel public key …: report_data = SHA-256("SGXRA-v1/report-data" || 00 01 || key) || 0^32 = …
[OK] Handshake complete: the enclave proved possession of the attested private key (key confirmation verified); …
[OK] Confidential channel established (X25519 + HKDF-SHA256, ChaCha20-Poly1305 records)
[OK] Sent 18 bytes encrypted; reply of 18 bytes decrypted and authenticated
[OK] Echo matches the request
```

(abridged; this is the expected output, which has not yet been observed
against real SGX hardware). The important line is the report_data one: the X25519 key of
the channel hashes to the value that Intel's QE signed together with
MRENCLAVE, and the enclave proved during the handshake that it holds the
private key. Only code with that MRENCLAVE could have produced the key
([PROTOCOL.md §6.2](PROTOCOL.md#62-enclave-identity-key-and-report_data-binding)).

### Exit codes and what to do

| code | meaning | typical cause |
|---|---|---|
| 0 | verified, all echoes matched | — |
| 1 | build, verification, policy, handshake or echo failure | MRENCLAVE mismatch (the executor runs a different enclave); TCB status not allowed (`--allow-tcb-status SWHardeningNeeded` if you accept it); stale collateral |
| 2 | invalid command line | — |
| 3 | the remote sent a DCAP error text instead of a quote | the executor's PCCS is down (the current state of the public executor) |

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

On a machine with `/dev/sgx_enclave` and `/dev/sgx_provision`, with the
PCCS from step 1 running:

```sh
scripts/nix-build-host-image.sh                          # sgx-ra-echo-host:latest (Nix, reproducible)
docker compose --profile local-sgx up -d host-app        # 127.0.0.1:7000, one enclave per connection
SGX_RA_HOST=127.0.0.1 SGX_RA_PORT=7000 SGX_RA_TRANSPORT=--plaintext \
  docker compose run --rm verify-rs
```

`config/sgx_default_qcnl.conf` points the host's quote provider at
`https://localhost:8081`. To expose the host the way the public executor
does, put stunnel in front of it and use
[`containers/wrapper.sh`](../containers/wrapper.sh) as its `exec`.

# echo-client

Rust replacement for the blueprint's `sgx-client/main.py`, built on
`sgx-ra-client`. It rebuilds the echo enclave from source, attests the
remote enclave and then talks to it over a channel whose key provably exists
only inside that enclave.

```sh
cargo build --release -p echo-client
# from the repository root (the build context):
target/release/echo-client --insecure-tls
```

## Flow and output

| step | what is checked | `[OK]` line (abridged) |
|---|---|---|
| 1 | Build `containers/Dockerfile.nix-build` locally (`docker build --output type=local,…`; without buildx the classic builder plus `docker create`/`docker cp` is used, and podman also works). MRENCLAVE comes from the exported `enclave.so.gendata` and is cross-checked against `MRENCLAVE.txt`. | `Expected MRENCLAVE from the local build: …` |
| 2 | Outer TLS (rustls with Mozilla roots). It is transport only, because TLS ends at the operator's stunnel. | `Connected to …:443 via TLS (…)` |
| 3 | Quote announcement: framing, size limits, DCAP v3 structure. A quote MRENCLAVE that differs from the build fails here, before any collateral is fetched. | `Received quote`, `Quote structure valid` |
| 4 | DCAP: the PCK chain goes up to the pinned Intel SGX Root CA, the CRLs are checked, TCB Info and QE Identity signatures are verified, the QE report is checked, then the quote signature. Policy: no DEBUG, 64-bit, MRENCLAVE equals the build, ISVPRODID / ISVSVN (default: the build's SIGSTRUCT values), optional MRSIGNER, and the TCB status is in the allowed set (default `UpToDate`). | one line per check |
| 5 | SGXRA v1 handshake. The enclave's X25519 key must hash to the attested report_data, and the enclave must prove it holds the private key (key confirmation). | `Attested report_data binds the enclave's channel public key …`, `Handshake complete` |
| 6 | Encrypted echo of `Hello, SGX server!` (or of each `--message`, or of each stdin line with `--interactive`). The reply must equal the request. | `Echo matches the request` |

Every failure prints `[FAIL] …` on stderr and exits non-zero.

| exit code | meaning |
|---|---|
| 0 | everything verified, all echoes matched |
| 1 | a build, verification, policy, handshake or echo failure |
| 2 | invalid command line |
| 3 | the remote host sent a DCAP error text instead of a quote (the remote attestation infrastructure is unavailable) |

## Common options

* `--gendata-path FILE` / `--expected-mrenclave HEX`: skip the build.
* `--pccs-url URL`: Intel PCS by default. A PCCS such as
  `http://127.0.0.1:8080` also works; collateral is always verified.
  `--pccs-ca PEM` sets the CA for an HTTPS PCCS.
* `--strict-tcb` (only `UpToDate`; the default accepts every TCB status
  except `Revoked`, with a warning), `--allow-tcb-status STATUS`
  (repeatable: `UpToDate` plus these), `--mrsigner`,
  `--isv-prod-id`, `--min-isv-svn`, `--collateral-grace SECONDS`.
* `--insecure-tls` (accept any TLS certificate; TLS is not trusted),
  `--tls-ca PEM`, and `--plaintext` (for a local `echo-host-app --listen`).
* `-m TEXT` (repeatable), `-i/--interactive`, `--loglevel debug`.
* `--build-output DIR` keeps the artefacts. `--build-arg K=V`,
  `--container-engine docker|podman` and `--no-cache` are passed through to
  the build.
* `inspect-quote` / `inspect-gendata` / `inspect-sigstruct` parse files
  offline. They do not verify anything.

## Status of the public executor

`sgx-playground.blechschmidt.io:443` runs this echo enclave on real SGX
hardware, and `echo-client` without arguments attests it and echoes a
message. Its platform TCB status is `OutOfDateConfigurationNeeded`, which
the default policy accepts with a warning (`--strict-tcb` rejects it). The
client also prints which TCB components fall short; see
[TCB_STATUS.md](../../docs/TCB_STATUS.md). If
the executor's PCCS is down, it sends `[QCNL] Error: …` instead of a
quote, and the client exits with code 3.

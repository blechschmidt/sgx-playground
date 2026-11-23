# SGX remote attestation without an Intel API key

**Short answer: it works end to end with no API key.** Neither the side that
generates a quote nor the side that verifies one needs a key. The blueprint
used a key only because its PCCS, a caching proxy, sends one on every request
to Intel. We go straight to Intel's PCS v4, which answers without one.
Measured on 2026-11-24 against the live executor; `scripts/check-intel-pcs-keyless.sh`
repeats the endpoint checks from any machine.

## What needs Intel, and for what

DCAP attestation contacts Intel's Provisioning Certification Service (PCS,
`https://api.trustedservices.intel.com/sgx/certification/v4/`) at two
points:

| Who | Request | What for | Key needed? |
|---|---|---|---|
| SGX host, quote generation (QCNL in `libdcap_quoteprov`) | `GET v4/pckcert?encrypted_ppid=…&cpusvn=…&pcesvn=…&pceid=…` | the platform's PCK certificate and chain; QE3 puts them into the quote (certification data type 5) | **no** (200 with a real PPID) |
| PCCS in `REQ` mode | `GET v4/pckcerts?encrypted_ppid=…&pceid=…` | every PCK certificate of the platform, for caching | **no** (200 with a real PPID) |
| verifier (our client) | `v4/tcb`, `v4/qe/identity`, `v4/pckcrl`, Root CA CRL on `certificates.trustedservices.intel.com` | collateral for the TCB, QE and revocation checks | **no** |
| verifier | PCK certificate | not needed: it is inside the quote | n/a |
| anyone, **PCS v3** | `v3/pckcert`, `v3/pckcerts` | older API | **yes** (401) |
| anyone, v4 with an **empty or wrong** `Ocp-Apim-Subscription-Key` header | `v4/pckcert(s)` | | **refused** (401) |

The last two rows explain why the blueprint needed a key: the stock PCCS
(`pcs_client.js` in DCAP 1.23) always sends `Ocp-Apim-Subscription-Key`,
even when its `ApiKey` setting is empty, and PCS rejects an empty key. So a
PCCS cannot simply be run with `"ApiKey": ""`; it would have to be patched
to omit the header. Leaving the header out is all it takes.

Legacy EPID attestation through the Intel Attestation Service (IAS) always
needed a subscription key, but IAS has been shut down. DCAP is the only
option on current platforms anyway.

## How the framework avoids the key

**Verifying** has always been keyless: `sgx-ra-client` fetches collateral
from Intel's PCS by default (`PccsConfig::default()`), and every document is
checked against the Intel SGX Root CA pinned in the client. Where the bytes
come from does not affect trust ([THREAT_MODEL.md §4.8](THREAT_MODEL.md)).

**Quote generation** used to go through the blueprint's PCCS on
`localhost:8081`, whose setup asks for an API key. Now:

* the host image (`nix/host-image.nix`) ships a QCNL config that points
  `pccs_url` at `https://api.trustedservices.intel.com/sgx/certification/v4/`
  with TLS verification on. QCNL's `pckcert` request is exactly the keyless
  v4 call above (Intel's extra `qeid` parameter is ignored by PCS);
* `config/sgx_default_qcnl.conf` holds the same config for compose's
  `host-app`; the old one is `config/sgx_default_qcnl.local-pccs.conf`;
* `containers/wrapper.sh` (stunnel `exec` on the public executor) uses the
  image's built-in config unless `SGX_RA_QCNL_CONF` names another file.

With that, an SGX host only needs the two device nodes. It needs no PCCS,
no AESM and no API key:

```sh
scripts/nix-build-host-image.sh
docker run --rm -d -p 127.0.0.1:7000:7000 \
  --device /dev/sgx_enclave --device /dev/sgx_provision \
  sgx-ra-echo-host:latest --listen 0.0.0.0:7000
echo-client --plaintext --host 127.0.0.1 --port 7000
```

The example uses Docker's default bridge network, so the container cannot
reach a PCCS on the host's `localhost` even if one is running.

## Verification done

* `scripts/check-intel-pcs-keyless.sh`: all keyless v4 requests pass
  authentication and both controls (v3, empty key header) get 401.
* A real encrypted PPID taken from this platform's PCCS log returned the PCK
  certificate (`SGX-FMSPC: 00606A000000`, `SGX-PCK-Certificate-CA-Type:
  platform`) from `v4/pckcert` and `v4/pckcerts` without a key.
* The host image ran on bridge networking with the keyless QCNL config (no
  PCCS reachable). `echo-client` verified the quote (PCK chain to the
  pinned root, TCB Info, QE Identity, MRENCLAVE `bdd7e786…`, report_data
  binding) and exchanged encrypted echoes.
* The public executor `sgx-playground.blechschmidt.io:443` was switched to
  the rebuilt image and wrapper, and its PCCS container was stopped
  (nothing listens on 8080/8081). `scripts/e2e.sh --skip-build` passed all
  nine stages, including the live attested echo and the live MITM attacks.

## Limits and trade-offs

* **Intel's terms, not cryptography.** Intel can require a key for v4 again
  at any time. The checks above would then fail with 401, and the fallback
  is the blueprint's PCCS plus a key (`config/sgx_default_qcnl.local-pccs.conf`).
  Trust is not affected either way: a key only authorises downloads, and
  everything downloaded is verified against Intel's root.
* **No shared cache.** Each host container fetches its PCK certificate from
  Intel once. Its QCNL cache lives in the container's `/tmp`, and the
  wrapper starts one container per connection, so that means one PCS
  request per connection. That is fine at demo scale. Busy hosts would
  hit Intel's rate limits; they can mount a persistent `/tmp` (QCNL caches
  for `pck_cache_expire_hours`) or run a PCCS.
* **Platform registration.** Multi-package servers must register their
  platform manifest with Intel before a PCK certificate exists. That goes
  through a separate registration service and was not tested here: the
  executor is a single-package KVM guest whose certificate already exists.
* **Offline hosts** need the PCK certificate some other way: a PCCS fed by
  the PCCS admin tool, or QCNL's `local_cache_only` with a pre-seeded cache.

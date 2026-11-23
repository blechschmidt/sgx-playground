# Test fixtures

Binary SGX artefacts used by the unit tests (`include_bytes!` from the
crates). Do not modify them; tests assert exact values.

| File | Size | SHA-256 | Provenance |
|------|------|---------|------------|
| `quote_v3.dat` | 4734 | `a10499ea37456dc0a5e81cff86f9a48a397fa2aa548f058ac53b1577653fd650` | Real DCAP v3 ECDSA quote from [`blechschmidt/intel-sgx-ra`](https://github.com/blechschmidt/intel-sgx-ra) `tests/data/quote.dat` at commit `c253216` (MIT, Cosmian Tech). The live remote executor cannot currently produce quotes (`docs/PROTOCOL.md` §5), so this is the reference quote. |
| `blueprint_enclave.so.gendata` | 256 | `1b01bb470be6b46d9d1d8f08cb3a3903368fccf7aa822cbfb70395750600fd08` | `sgx_sign gendata` output for the blueprint C++ enclave (`sgx-playground` commit `0532c29`, `server/`, `make enclave.signed.so`, SGX SDK 2.26, inside the `sgx-playground-server` image), built 2026-11-22. |
| `blueprint_enclave.sigstruct` | 1808 | `4d0d21861b6fc9ea60a8b0e5133802decdfd829a034757efd0bf6c49961d7545` | The full SIGSTRUCT of that same build (`sgx_sign dump -enclave enclave.signed.so -cssfile …`). It is signed with the throw-away key the blueprint Makefile generates. |
| `remote_pccs_error_session.bin` | 388 | `76a018a6d722dab0f7096fe5ceb7c7db4c01b970a1643a20987d6aacb81749af` | Everything `sgx-playground.blechschmidt.io:443` sent on 2026-11-22: a DCAP error text instead of a quote (quirk Q5). |

## Expected values

`quote_v3.dat`:

* header: version 3, att_key_type 2, qe_svn 9, pce_svn 14, Intel QE vendor id
  `939a7233f79c4ca9940a0db3957f0607`
* MRENCLAVE `e413a4ed616c7a79634d5ca05a2fda746a1f0c71349a80b25a02828846fab90e`
* MRSIGNER `ac2c9fa87e4c91768b1d0c47169466c50d5a98c790639fbaefe7352a59919980`
* ISVPRODID 1, ISVSVN 10, attributes flags `0x5` (INIT | MODE64BIT, not
  DEBUG), xfrm `0xe7`, report_data all zero
* QE auth data 32 bytes. Certification data is type 5, a 3682-byte PEM chain
  of 3 certificates. The QE report's report_data equals
  `SHA-256(att_key ‖ qe_auth_data)` followed by 32 zero bytes.

`blueprint_enclave.so.gendata` / `.sigstruct`:

* header magic `06000000E100000000000100`, header2
  `01010000600000006000000001000000`, date `0x20261122`
* MRENCLAVE (`enclave_hash`) `ed92b9ba8521bec3c3b2eacdf67846d275dd655965280028e05bf1a5f318434c`
* MRSIGNER (SHA-256 of the modulus) `c5cee5fe4a89d7ef4a3070015f344eee2c72710548a9c76c5e6cf7bb18cddfb2`
* attributes flags `0x4`, xfrm `0x3`. The attribute mask is
  `0xff00fffffffffffd`/`0xffffffffffffff1b`, so the DEBUG bit is unmasked
  (`DisableDebug = 0`).
* RSA exponent 3. The SIGSTRUCT header and body equal the gendata bytes.

## `dcap/`: DCAP collateral for `quote_v3.dat`

Recorded from Intel PCS (`https://api.trustedservices.intel.com/sgx/certification/v4/…`) on
2026-11-22 22:45 UTC for FMSPC `30606a000000` (the PCK leaf of `quote_v3.dat`,
issued by the Platform CA). The issuer chains are the URL-decoded response headers. The
Root CA CRL is from `https://certificates.trustedservices.intel.com/IntelSGXRootCA.der`.
Tests verify at 2026-11-23T00:00:00Z. The first item to expire is the PCK CRL, at
2026-12-22T21:33:19Z.

| File | Size | SHA-256 |
|------|------|---------|
| `intel_sgx_root_ca.der` | 659 | `44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3` |
| `pck_crl_platform.der` | 3355 | `8d6a473b53e04117e7048a889446226fa8520c705d5f66d49c2592857ed69d3b` |
| `qe_identity.json` | 1380 | `a3fbd7cd98b166b98d3b85d3235aea8aea95de59e829c34574e83ece741c49a6` |
| `qe_identity_issuer_chain.pem` | 1892 | `c550544e4442d9be583a5eddd48df8ba0149ddeef40efd3737ebe0f885dc3711` |
| `root_ca_crl.der` | 294 | `c114be5d5ca7aab2d37817eca55aa8a2353853809904ff3695b31c26bcb7465b` |
| `tcb_info.json` | 9346 | `b06def97eb7496c03ddf5bf337655bd5f9b57e5422d8a8bd839f80ff0465f185` |
| `tcb_info_issuer_chain.pem` | 1892 | `c550544e4442d9be583a5eddd48df8ba0149ddeef40efd3737ebe0f885dc3711` |

Expected verification result: PCK TCB components `7 9 3 3 255 255 1 0…`, PCE SVN 13.
That matches the TCB level with tcbDate 2022-08-10, which is `OutOfDate`. QE ISVSVN ≥ 8
is `UpToDate`, so the converged status is `OutOfDate`, with TCB evaluation data number 20.
`intel_sgx_root_ca.der` is byte-identical to the PEM Intel publishes at
`certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem`
and to `crates/sgx-ra-verifier/src/intel_sgx_root_ca.der`.

## `live/`: the public executor's quote and its collateral

`quote.dat` is a quote `sgx-playground.blechschmidt.io:443` sent on
2026-11-23 (echo enclave, MRENCLAVE
`bdd7e7862557e60ed2db5c01aa6bc46f6ede0483209fa39680caf7b889a09263`; the
report_data binds that session's ephemeral channel key). The PCK leaf
(Platform CA) is for FMSPC `00606a000000` (Xeon Platinum 8369B, Ice Lake SP,
Alibaba Cloud KVM guest). The collateral was recorded from Intel PCS v4
(no API key) on 2026-11-23 23:10 UTC, the same way as `dcap/`. Tests verify at
2026-11-24T00:00:00Z. The first item to expire is the PCK CRL, at
2026-12-23T22:33:45Z.

| File | Size | SHA-256 |
|------|------|---------|
| `pck_crl_platform.der` | 3354 | `6f09536f4cdde7c724557870aa08abff0e5985ffeed7173855086988e03df2b0` |
| `qe_identity.json` | 1380 | `c8fbe85d41866f9fca29821214c99d2dbcf5eb81fed0c3e07201d92cd4a85ee9` |
| `qe_identity_issuer_chain.pem` | 1892 | `c550544e4442d9be583a5eddd48df8ba0149ddeef40efd3737ebe0f885dc3711` |
| `quote.dat` | 4734 | `bf4a1d71245ee93aa07f5b49d5a7016825bf780a15e946b4db08e06a0cf4d48e` |
| `root_ca_crl.der` | 294 | `c114be5d5ca7aab2d37817eca55aa8a2353853809904ff3695b31c26bcb7465b` |
| `tcb_info.json` | 9346 | `4c6715edd4f8039ace161369fb8adaaf43ff27f47056d2a7f08103f13adb0412` |
| `tcb_info_issuer_chain.pem` | 1892 | `c550544e4442d9be583a5eddd48df8ba0149ddeef40efd3737ebe0f885dc3711` |

Expected verification result: PCK TCB components `14 14 3 3 255 255 0 0…`,
PCE SVN 13, matching the 2024-03-13 level `OutOfDateConfigurationNeeded`
(TCB evaluation data number 20). The QE is `UpToDate`. Advisories:
INTEL-SA-00615, -00657, -00767, -01079, -01103, -01153. The best level for this
FMSPC is `SWHardeningNeeded` (2025-08-13).

# Platform TCB status of the public executor

The public executor `sgx-playground.blechschmidt.io:443` attests with platform
TCB status **`OutOfDateConfigurationNeeded`**. This page explains where that
status comes from, why nothing in this repository or on the executor VM can
change it, and what the operator of the physical machine has to do.

Findings from 2026-11-24, Intel TCB evaluation data number 20 (standard) and 22
(early).

## Where the status comes from

The TCB status isn't something the enclave or the host app reports. The
verifier derives it from two Intel-signed inputs:

1. The **PCK certificate** in the quote. Intel's PCS issues it for the
   platform's raw TCB (CPUSVN, PCE SVN), and it certifies the 16 SGX TCB
   component SVNs and the PCE SVN of the platform.
2. The **TCB Info** for the platform's FMSPC, which lists TCB levels (minimum
   SVNs, highest first) and Intel's status for each. The verifier takes the
   first level whose minimums the certified SVNs all meet
   (`TcbInfo::level_for`).

The live executor (Alibaba Cloud `ecs.c7t.large`, Intel Xeon Platinum 8369B,
Ice Lake SP, FMSPC `00606a000000`):

| | Value |
|---|---|
| Raw CPUSVN in the enclave report | `0e0f100fffff00000000000000000000` |
| TCB components certified by the PCK certificate | `14 14 3 3 255 255 0 0 …`, PCE SVN 13 |
| Matched TCB level | `[14, 14, 3, 3, 255, 255, 0]`, 2024-03-13, `OutOfDateConfigurationNeeded` |
| QE identity | ISVSVN ≥ 8, `UpToDate` |
| Advisories | INTEL-SA-00657, -00767, -01079, -01103, -01153, -00615 |

The top of Intel's TCB Info for this FMSPC (standard update):

| SGX TCB components | TCB date | Status |
|---|---|---|
| `15 16 3 3 255 255 1` | 2025-08-13 | `SWHardeningNeeded` |
| `15 16 3 3 255 255 0` | 2025-08-13 | `ConfigurationAndSWHardeningNeeded` |
| `15 15 3 3 255 255 1` | 2024-11-13 | `OutOfDate` |
| `15 15 3 3 255 255 0` | 2024-11-13 | `OutOfDateConfigurationNeeded` |
| `14 14 3 3 255 255 1` | 2024-03-13 | `OutOfDate` |
| **`14 14 3 3 255 255 0`** | **2024-03-13** | **`OutOfDateConfigurationNeeded`** ← executor |

The "early" TCB Info (evaluation data number 22) adds a 2026-08-12 level
(`15 17 …`) and leaves the executor at the same level and status.

Two points follow from this table:

* **"OutOfDate"** comes from the microcode SVNs. Component 0 (BIOS, Early
  Microcode Update) is 14, but at least 15 is needed. Component 1 (OS/VMM,
  SGX Late Microcode Update) is certified at 14, but 16 is needed.
* **"ConfigurationNeeded"** comes from component 6. Intel gives it no label,
  and every pair of levels splits on it (1 vs 0). The `…0` level always adds
  INTEL-SA-00657 and INTEL-SA-00767 to the advisories. So component 6 is
  most likely the configuration Intel's guidance for those two advisories
  asks for on 3rd-gen Xeon SP: x2APIC mode locked (ÆPIC Leak,
  CVE-2022-21233) and SGX error injection disabled (CVE-2022-41804). Both
  are set in the BIOS.

**`UpToDate` is not reachable on this platform type at all.** The best level
Intel defines for FMSPC `00606a000000` is `SWHardeningNeeded`, because of
INTEL-SA-00615 (MMIO stale data), which applies to every Ice Lake SP. So
`--strict-tcb` (`UpToDate` only) rejects every Ice Lake SP server, however well
it is patched.

## Why it can't be fixed from the executor or this repository

Every SVN that is short is set by the **physical host**. The executor is a KVM
guest (`systemd-detect-virt` → `kvm`, DMI "Alibaba Cloud ECS"):

* The BIOS loads the early microcode (component 0) and sets the configuration
  (component 6) when the physical server boots. A guest has no BIOS of its own
  that SGX attests.
* The OS/VMM loads late microcode (component 1), and here that means the
  hypervisor's OS. KVM hides the real microcode from the guest, which sees
  `microcode : 0x1` in `/proc/cpuinfo`, and a guest can't load microcode.
  Installing `intel-microcode` in the guest (it is installed, version
  3.20260210) has no effect.
* CPUSVN is computed by the CPU. The PCK certificate and the TCB Info are
  signed by Intel. A PCCS, a different collateral source or a verifier option
  can't make the platform look better. They can only make the verifier
  accept it, which `echo-client` does by default through explicit
  allowlists (below).
* The enclave, the host app and the Nix build don't feed into the TCB status.
  MRENCLAVE stays the same whatever the status is.

A rebuild, a redeploy of the container, a PCCS or a different client policy
therefore can't move the executor to a better level. The changes have to
happen on the physical host.

## What fixes it

In order of effect:

1. **The cloud provider updates the physical host's BIOS and microcode** to
   at least the 2025-08-13 TCB recovery (component 0 ≥ 15, component 1 ≥ 16;
   the early TCB Info already asks for 17), **and applies the BIOS
   configuration** for INTEL-SA-00657 and INTEL-SA-00767. The platform then moves to `SWHardeningNeeded`,
   which is the best this CPU can reach. Request it from Alibaba Cloud support
   for instance `i-k1a0k8f34bzqns3p03x5` (region `ap-southeast-5`), or ask to
   be migrated to an SGX host that already has it.
2. **Move the executor to an SGX host that is already patched.** Stopping and
   starting an ECS instance (or redeploying it) may place it on a different
   physical server. Another SGX instance family or region works too, and so
   does a bare-metal SGX server you manage yourself. The quote shows the
   result straight away. After the move, run `echo-client` once and check
   that the gap lines described below are gone. Recompute MRENCLAVE as
   usual; it doesn't change.
3. On your own hardware: update the BIOS (and with it the early microcode),
   and apply the BIOS settings the vendor's guidance for INTEL-SA-00657 and
   INTEL-SA-00767 names (x2APIC mode, error injection off). Then reboot and
   let the host OS load the current `intel-microcode` package.

None of these steps can be done from inside the executor VM. They need the
cloud provider (or credentials for its console/API, which this project
doesn't have).

## How the client handles it

`echo-client` names the exact gap after each attestation. For the live
executor:

```text
[OK] Platform TCB status OutOfDateConfigurationNeeded (platform OutOfDateConfigurationNeeded, TCB date 2024-03-13T00:00:00Z); allowed by policy
     Intel security advisories: INTEL-SA-00657, INTEL-SA-00767, INTEL-SA-01079, INTEL-SA-01103, INTEL-SA-01153, INTEL-SA-00615 (all on the advisory allowlist)
     The best TCB level Intel defines for this platform type is SWHardeningNeeded (TCB date 2025-08-13T00:00:00Z); this platform falls short of it:
       component 0 (BIOS, Early Microcode Update) is 14 < 15: update the BIOS / microcode of the physical host
       component 1 (OS/VMM, SGX Late Microcode Update) is 14 < 16: load newer microcode in the host OS / VMM, or update the BIOS
       component 6 is 0 < 1: update or reconfigure the BIOS of the physical host
```

Other applications get the same diagnosis from the verifier crate:
`VerifiedQuote::platform_tcb_gap` (a `TcbGap` holding the best level and one
`TcbShortfall` per short SVN, each with `remedy()`), or
`TcbInfo::gap_to_best`.

The policy stays a decision for the relying party
([THREAT_MODEL.md §4.7](THREAT_MODEL.md#47-tcb-status-policy-defaults--ok)).
`echo-client` accepts a non-`UpToDate` platform only if **both** hold
(deny by default):

1. its TCB status is on the status allowlist. Default
   (`sgx_ra_verifier::tcb::ICE_LAKE_SP_TCB_STATUSES`): `SWHardeningNeeded`,
   `ConfigurationAndSWHardeningNeeded`, `OutOfDate`,
   `OutOfDateConfigurationNeeded`. These are the statuses of the
   levels from 2024-03-13 up in the table above. `ConfigurationNeeded` is
   not on it, and `Revoked` never can be.
2. every Intel advisory it is affected by is on the advisory allowlist.
   Default (`sgx_ra_verifier::tcb::ICE_LAKE_SP_ADVISORIES`):

   | Advisory | Why it applies here | Fixed by |
   |---|---|---|
   | INTEL-SA-00615 | MMIO stale data; every Ice Lake SP | nothing (software hardening) |
   | INTEL-SA-00657 | ÆPIC Leak | BIOS configuration (component 6) |
   | INTEL-SA-00767 | SGX error injection | BIOS configuration (component 6) |
   | INTEL-SA-01079, INTEL-SA-01103 | microcode | 2024-11-13 TCB recovery |
   | INTEL-SA-01153 | microcode | 2025-08-13 TCB recovery |

   A platform with any other advisory is rejected:
   `[FAIL] Policy rejected the enclave: platform (TCB status …) is affected
   by INTEL-SA-…, which is not on the advisory allowlist`. Every level
   older than 2024-03-13 carries INTEL-SA-00960, so those are rejected,
   and so is any advisory Intel adds to this FMSPC later, until someone
   reviews it and allowlists it.

The lists are checked against the recorded TCB Info and live quote in
`fixtures/live/` (`cargo test -p sgx-ra-verifier live`). Library users
get the same behaviour with
`EnclavePolicy::allow_tcb_status(…)` and `.allow_advisories(…)`
(`PolicyViolation::AdvisoryNotAllowed`).

| Flag | Accepts |
|---|---|
| *(default)* | `UpToDate`, plus the allowlisted statuses if all advisories are allowlisted; a warning with the gap above |
| `--allow-tcb-status S` (repeatable) | `UpToDate` plus the listed statuses (replaces the status allowlist; advisories still checked) |
| `--allow-tcb-status SWHardeningNeeded` | the strictest policy a fully patched Ice Lake SP passes. The live executor fails it until its host is fixed. |
| `--allow-advisory ID` (repeatable) | replaces the advisory allowlist, e.g. `--allow-advisory INTEL-SA-00615` alone admits only a fully patched and configured host |
| `--any-advisory` | no advisory check (statuses only) |
| `--strict-tcb` | `UpToDate` only. No Ice Lake SP platform passes it. |

Accepting `OutOfDateConfigurationNeeded` means trusting that the listed
advisories aren't exploited against this host. They need a privileged
attacker on the physical platform: the cloud provider or someone who has
compromised the hypervisor.

## Follow-up for the platform owner

Moving the executor to a better TCB level needs access this project
doesn't have: the Alibaba Cloud console/API for instance
`i-k1a0k8f34bzqns3p03x5` (to stop/start or redeploy it onto another
physical host) or a support ticket asking for the BIOS/microcode update
and the INTEL-SA-00657/-00767 BIOS configuration. Once it reaches
`SWHardeningNeeded`, tighten the default to
`--allow-tcb-status SWHardeningNeeded --allow-advisory INTEL-SA-00615`.

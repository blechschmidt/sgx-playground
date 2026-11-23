# Reproducing MRENCLAVE bit for bit on another host

Remote attestation is only as good as the measurement the client compares
against. In this framework, a client does not accept a published
MRENCLAVE on faith. It rebuilds the enclave from source and pins the
MRENCLAVE of its own build. This works only if any machine that builds
the same source gets the same bytes. This document shows how to check that,
and what to do when two builds differ.

## What is reproduced

`nix build .#enclave` (or the container `containers/Dockerfile.nix-build`)
produces six files. Every one of them is bit-for-bit reproducible:

| File | Depends on | Used for |
|---|---|---|
| `enclave.so` | the source tree and every pinned input | input to signing |
| `enclave.so.gendata` | `enclave.so`, `Enclave.config.xml` | **MRENCLAVE**: the client reads it from here |
| `enclave.signed.so` | the above + the published signing key + the fixed date | what the host loads |
| `MRENCLAVE.txt`, `MRSIGNER.txt` | the above | human-readable copies |
| `SHA256SUMS` | all of the above | quick comparison between builders |

MRENCLAVE is a hash over the enclave's measured pages and layout. It does
not depend on who signed the enclave. Two builders who get the same
`enclave.so.gendata` agree on MRENCLAVE, even if one of them re-signs the
image with their own key.

## Steps

You need Docker (or Podman) and about 6 GB of disk. Nothing else is taken
from the build host: the compiler, the SGX SDK and every library come
from inputs pinned by hash.

1. **Get the exact source.** Check out the same commit. Only these paths
   enter the build (the flake's `src` fileset plus `flake.nix`,
   `flake.lock` and `nix/`): `Cargo.toml`, `Cargo.lock`,
   `rust-toolchain.toml`, `.cargo/config.toml`, `crates/`, `examples/`,
   `enclave-sys/`. Changes to documentation, scripts, `target/` or the
   blueprint checkout do not affect the result.

2. **Build in the pinned container.**

   ```sh
   scripts/nix-build-enclave.sh                 # -> target/nix-enclave/enclave/
   cat target/nix-enclave/enclave/MRENCLAVE.txt
   cat target/nix-enclave/enclave/SHA256SUMS
   ```

   The script runs `docker build -f containers/Dockerfile.nix-build`. It
   works with the classic builder and with BuildKit. The base image is
   pinned by digest (`nixos/nix:2.36.0@sha256:74628055…`).

3. **Compare.** MRENCLAVE must equal the value in the
   [README table](../README.md#measurements-of-the-echo-enclave). CI fails
   if the table does not match its own build. To compare with another
   builder, compare `SHA256SUMS`: all five hashes must match.

4. **Check that the build is deterministic on your machine.**

   ```sh
   scripts/nix-build-enclave.sh --verify
   ```

   This runs two `--no-cache` builds. The second copies the sources to a
   different directory inside the container (`SRC_DIR`). The script then
   compares all artifacts byte for byte. CI runs the same check.

5. **Compare with the remote enclave.** Pass the build output to the client:

   ```sh
   target/release/echo-client --insecure-tls \
     --gendata-path target/nix-enclave/enclave/enclave.so.gendata
   ```

   Without `--gendata-path`, the client runs the build itself
   ([QUICKSTART.md](QUICKSTART.md)). To check a saved quote offline:
   `echo-client inspect-quote quote.dat --expect-gendata enclave.so.gendata`.

### Other ways to build

* **With Nix installed:** `nix build .#enclave` gives the same result
  (`result/`). Inside a git checkout, Nix uses only files that git
  tracks. An untracked file under `crates/` is ignored by `nix build` but
  copied by the container build, so commit or remove it before you
  compare.
* **Without binary caches:** by default the container fetches nixpkgs
  store paths from `cache.nixos.org`. These are addressed by derivation
  hash and checked against the cache's signing key. If you do not want to
  rely on that cache, run
  `docker build -f containers/Dockerfile.nix-build --build-arg NIX_SUBSTITUTE=false .`
  It builds the whole toolchain from source, which takes hours, and
  produces the same bits.
* **Other enclaves:** pass `--enclave <flake attribute>`, e.g.
  `--enclave sealing-enclave`.

## Why it is reproducible

These measures are described in detail in
[ARCHITECTURE.md §6](ARCHITECTURE.md#6-reproducible-build).

| Source of variation | How it is removed |
|---|---|
| Toolchain, SDK, libraries | nixpkgs, crane and fenix are locked in `flake.lock`. Rust 1.100.0 is pinned by the sha256 of its channel manifest. The Intel SGX SDK 2.26 and DCAP 1.23 are pinned by sha256. Crates are vendored by their `Cargo.lock` checksums and built `--offline --locked`. |
| Build host (distribution, installed packages, CPU count) | Everything runs inside the digest-pinned `nixos/nix` image. `codegen-units = 1` and fat LTO make the output independent of parallelism. |
| Paths (checkout directory, `$HOME`, store paths) | `--remap-path-prefix`, `-ffile-prefix-map`, the unwrapped gcc/binutils (no rpaths), `PT_INTERP` set to the FHS path. |
| Time | `SOURCE_DATE_EPOCH=315532800`. `sgx_sign` runs under libfaketime, so the SIGSTRUCT date is always 1980-01-01. |
| Build IDs, debug info | `--build-id=none`, no debuginfo, no incremental compilation, the Nix fixup phase is disabled. |
| Signature | PKCS#1 v1.5 signing is deterministic, and the key is published (`enclave-sys/reproducible-signing-key.pem`). It is a build input, not a secret. Clients pin MRENCLAVE, so the key carries no trust. |

## If your MRENCLAVE differs

1. **Check the inputs.** Compare the commit, `flake.lock`, `Cargo.lock`
   and `rust-toolchain.toml`. A different MRENCLAVE almost always means
   different input trees. Look for uncommitted edits and for line-ending
   conversion (`git config core.autocrlf` must be `false` or `input`).
2. **Find where the builds diverge.** Compare `SHA256SUMS` file by file:
   * `enclave.so` differs: the compiled code differs. Compare the inputs
     again, then run `--verify` on both machines to rule out
     nondeterminism.
   * `enclave.so` is equal but `enclave.so.gendata` differs: the
     enclave configuration (`enclave-sys/Enclave.config.xml`) differs.
   * Only `enclave.signed.so` differs: the signing key or date differs.
     MRENCLAVE is the same, so attestation is not affected.
3. **Inspect the measurement inputs** with
   `echo-client inspect-gendata enclave.so.gendata`. It prints MRENCLAVE,
   ISVPRODID, ISVSVN and the attributes.
4. If `--verify` fails on one machine, the build is nondeterministic.
   Please report it, together with both artifact sets.

## When MRENCLAVE changes on purpose

Any change to the inputs listed in step 1 gives a new MRENCLAVE. That
includes a dependency bump in `Cargo.lock` and a `flake.lock` update. After
such a change:

1. rebuild and update the table in [README.md](../README.md#measurements-of-the-echo-enclave)
   (CI enforces this);
2. have the operator deploy the new `enclave.signed.so`. Clients that pin
   the old value reject the new enclave until they rebuild. During a
   rollout, a client can accept both measurements with a policy that
   tries each one ([NEW_ENCLAVE_APP.md](NEW_ENCLAVE_APP.md#defining-the-policy)).

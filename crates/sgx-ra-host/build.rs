//! Build script of `sgx-ra-host`.
//!
//! Without the `sgx` feature it does nothing. With it, it
//!
//! 1. runs the SDK's `sgx_edger8r --untrusted` on the framework EDL
//!    (`enclave-sys/sealed-storage/Enclave.edl`, override with `SGX_RA_EDL`):
//!    the blueprint ECALLs plus the sealed-storage OCALLs, so one host binary
//!    serves enclaves linked with either EDL (an enclave without OCALLs
//!    never calls them; the ECALL numbering is identical),
//! 2. compiles the generated ECALL bridge `Enclave_u.c` with the `cc` crate,
//! 3. links the untrusted runtime: `libsgx_urts` (`SGX_MODE=HW`, default) or
//!    `libsgx_urts_sim` (`SGX_MODE=SIM`).
//!
//! Environment:
//!
//! | variable | default | meaning |
//! |----------|---------|---------|
//! | `SGX_SDK` | `/opt/intel/sgxsdk` | SDK root (`bin/x64/sgx_edger8r`, `include/`) |
//! | `SGX_MODE` | `HW` | `HW` or `SIM` |
//! | `SGX_URTS_LIB_DIR` | `$SGX_SDK/lib64` | directory with `libsgx_urts.so` / `libsgx_urts_sim.so` |
//! | `SGX_RA_EDL` | `../../enclave-sys/sealed-storage/Enclave.edl` | EDL whose untrusted bridge is built (imports are searched in the SDK and the EDL's parent directory) |
//!
//! `libsgx_dcap_ql` is not linked: the host loads it at runtime (see
//! `src/sgx/dcap.rs`), so a simulation build never pulls the hardware
//! runtime into the process.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rustc-check-cfg=cfg(sgx_ra_sim)");
    #[cfg(feature = "sgx")]
    sgx::build();
}

#[cfg(feature = "sgx")]
mod sgx {
    use std::env;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn var(name: &str) -> Option<String> {
        println!("cargo::rerun-if-env-changed={name}");
        env::var(name).ok().filter(|v| !v.is_empty())
    }

    pub(super) fn build() {
        let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let sdk = PathBuf::from(var("SGX_SDK").unwrap_or_else(|| "/opt/intel/sgxsdk".into()));
        let edl = var("SGX_RA_EDL")
            .map(PathBuf::from)
            .unwrap_or_else(|| manifest_dir.join("../../enclave-sys/sealed-storage/Enclave.edl"));
        let mode = var("SGX_MODE").unwrap_or_else(|| "HW".into());
        let urts = match mode.as_str() {
            "HW" => "sgx_urts",
            "SIM" => {
                println!("cargo::rustc-cfg=sgx_ra_sim");
                "sgx_urts_sim"
            }
            other => panic!("SGX_MODE must be HW or SIM, not {other:?}"),
        };
        let urts_dir = var("SGX_URTS_LIB_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| sdk.join("lib64"));
        println!("cargo::rerun-if-changed={}", edl.display());
        let edl_dir = edl.parent().unwrap().to_owned();
        let edl_parent = edl_dir.parent().unwrap_or(&edl_dir).to_owned();
        // The sealed-storage EDL imports the base EDL from its parent.
        println!(
            "cargo::rerun-if-changed={}",
            edl_parent.join("Enclave.edl").display()
        );

        let include = sdk.join("include");
        let edger8r = sdk.join("bin/x64/sgx_edger8r");
        require(&edger8r, "SGX_SDK");
        require(&include.join("sgx_edger8r.h"), "SGX_SDK");
        require(&edl, "SGX_RA_EDL");

        let gen_dir = out_dir.join("edger8r");
        std::fs::create_dir_all(&gen_dir).unwrap();
        let status = Command::new(&edger8r)
            .arg("--untrusted")
            .arg(&edl)
            .arg("--search-path")
            .arg(&include)
            .arg("--search-path")
            .arg(&edl_parent)
            .arg("--untrusted-dir")
            .arg(&gen_dir)
            .status()
            .unwrap_or_else(|e| panic!("cannot run {}: {e}", edger8r.display()));
        assert!(status.success(), "sgx_edger8r failed: {status}");

        let stem = edl.file_stem().unwrap().to_str().unwrap();
        let bridge = gen_dir.join(format!("{stem}_u.c"));
        require(&bridge, "sgx_edger8r output");
        cc::Build::new()
            .file(&bridge)
            .include(&include)
            .include(&gen_dir)
            .warnings(false)
            // Keep build paths out of the object so the host binary is
            // reproducible as well.
            .flag_if_supported(format!("-ffile-prefix-map={}=/edger8r", gen_dir.display()))
            .flag_if_supported(format!("-ffile-prefix-map={}=/sgxsdk", sdk.display()))
            .compile("sgx_ra_enclave_u");

        println!("cargo::rustc-link-search=native={}", urts_dir.display());
        println!("cargo::rustc-link-lib=dylib={urts}");
    }

    fn require(path: &Path, source: &str) {
        assert!(
            path.exists(),
            "{} does not exist (check {source}; the `sgx` feature needs the Intel SGX SDK)",
            path.display()
        );
    }
}

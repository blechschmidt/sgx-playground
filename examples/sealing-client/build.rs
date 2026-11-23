//! Emits `cfg(sgx_hw)` when this machine exposes SGX (`/dev/sgx_enclave`),
//! so the hardware tests are `#[ignore]`d exactly when it is absent.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(sgx_hw)");
    println!("cargo::rerun-if-env-changed=SGX_RA_FORCE_HW_TESTS");
    if std::path::Path::new("/dev/sgx_enclave").exists()
        || std::env::var_os("SGX_RA_FORCE_HW_TESTS").is_some()
    {
        println!("cargo::rustc-cfg=sgx_hw");
    }
}

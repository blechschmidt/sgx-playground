//! The real SGX backend (cargo feature `sgx`).
//!
//! * [`SgxEnclave`]: `sgx_create_enclave` from `libsgx_urts` plus the
//!   edger8r-generated ECALL bridge `Enclave_u.c` (compiled by `build.rs`).
//! * [`DcapQuoter`]: `libsgx_dcap_ql`, loaded at runtime, in-process mode
//!   (QE3, PCE and ID enclave loaded into this process), like `App.cpp`.
//! * The storage OCALLs of `enclave-sys/sealed-storage/Enclave.edl`,
//!   backed by [`crate::sealed_store`] (`--sealed-dir`).
//!
//! `build.rs` links `libsgx_urts_sim` instead of `libsgx_urts` when built
//! with `SGX_MODE=SIM`; [`SIMULATION`] tells which one this binary uses.

mod dcap;
mod enclave;
mod ffi;
mod ocalls;

pub use dcap::{DcapConfig, DcapQuoter};
pub use enclave::SgxEnclave;

/// Whether this build links the SGX *simulation* runtime. Simulation
/// enclaves have no hardware protection and cannot be quoted.
pub const SIMULATION: bool = cfg!(sgx_ra_sim);

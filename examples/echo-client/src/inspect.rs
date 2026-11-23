//! Offline inspection of SGX artefacts. Parses structure only; it does
//! **not** verify signatures, so its output must not be used to trust an
//! enclave.

use std::fs;
use std::path::Path;
use std::process::ExitCode;

use sgx_ra_client::sgx_ra_core::hex::Hex;
use sgx_ra_client::sgx_ra_core::sgx::{Gendata, Quote, Sigstruct};
use sgx_ra_client::sgx_ra_verifier::parse_and_check_structure;
use sgx_ra_client::{GendataFile, MeasurementSource};

use crate::args::InspectQuoteArgs;
use crate::exit;

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn finish(result: Result<ExitCode, String>) -> ExitCode {
    result.unwrap_or_else(|message| {
        eprintln!("error: {message}");
        ExitCode::from(exit::FAILURE)
    })
}

/// `inspect-quote`.
pub fn quote(args: &InspectQuoteArgs) -> ExitCode {
    finish(quote_inner(args))
}

fn quote_inner(args: &InspectQuoteArgs) -> Result<ExitCode, String> {
    let expected = match (&args.expect_mrenclave, &args.expect_gendata) {
        (Some(m), _) => Some(*m),
        (None, Some(path)) => Some(
            GendataFile::new(path)
                .mr_enclave()
                .map_err(|e| e.to_string())?,
        ),
        (None, None) => None,
    };
    let path = &args.path;
    let raw = read(path)?;
    let quote = Quote::parse(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
    let h = quote.header();
    let body = quote.report_body();
    let attrs = body.attributes();
    let sig = quote.signature();
    println!("quote             {} ({} bytes)", path.display(), raw.len());
    println!("version           {}", h.version);
    println!("qe_svn / pce_svn  {} / {}", h.qe_svn, h.pce_svn);
    println!("qe_vendor_id      {}", Hex(&h.qe_vendor_id));
    println!("mr_enclave        {}", body.mr_enclave());
    println!("mr_signer         {}", body.mr_signer());
    println!("isv_prod_id       {}", body.isv_prod_id());
    println!("isv_svn           {}", body.isv_svn());
    println!(
        "attributes        flags={:#x} xfrm={:#x} debug={} mode64={}",
        attrs.flags,
        attrs.xfrm,
        attrs.is_debug(),
        attrs.is_mode64bit()
    );
    println!("report_data       {}", Hex(body.report_data().as_bytes()));
    println!(
        "certification     type {} ({} bytes)",
        sig.certification.cert_type,
        sig.certification.data.len()
    );
    match parse_and_check_structure(&raw) {
        Ok(_) => println!("structure         ok"),
        Err(e) => println!("structure         REJECTED: {e}"),
    }
    println!("signatures        NOT VERIFIED (inspection only)");

    let Some(expected) = expected else {
        return Ok(ExitCode::SUCCESS);
    };
    if body.mr_enclave() == expected {
        println!("mr_enclave check  matches {expected}");
        Ok(ExitCode::SUCCESS)
    } else {
        println!("mr_enclave check  MISMATCH: expected {expected}");
        Ok(ExitCode::from(exit::FAILURE))
    }
}

/// `inspect-gendata`.
pub fn gendata(path: &Path) -> ExitCode {
    finish((|| {
        let raw = read(path)?;
        let g = Gendata::parse(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
        println!("gendata           {}", path.display());
        print_sigstruct_fields(&g);
        Ok(ExitCode::SUCCESS)
    })())
}

/// `inspect-sigstruct`.
pub fn sigstruct(path: &Path) -> ExitCode {
    finish((|| {
        let raw = read(path)?;
        let s = Sigstruct::parse(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
        println!("sigstruct         {}", path.display());
        print_sigstruct_fields(&s.gendata());
        println!("mr_signer         {}", s.mr_signer());
        println!("rsa exponent      {}", s.exponent());
        println!("signature         NOT VERIFIED (inspection only)");
        Ok(ExitCode::SUCCESS)
    })())
}

fn print_sigstruct_fields(g: &Gendata) {
    match g.header.date_ymd() {
        Some((y, m, d)) => println!("date              {y:04}-{m:02}-{d:02}"),
        None => println!("date              {:#x} (not BCD)", g.header.date),
    }
    println!("mr_enclave        {}", g.mr_enclave());
    println!("isv_prod_id       {}", g.body.isv_prod_id);
    println!("isv_svn           {}", g.body.isv_svn);
    println!(
        "attributes        flags={:#x}/{:#x} xfrm={:#x}/{:#x}",
        g.body.attributes.flags,
        g.body.attribute_mask.flags,
        g.body.attributes.xfrm,
        g.body.attribute_mask.xfrm
    );
    println!(
        "debug launch      {}",
        if g.body.allows_debug_launch() {
            "allowed (DisableDebug=0)"
        } else {
            "disabled"
        }
    );
}

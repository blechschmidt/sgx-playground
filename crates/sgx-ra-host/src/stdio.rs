//! stdin/stdout as the wire, for the operator's `stunnel` `exec`
//! (`docs/PROTOCOL.md` §1).
//!
//! The blueprint host shares stdout between the protocol and diagnostics
//! (the DCAP logger, `printf`), which corrupts the stream (quirks Q5/Q6).
//! [`claim`] fixes that for the whole process: it duplicates the original
//! stdout into a private descriptor that only the protocol writes to, and
//! points fd 1 at stderr. Whatever the SGX/DCAP libraries print afterwards
//! ends up in the log, never on the wire.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

/// The protocol's private ends of the original stdin and stdout.
#[derive(Debug)]
pub struct StdioWire {
    /// Reads the client's bytes (a duplicate of the original fd 0).
    pub reader: File,
    /// Writes to the client (a duplicate of the original fd 1).
    pub writer: File,
}

/// Takes over stdin/stdout for the protocol and redirects fd 1 to stderr.
///
/// Call it once, before loading any SGX library.
pub fn claim() -> io::Result<StdioWire> {
    let reader = dup_of(&io::stdin())?;
    let writer = dup_of(&io::stdout())?;
    redirect_stdout_to_stderr()?;
    Ok(StdioWire {
        reader: File::from(reader),
        writer: File::from(writer),
    })
}

fn dup_of<T: AsFd>(stream: &T) -> io::Result<OwnedFd> {
    stream.as_fd().try_clone_to_owned()
}

#[allow(unsafe_code)]
fn redirect_stdout_to_stderr() -> io::Result<()> {
    unsafe extern "C" {
        fn dup2(oldfd: i32, newfd: i32) -> i32;
    }
    let stderr = io::stderr().as_fd().as_raw_fd();
    let stdout = io::stdout().as_fd().as_raw_fd();
    // SAFETY: dup2 only manipulates the process's descriptor table. Both
    // descriptors are open (stderr is borrowed from std for the call), and
    // replacing fd 1 does not invalidate any Rust-owned descriptor: the
    // wire uses its own duplicate, and `std::io::stdout` keeps writing to
    // fd 1, which now refers to stderr.
    if unsafe { dup2(stderr, stdout) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

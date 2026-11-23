//! Diagnostics. Everything goes to stderr: stdout is the wire
//! (`docs/PROTOCOL.md` quirks Q5/Q6). Messages never contain payload bytes.

use std::sync::atomic::{AtomicBool, Ordering};

static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Enables per-request diagnostics (sizes and statuses only, never content).
pub fn set_verbose(verbose: bool) {
    VERBOSE.store(verbose, Ordering::Relaxed);
}

pub(crate) fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Logs a line to stderr with the `[host]` prefix.
macro_rules! info {
    ($($arg:tt)*) => {
        ::std::eprintln!("[host] {}", ::std::format_args!($($arg)*))
    };
}

/// Like `info!`, but only with `set_verbose(true)`.
macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::log::verbose() {
            $crate::log::info!($($arg)*);
        }
    };
}

pub(crate) use {debug, info};

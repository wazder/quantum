//! Win32 base API surface (kernel32 equivalent).
//!
//! Functions here are the *guest-visible* entry points. The JIT writes
//! their addresses into IAT slots so JIT'd guest code calls them via
//! ordinary BLR. Each function uses `extern "C-unwind"` so a
//! `ProcessExit` panic raised from `ExitProcess` can propagate cleanly
//! through the JIT call boundary back to the runner.

pub mod io;
pub mod process;
pub mod thunks;

pub use process::{ExitProcess, ProcessExit};
pub use thunks::resolve;

//! Win32 base API surface (kernel32 equivalent).
//!
//! Functions here are the *guest-visible* entry points. The JIT writes
//! their addresses into IAT slots so JIT'd guest code calls them via
//! ordinary BLR. Each function uses `extern "C-unwind"` so a
//! `ProcessExit` panic raised from `ExitProcess` can propagate cleanly
//! through the JIT call boundary back to the runner.

pub mod heap;
pub mod io;
pub mod process;
pub mod thunks;
pub mod time;
pub mod vm;

pub use heap::{GetProcessHeap, HeapAlloc, HeapFree};
pub use process::{ExitProcess, ProcessExit};
pub use thunks::resolve;
pub use time::{
    GetCurrentProcessId, GetCurrentThreadId, GetSystemTimeAsFileTime, GetTickCount, GetTickCount64,
    QueryPerformanceCounter, QueryPerformanceFrequency, Sleep,
};
pub use vm::{VirtualAlloc, VirtualFree, VirtualProtect};

//! Win32 base API surface (kernel32 equivalent).
//!
//! Functions here are the *guest-visible* entry points. The JIT writes
//! their addresses into IAT slots so JIT'd guest code calls them via
//! ordinary BLR. Each function uses `extern "C-unwind"` so a
//! `ProcessExit` panic raised from `ExitProcess` can propagate cleanly
//! through the JIT call boundary back to the runner.

pub mod advapi32;
pub mod cocoa;
pub mod d3d11;
pub mod dxbc;
pub mod file_io;
pub mod gdi32;
pub mod handles;
pub mod heap;
pub mod io;
pub mod misc_win;
pub mod modules;
pub mod process;
pub mod seh;
pub mod steam;
pub mod stubs;
pub mod sync;
pub mod threads;
pub mod thunks;
pub mod time;
pub mod user32;
pub mod vm;
pub mod windows_state;
pub mod winmm;
pub mod ws2_32;

pub use heap::{GetProcessHeap, HeapAlloc, HeapFree};
pub use process::{ExitProcess, ProcessExit};
pub use thunks::resolve;
pub use time::{
    GetCurrentProcessId, GetCurrentThreadId, GetSystemTimeAsFileTime, GetTickCount, GetTickCount64,
    QueryPerformanceCounter, QueryPerformanceFrequency, Sleep,
};
pub use vm::{VirtualAlloc, VirtualFree, VirtualProtect};

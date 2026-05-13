//! Host (Darwin) abstraction layer.
//!
//! Every Win32 / NT surface in `quantum-ntdll` and `quantum-kernel32` calls
//! into this crate to talk to the kernel — never `libc` or `std::fs` directly.
//! Centralising this lets us swap the syscall path (e.g. raw `svc #0x80`) and
//! enforce the from-scratch principle.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod codecache;
pub mod dispatcher;
pub mod fd;
pub mod guest_stack;
pub mod mem;
pub mod sys;
pub mod thread;

pub use codecache::CodeCache;
pub use dispatcher::{
    Dispatcher, GuestContext, STOP_SENTINEL, invoke_block, invoke_block_with_ctx,
};
pub use fd::{HostFd, OpenFlags, StdStream};
pub use guest_stack::{DEFAULT_GUEST_STACK_SIZE, GuestStack};
pub use mem::{MachVmManager, MemoryManager, Protection, Region};

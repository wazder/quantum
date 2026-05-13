//! Process-control thunks.
//!
//! `ExitProcess` never returns to the guest. On real Windows it
//! terminates the process; in Quantum we keep the calling process alive
//! (so tests can observe the exit code) by `longjmp`-ing back to an
//! `ExitTrap` previously installed by the runner. `longjmp` rather than
//! `panic` because the JIT'd code in between has no DWARF unwind info
//! and the system unwinder would abort.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};

/// `jmp_buf` is platform-dependent. Apple arm64-darwin keeps it small
/// (under 200 bytes), but we oversize ours to 512 so we don't have to
/// chase upstream layout changes. The host is guaranteed not to read
/// past the bytes `setjmp` wrote.
#[repr(C, align(16))]
pub struct JmpBuf(UnsafeCell<[u8; 512]>);

unsafe impl Sync for JmpBuf {}

impl JmpBuf {
    pub const fn new() -> Self {
        Self(UnsafeCell::new([0; 512]))
    }

    /// Raw pointer for `setjmp`/`longjmp` FFI.
    pub fn as_ptr(&self) -> *mut core::ffi::c_void {
        self.0.get().cast()
    }
}

impl Default for JmpBuf {
    fn default() -> Self {
        Self::new()
    }
}

unsafe extern "C" {
    /// Returns 0 on direct call, non-zero when reached via `longjmp`.
    pub safe fn setjmp(env: *mut core::ffi::c_void) -> i32;

    /// Never returns; control resumes at the matching `setjmp` with the
    /// return value `val` (mapped to 1 if `val == 0`).
    pub safe fn longjmp(env: *mut core::ffi::c_void, val: i32) -> !;
}

/// Single-process global ExitProcess sink.
///
/// Tests install the `ExitTrap` once before invoking JIT'd code. When
/// `ExitProcess` is called from JIT, it writes the exit code into
/// `EXIT_CODE` and longjmps back through `EXIT_ENV`.
pub static EXIT_ENV: JmpBuf = JmpBuf::new();
pub static EXIT_CODE: AtomicU32 = AtomicU32::new(0);
/// Set to 1 once `arm_exit_trap` has called `setjmp`. A guest that
/// calls ExitProcess without an armed trap is treated as a hard abort.
pub static EXIT_ARMED: AtomicU32 = AtomicU32::new(0);

/// Payload type kept around for compatibility — callers can ignore it.
#[derive(Debug, Clone, Copy)]
pub struct ProcessExit {
    pub code: u32,
}

/// `VOID ExitProcess(UINT uExitCode)`.
///
/// Marshalled at the JIT boundary so the value of `uExitCode` (Win64
/// RCX) arrives in `x0` (AAPCS64 arg0). See
/// `quantum-jit::lifter::lift_call_indirect`.
#[unsafe(no_mangle)]
pub extern "C" fn ExitProcess(exit_code: u32) -> ! {
    EXIT_CODE.store(exit_code, Ordering::SeqCst);
    if EXIT_ARMED.load(Ordering::SeqCst) != 0 {
        longjmp(EXIT_ENV.as_ptr(), 1);
    }
    // No trap armed — the only sensible thing is to terminate.
    std::process::exit(exit_code as i32);
}

/// Arm the ExitProcess trap. Returns 0 on the direct call (caller
/// should now invoke the JIT'd guest), or the saved exit code when
/// reached via the longjmp from `ExitProcess`.
///
/// # Safety
/// The closure must not invoke C++ destructors that depend on stack
/// unwinding; longjmp skips them. Rust drop is also skipped along the
/// short-circuited path.
pub fn run_with_exit_trap<F: FnOnce()>(body: F) -> u32 {
    EXIT_CODE.store(0, Ordering::SeqCst);
    EXIT_ARMED.store(1, Ordering::SeqCst);
    let rc = setjmp(EXIT_ENV.as_ptr());
    if rc == 0 {
        body();
        EXIT_ARMED.store(0, Ordering::SeqCst);
        // Guest returned without calling ExitProcess: signal that to the
        // caller via a sentinel exit code distinct from anything a guest
        // is plausibly going to set.
        u32::MAX
    } else {
        EXIT_ARMED.store(0, Ordering::SeqCst);
        EXIT_CODE.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setjmp_longjmp_roundtrip() {
        let env = JmpBuf::new();
        let p = env.as_ptr();
        let r = setjmp(p);
        if r == 0 {
            longjmp(p, 7);
        }
        assert_eq!(r, 7);
    }

    #[test]
    fn run_with_exit_trap_catches_exit_code() {
        let code = run_with_exit_trap(|| {
            ExitProcess(99);
        });
        assert_eq!(code, 99);
    }
}

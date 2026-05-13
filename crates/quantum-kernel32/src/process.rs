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
    install_crash_handler();
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

// ---------- Crash handler ----------
//
// Install a SIGSEGV/SIGBUS/SIGTRAP handler that reports the host PC and
// fault address, then exits with a sentinel code. This makes JIT bugs
// (mis-encoded address arithmetic, bad guest-RIP routing) diagnosable
// instead of opaque "Segmentation fault" lines from the shell.

use core::sync::atomic::AtomicBool;
use std::sync::Mutex;

static CRASH_INSTALLED: AtomicBool = AtomicBool::new(false);
/// Captured at signal time. Read after the longjmp so we can format the
/// diagnostic without touching stdio from inside the handler.
static CRASH_INFO: Mutex<Option<CrashInfo>> = Mutex::new(None);

#[derive(Debug, Clone, Copy)]
pub struct CrashInfo {
    pub sig: i32,
    pub fault_addr: u64,
    pub host_pc: u64,
}

#[repr(C)]
struct DarwinSigInfo {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    si_pid: i32,
    si_uid: u32,
    si_status: i32,
    si_addr: *mut core::ffi::c_void,
    // Rest of the struct doesn't concern us.
}

#[repr(C)]
struct DarwinSigAction {
    /// Union: function pointer (either `sa_handler` or `sa_sigaction`).
    sa_handler: usize,
    sa_mask: u32,
    sa_flags: i32,
}

const SA_SIGINFO: i32 = 0x0040;
const SIGSEGV: i32 = 11;
const SIGBUS: i32 = 10;
const SIGTRAP: i32 = 5;
const SIGILL: i32 = 4;

unsafe extern "C" {
    fn sigaction(
        sig: i32,
        act: *const DarwinSigAction,
        oldact: *mut DarwinSigAction,
    ) -> i32;
    fn _exit(status: i32) -> !;
}

/// Pull the saved PC out of the ucontext passed to the signal handler.
/// Layout follows Darwin arm64 `<mach/arm/_structs.h>`:
///   ucontext_t.uc_mcontext is a pointer to mcontext64
///   mcontext64 = { __es (16B), __ss (arm_thread_state64_t), __ns (...) }
///   __ss.__pc is at offset 32 within __ss after __x[29] (29*8 = 232)
///     + __fp (8) + __lr (8) + __sp (8), so __pc offset within __ss is 256.
///   __ss starts at offset 16 within mcontext64.
unsafe fn pc_from_ucontext(ucontext: *mut core::ffi::c_void) -> u64 {
    if ucontext.is_null() {
        return 0;
    }
    // SAFETY: caller passes a valid Darwin ucontext_t pointer from
    // sigaction; layout is documented in <mach/arm/_structs.h>.
    unsafe {
        let mcontext_ptr_off: usize = 48;
        let mcontext_pp = (ucontext as *const u8).add(mcontext_ptr_off) as *const *mut u8;
        let mcontext = *mcontext_pp;
        if mcontext.is_null() {
            return 0;
        }
        let pc_ptr = mcontext.add(16 + 256) as *const u64;
        *pc_ptr
    }
}

extern "C" fn crash_handler(
    sig: i32,
    info: *mut DarwinSigInfo,
    ucontext: *mut core::ffi::c_void,
) {
    let fault_addr = if info.is_null() {
        0
    } else {
        unsafe { (*info).si_addr as u64 }
    };
    let host_pc = unsafe { pc_from_ucontext(ucontext) };
    let crash = CrashInfo {
        sig,
        fault_addr,
        host_pc,
    };
    if let Ok(mut g) = CRASH_INFO.lock() {
        *g = Some(crash);
    }
    // longjmp from signal handler is technically allowed by POSIX
    // (siglongjmp is the safer cousin, but our setjmp impl is from libc
    // and the saved sigmask is restored on longjmp on Darwin).
    EXIT_CODE.store(0xFFFF_FFFE, Ordering::SeqCst);
    if EXIT_ARMED.load(Ordering::SeqCst) != 0 {
        longjmp(EXIT_ENV.as_ptr(), 2);
    }
    // Fall back to abort.
    unsafe {
        _exit(139);
    }
}

fn install_crash_handler() {
    if CRASH_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    let act = DarwinSigAction {
        sa_handler: crash_handler as *const () as usize,
        sa_mask: 0,
        sa_flags: SA_SIGINFO,
    };
    for sig in [SIGSEGV, SIGBUS, SIGTRAP, SIGILL] {
        unsafe {
            sigaction(sig, &act, core::ptr::null_mut());
        }
    }
}

/// Read any captured crash info from the most recent fatal signal.
/// Cleared on read so subsequent calls return None until the next crash.
pub fn take_crash_info() -> Option<CrashInfo> {
    CRASH_INFO.lock().ok().and_then(|mut g| g.take())
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

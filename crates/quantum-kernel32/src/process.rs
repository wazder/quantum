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

/// Per-thread ExitProcess / crash sink. Each guest thread (main +
/// CreateThread-spawned workers) has its own `ExitState` reachable via
/// a pthread key, so longjmp from a worker's signal handler lands in
/// that worker's setjmp slot — not back into the main thread's frame.
#[repr(C, align(16))]
pub struct ExitState {
    pub env: JmpBuf,
    pub code: AtomicU32,
    pub armed: AtomicU32,
}

unsafe impl Sync for ExitState {}

impl ExitState {
    pub const fn new() -> Self {
        Self {
            env: JmpBuf::new(),
            code: AtomicU32::new(0),
            armed: AtomicU32::new(0),
        }
    }
}

impl Default for ExitState {
    fn default() -> Self {
        Self::new()
    }
}

/// pthread-key handle for `ExitState`. Initialised lazily on first
/// access; `u64::MAX` means "not yet initialised". Darwin `pthread_key_t`
/// is `unsigned long` (8 bytes on arm64), so we keep the storage 64-bit
/// wide; mis-declaring this as `u32` causes pthread_key_create to
/// scribble past the local and corrupt the caller's stack frame.
static EXIT_KEY: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

unsafe extern "C" {
    fn pthread_key_create(key: *mut u64, destructor: *const ()) -> i32;
    fn pthread_getspecific(key: u64) -> *mut core::ffi::c_void;
    fn pthread_setspecific(key: u64, val: *const core::ffi::c_void) -> i32;
}

/// One-time creation of the pthread key. We deliberately leak the key
/// for the lifetime of the process — pthread keys are a small global
/// resource. The destructor is null because each thread's box is owned
/// by the runtime and shouldn't be auto-freed when the thread exits;
/// any cleanup happens explicitly in the worker bootstrap.
fn ensure_exit_key() -> u64 {
    let cur = EXIT_KEY.load(Ordering::SeqCst);
    if cur != u64::MAX {
        return cur;
    }
    let mut k: u64 = 0;
    // SAFETY: writes into our local stack u64 (Darwin pthread_key_t).
    unsafe {
        pthread_key_create(&mut k, core::ptr::null());
    }
    match EXIT_KEY.compare_exchange(u64::MAX, k, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(_) => k,
        // A racing thread already installed a key. We leak `k` (small)
        // and use the winner's value.
        Err(existing) => existing,
    }
}

/// Get this thread's `ExitState`, allocating one on first access.
/// Returned pointer is stable for the life of the thread.
fn current_exit_state() -> &'static ExitState {
    let key = ensure_exit_key();
    // SAFETY: pthread_{get,set}specific are async-signal-safe (get is
    // mandated by POSIX; set is technically not, but we never call it
    // from signal context — only from this allocator).
    unsafe {
        let p = pthread_getspecific(key) as *mut ExitState;
        if !p.is_null() {
            return &*p;
        }
        let boxed = Box::into_raw(Box::new(ExitState::new()));
        pthread_setspecific(key, boxed as *const _);
        &*boxed
    }
}

#[cfg(test)]
mod key_tests {
    use super::*;

    #[test]
    fn pthread_key_round_trip() {
        let key = ensure_exit_key();
        assert_ne!(key, u64::MAX, "key must be initialised");
        let st = current_exit_state();
        let p1 = st as *const ExitState as usize;
        let p2 = current_exit_state() as *const ExitState as usize;
        assert_eq!(p1, p2, "current_exit_state must be stable per thread");
    }
}

/// Compat accessor for callers that used the old global `EXIT_ENV`.
/// Returns this thread's setjmp slot pointer.
pub fn exit_env_ptr() -> *mut core::ffi::c_void {
    current_exit_state().env.as_ptr()
}

/// Compat accessor for the old `EXIT_ARMED` flag.
pub fn exit_armed() -> &'static AtomicU32 {
    &current_exit_state().armed
}

/// Compat accessor for the old `EXIT_CODE` register.
pub fn exit_code() -> &'static AtomicU32 {
    &current_exit_state().code
}

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
pub extern "C" fn ExitProcess(code: u32) -> ! {
    let st = current_exit_state();
    st.code.store(code, Ordering::SeqCst);
    if st.armed.load(Ordering::SeqCst) != 0 {
        longjmp(st.env.as_ptr(), 1);
    }
    // No trap armed — the only sensible thing is to terminate.
    std::process::exit(code as i32);
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
    let st = current_exit_state();
    // Snapshot the previous trap state on THIS thread so nested calls
    // restore on exit. The env buf is overwritten by setjmp; we copy
    // the prior bytes out and put them back on the way out. Nested
    // run_with_exit_trap calls compose because each thread owns its
    // own state — there's no cross-thread interference.
    let mut saved_env: [u8; 512] = [0; 512];
    unsafe {
        let env_ptr = st.env.as_ptr() as *const u8;
        core::ptr::copy_nonoverlapping(env_ptr, saved_env.as_mut_ptr(), 512);
    }
    let saved_code = st.code.swap(0, Ordering::SeqCst);
    let saved_armed = st.armed.swap(1, Ordering::SeqCst);

    let rc = setjmp(st.env.as_ptr());
    let result = if rc == 0 {
        body();
        u32::MAX
    } else {
        st.code.load(Ordering::SeqCst)
    };

    // Restore caller's trap state.
    unsafe {
        let env_ptr = st.env.as_ptr() as *mut u8;
        core::ptr::copy_nonoverlapping(saved_env.as_ptr(), env_ptr, 512);
    }
    st.code.store(saved_code, Ordering::SeqCst);
    st.armed.store(saved_armed, Ordering::SeqCst);

    result
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

#[derive(Debug, Clone, Copy, Default)]
pub struct CrashInfo {
    pub sig: i32,
    pub fault_addr: u64,
    pub host_pc: u64,
    /// AArch64 host GPRs X0..X30 + SP at the trap. Slots 0..15 carry
    /// the guest GPRs (pinned RAX..R15 per the JIT's register map).
    /// X19 is the pinned guest RSP. The SEH dispatcher uses these to
    /// build the Win64 CONTEXT it hands to vectored / unhandled
    /// exception filters.
    pub host_gprs: [u64; 32],
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
    fn sigaction(sig: i32, act: *const DarwinSigAction, oldact: *mut DarwinSigAction) -> i32;
    fn _exit(status: i32) -> !;
}

/// Pull the saved PC + all 32 GPR-class regs out of the ucontext
/// passed to the signal handler. Layout follows Darwin arm64
/// `<mach/arm/_structs.h>`:
///   ucontext_t.uc_mcontext is a pointer to mcontext64
///   mcontext64 = { __es (16B), __ss (arm_thread_state64_t), __ns (...) }
///   __ss layout:
///     __x[0..28]  offset   0..232  (29 * 8 bytes)
///     __fp (x29)  offset 232
///     __lr (x30)  offset 240
///     __sp        offset 248
///     __pc        offset 256
///   __ss starts at offset 16 within mcontext64.
///
/// Returns `(pc, gprs)` where `gprs[0..29] = x0..x28`,
/// `gprs[29] = fp`, `gprs[30] = lr`, `gprs[31] = sp`.
unsafe fn regs_from_ucontext(ucontext: *mut core::ffi::c_void) -> (u64, [u64; 32]) {
    if ucontext.is_null() {
        return (0, [0; 32]);
    }
    // SAFETY: caller passes a valid Darwin ucontext_t pointer from
    // sigaction; layout is documented in <mach/arm/_structs.h>.
    unsafe {
        let mcontext_ptr_off: usize = 48;
        let mcontext_pp = (ucontext as *const u8).add(mcontext_ptr_off) as *const *mut u8;
        let mcontext = *mcontext_pp;
        if mcontext.is_null() {
            return (0, [0; 32]);
        }
        let ss = mcontext.add(16);
        let mut gprs = [0u64; 32];
        // x0..x28: 29 registers at offset 0.
        for (i, slot) in gprs.iter_mut().enumerate().take(29) {
            *slot = *(ss.add(i * 8) as *const u64);
        }
        gprs[29] = *(ss.add(232) as *const u64); // fp
        gprs[30] = *(ss.add(240) as *const u64); // lr
        gprs[31] = *(ss.add(248) as *const u64); // sp
        let pc = *(ss.add(256) as *const u64);
        (pc, gprs)
    }
}

extern "C" fn crash_handler(sig: i32, info: *mut DarwinSigInfo, ucontext: *mut core::ffi::c_void) {
    let fault_addr = if info.is_null() {
        0
    } else {
        unsafe { (*info).si_addr as u64 }
    };
    let (host_pc, host_gprs) = unsafe { regs_from_ucontext(ucontext) };
    let crash = CrashInfo {
        sig,
        fault_addr,
        host_pc,
        host_gprs,
    };
    if let Ok(mut g) = CRASH_INFO.lock() {
        *g = Some(crash);
    }
    // longjmp from signal handler is technically allowed by POSIX
    // (siglongjmp is the safer cousin, but our setjmp impl is from libc
    // and the saved sigmask is restored on longjmp on Darwin).
    //
    // pthread_getspecific is async-signal-safe per POSIX, so it's OK
    // to fetch this thread's ExitState from inside the handler.
    let key = EXIT_KEY.load(Ordering::SeqCst);
    if key != u64::MAX {
        let p = unsafe { pthread_getspecific(key) } as *const ExitState;
        if !p.is_null() {
            let st = unsafe { &*p };
            st.code.store(0xFFFF_FFFE, Ordering::SeqCst);
            if st.armed.load(Ordering::SeqCst) != 0 {
                longjmp(st.env.as_ptr(), 2);
            }
        }
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

impl CrashInfo {
    /// Map the captured AArch64 host GPRs to the 16 Win64 GPRs in
    /// `GuestContext::gprs` ordering: [RAX, RCX, RDX, RBX, RSP, RBP,
    /// RSI, RDI, R8..R15]. Pinning mirrors `quantum_jit::lifter::host_reg`:
    ///   RAX..R15 ↔ X0..X15 (slot index = guest GP ordinal)
    ///   except RSP ↔ X19 and RBP ↔ X5.
    pub fn to_guest_gprs(&self) -> [u64; 16] {
        let mut gprs = [0u64; 16];
        gprs[..16].copy_from_slice(&self.host_gprs[..16]);
        gprs[4] = self.host_gprs[19]; // RSP comes from X19
        gprs
    }
}

#[cfg(test)]
mod crashinfo_tests {
    use super::*;

    #[test]
    fn crash_info_maps_x19_to_rsp() {
        let mut c = CrashInfo::default();
        // Populate distinct values so the mapping is observable.
        for i in 0..32 {
            c.host_gprs[i] = 0xAA00 + i as u64;
        }
        let gprs = c.to_guest_gprs();
        assert_eq!(gprs[0], 0xAA00); // RAX from X0
        assert_eq!(gprs[1], 0xAA01); // RCX from X1
        assert_eq!(gprs[3], 0xAA03); // RBX from X3
        assert_eq!(gprs[4], 0xAA13); // RSP from X19
        assert_eq!(gprs[5], 0xAA05); // RBP from X5
        assert_eq!(gprs[8], 0xAA08); // R8 from X8
        assert_eq!(gprs[15], 0xAA0F); // R15 from X15
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

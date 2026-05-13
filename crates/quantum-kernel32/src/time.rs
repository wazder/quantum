//! Time and timing thunks. Real programs hit these constantly — frame
//! pacing in games, log timestamps, profiling, sleep-based polling.

// Guest-callable extern "C" thunks — making them unsafe fn would change
// the callable type and break JIT marshaling.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// `void Sleep(DWORD dwMilliseconds)`.
#[unsafe(no_mangle)]
pub extern "C" fn Sleep(ms: u32) {
    std::thread::sleep(std::time::Duration::from_millis(ms as u64));
}

/// `DWORD GetTickCount(void)` — ms since the system started, wrapping
/// to u32 at ~49 days uptime.
#[unsafe(no_mangle)]
pub extern "C" fn GetTickCount() -> u32 {
    GetTickCount64() as u32
}

/// `ULONGLONG GetTickCount64(void)` — same but 64-bit.
#[unsafe(no_mangle)]
pub extern "C" fn GetTickCount64() -> u64 {
    QPC_ANCHOR.with(|a| a.elapsed().as_millis() as u64)
}

thread_local! {
    static QPC_ANCHOR: Instant = Instant::now();
}

/// `BOOL QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount)`.
#[unsafe(no_mangle)]
pub extern "C" fn QueryPerformanceCounter(out: *mut i64) -> i32 {
    if out.is_null() {
        return 0;
    }
    let nanos = QPC_ANCHOR.with(|a| a.elapsed().as_nanos() as i64);
    // SAFETY: caller-supplied pointer; we only write a single i64.
    unsafe {
        *out = nanos;
    }
    1
}

/// `BOOL QueryPerformanceFrequency(LARGE_INTEGER *)`. Real Win64 returns
/// the TSC tick rate (typically ~10 MHz); we report nanoseconds (1e9 Hz)
/// because that's what `QueryPerformanceCounter` returns now.
#[unsafe(no_mangle)]
pub extern "C" fn QueryPerformanceFrequency(out: *mut i64) -> i32 {
    if out.is_null() {
        return 0;
    }
    // SAFETY: caller pointer.
    unsafe {
        *out = 1_000_000_000;
    }
    1
}

/// `void GetSystemTimeAsFileTime(FILETIME *lpSystemTimeAsFileTime)`.
/// FILETIME counts 100-ns intervals since 1601-01-01 (the so-called
/// "Windows epoch"). We translate from Unix epoch (1970-01-01).
#[unsafe(no_mangle)]
pub extern "C" fn GetSystemTimeAsFileTime(out: *mut u64) {
    if out.is_null() {
        return;
    }
    // 11_644_473_600 seconds between 1601-01-01 and 1970-01-01.
    const WINDOWS_TO_UNIX_EPOCH_SECS: u64 = 11_644_473_600;
    let unix_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = unix_now.as_secs() + WINDOWS_TO_UNIX_EPOCH_SECS;
    let total_100ns = total_secs * 10_000_000 + (unix_now.subsec_nanos() as u64 / 100);
    // SAFETY: caller pointer.
    unsafe {
        *out = total_100ns;
    }
}

/// `DWORD GetCurrentThreadId(void)`. Returns a pthread-derived value
/// for the calling thread. Sekiro and most game engines query this
/// for per-thread logging.
#[unsafe(no_mangle)]
pub extern "C" fn GetCurrentThreadId() -> u32 {
    // Use the low 32 bits of the pthread mach port number for stability
    // across queries on the same thread.
    unsafe extern "C" {
        fn pthread_mach_thread_np(thread: *const core::ffi::c_void) -> u32;
        fn pthread_self() -> *const core::ffi::c_void;
    }
    // SAFETY: pthread_self / pthread_mach_thread_np are POSIX-safe.
    unsafe { pthread_mach_thread_np(pthread_self()) }
}

/// `DWORD GetCurrentProcessId(void)`.
#[unsafe(no_mangle)]
pub extern "C" fn GetCurrentProcessId() -> u32 {
    std::process::id()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perf_counter_monotone() {
        let mut a = 0i64;
        let mut b = 0i64;
        assert_eq!(QueryPerformanceCounter(&mut a), 1);
        std::thread::sleep(std::time::Duration::from_millis(1));
        assert_eq!(QueryPerformanceCounter(&mut b), 1);
        assert!(b > a);
    }

    #[test]
    fn perf_frequency_nonzero() {
        let mut f = 0i64;
        assert_eq!(QueryPerformanceFrequency(&mut f), 1);
        assert!(f > 0);
    }

    #[test]
    fn tick_count_increasing() {
        let a = GetTickCount64();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = GetTickCount64();
        assert!(b > a);
    }

    #[test]
    fn file_time_in_sane_range() {
        let mut ft = 0u64;
        GetSystemTimeAsFileTime(&mut ft);
        // 2026-05 is about 13_400_000_000 seconds * 10M into FILETIME.
        assert!(ft > 132_000_000_000_000_000);
    }

    #[test]
    fn thread_and_process_ids_nonzero() {
        assert!(GetCurrentThreadId() != 0);
        assert!(GetCurrentProcessId() != 0);
    }
}

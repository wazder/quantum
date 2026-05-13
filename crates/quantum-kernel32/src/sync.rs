//! Synchronization-primitive thunks.
//!
//! Critical sections: Win64's lightweight intra-process mutex. The
//! guest passes a `LPCRITICAL_SECTION` (a pointer to an opaque
//! 40-byte struct). We treat that 40 bytes as our own state — the
//! guest never reads inside it.
//!
//! Today the implementation is a recursion-counting spin lock. That's
//! correct under single-threaded execution (which is where we are
//! until Phase 1.8 lands a real CreateThread). When threading goes
//! live, the spin lock becomes a real contention point — we'll swap
//! in pthread_mutex_t at that point.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::sync::atomic::{AtomicU32, Ordering};
use std::cell::Cell;

#[repr(C)]
struct GuestCriticalSection {
    lock_count: AtomicU32,
    owner_thread_id: AtomicU32,
    // padding: the Windows RTL_CRITICAL_SECTION is 40 bytes total.
    _pad: [u8; 32],
}

/// `void InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection)`.
#[unsafe(no_mangle)]
pub extern "C" fn InitializeCriticalSection(cs: *mut u8) {
    if cs.is_null() {
        return;
    }
    // SAFETY: caller-supplied buffer of at least 40 bytes (RTL_CRITICAL_SECTION layout).
    unsafe {
        let s = cs.cast::<GuestCriticalSection>();
        (*s).lock_count.store(0, Ordering::Release);
        (*s).owner_thread_id.store(0, Ordering::Release);
    }
}

/// `BOOL InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION, DWORD spinCount)`.
#[unsafe(no_mangle)]
pub extern "C" fn InitializeCriticalSectionAndSpinCount(cs: *mut u8, _spin: u32) -> i32 {
    InitializeCriticalSection(cs);
    1
}

/// `void EnterCriticalSection(LPCRITICAL_SECTION)`.
#[unsafe(no_mangle)]
pub extern "C" fn EnterCriticalSection(cs: *mut u8) {
    if cs.is_null() {
        return;
    }
    let tid = crate::time::GetCurrentThreadId();
    // SAFETY: buffer outlives the call; we only touch the first two atomics.
    let s = unsafe { &*cs.cast::<GuestCriticalSection>() };
    loop {
        // Re-entry: if we already own it, just bump count.
        if s.owner_thread_id.load(Ordering::Acquire) == tid {
            s.lock_count.fetch_add(1, Ordering::AcqRel);
            return;
        }
        // Try to grab it: only succeeds if count transitions 0 -> 1.
        if s.lock_count
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            s.owner_thread_id.store(tid, Ordering::Release);
            return;
        }
        std::hint::spin_loop();
    }
}

/// `void LeaveCriticalSection(LPCRITICAL_SECTION)`.
#[unsafe(no_mangle)]
pub extern "C" fn LeaveCriticalSection(cs: *mut u8) {
    if cs.is_null() {
        return;
    }
    // SAFETY: see EnterCriticalSection.
    let s = unsafe { &*cs.cast::<GuestCriticalSection>() };
    let prev = s.lock_count.fetch_sub(1, Ordering::AcqRel);
    if prev <= 1 {
        s.owner_thread_id.store(0, Ordering::Release);
    }
}

/// `void DeleteCriticalSection(LPCRITICAL_SECTION)`. We have no
/// per-CS host state to release; the guest reclaims the buffer.
#[unsafe(no_mangle)]
pub extern "C" fn DeleteCriticalSection(_cs: *mut u8) {}

/// `BOOL TryEnterCriticalSection(LPCRITICAL_SECTION)`.
#[unsafe(no_mangle)]
pub extern "C" fn TryEnterCriticalSection(cs: *mut u8) -> i32 {
    if cs.is_null() {
        return 0;
    }
    let tid = crate::time::GetCurrentThreadId();
    // SAFETY: see EnterCriticalSection.
    let s = unsafe { &*cs.cast::<GuestCriticalSection>() };
    if s.owner_thread_id.load(Ordering::Acquire) == tid {
        s.lock_count.fetch_add(1, Ordering::AcqRel);
        return 1;
    }
    if s.lock_count
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        s.owner_thread_id.store(tid, Ordering::Release);
        1
    } else {
        0
    }
}

// ---------- LastError ----------

thread_local! {
    static LAST_ERROR: Cell<u32> = const { Cell::new(0) };
}

/// `void SetLastError(DWORD dwErrCode)`.
#[unsafe(no_mangle)]
pub extern "C" fn SetLastError(code: u32) {
    LAST_ERROR.with(|c| c.set(code));
}

/// `DWORD GetLastError(void)`.
#[unsafe(no_mangle)]
pub extern "C" fn GetLastError() -> u32 {
    LAST_ERROR.with(Cell::get)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_section_lock_unlock_recursive() {
        let mut cs = [0u8; 40];
        let p = cs.as_mut_ptr();
        InitializeCriticalSection(p);
        EnterCriticalSection(p);
        EnterCriticalSection(p); // recursive
        // Re-entered: lock count should be 2 internally.
        // SAFETY: we own the buffer.
        let s = unsafe { &*p.cast::<GuestCriticalSection>() };
        assert_eq!(s.lock_count.load(Ordering::Acquire), 2);
        LeaveCriticalSection(p);
        assert_eq!(s.lock_count.load(Ordering::Acquire), 1);
        LeaveCriticalSection(p);
        assert_eq!(s.lock_count.load(Ordering::Acquire), 0);
        DeleteCriticalSection(p);
    }

    #[test]
    fn try_enter_succeeds_when_unlocked() {
        let mut cs = [0u8; 40];
        let p = cs.as_mut_ptr();
        InitializeCriticalSection(p);
        assert_eq!(TryEnterCriticalSection(p), 1);
        LeaveCriticalSection(p);
    }

    #[test]
    fn last_error_round_trip() {
        SetLastError(0xC000_0001);
        assert_eq!(GetLastError(), 0xC000_0001);
        SetLastError(0);
        assert_eq!(GetLastError(), 0);
    }
}

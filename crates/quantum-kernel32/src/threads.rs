//! Synchronization-object thunks built on top of `handles::KernelObject`.
//! Real CreateThread comes later (Phase 1.8 proper) — we first ship
//! the cross-thread primitives so any single-threaded guest CRT
//! initialisation that touches them runs cleanly.

#![allow(
    clippy::not_unsafe_ptr_arg_deref,
    clippy::collapsible_if,
    clippy::collapsible_else_if,
    clippy::collapsible_match
)]

use core::ffi::c_void;
use std::sync::{Condvar, Mutex};

use crate::handles::{self, INFINITE, KernelObject, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};

// ---------- Events ----------

/// `HANDLE CreateEventA(LPSECURITY_ATTRIBUTES, BOOL bManualReset,
///                       BOOL bInitialState, LPCSTR lpName)`.
/// Named events aren't shared across processes today; the name is
/// stored but ignored.
#[unsafe(no_mangle)]
pub extern "C" fn CreateEventA(
    _sec: *mut c_void,
    manual_reset: i32,
    initial_state: i32,
    _name: *const i8,
) -> usize {
    handles::insert(KernelObject::Event {
        manual_reset: manual_reset != 0,
        signaled: Mutex::new(initial_state != 0),
        cv: Condvar::new(),
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CreateEventW(
    sec: *mut c_void,
    manual_reset: i32,
    initial_state: i32,
    _name: *const u16,
) -> usize {
    CreateEventA(sec, manual_reset, initial_state, core::ptr::null())
}

#[unsafe(no_mangle)]
pub extern "C" fn SetEvent(handle: usize) -> i32 {
    if let Some(obj) = handles::get(handle) {
        if let KernelObject::Event { signaled, cv, .. } = &*obj {
            *signaled.lock().unwrap() = true;
            cv.notify_all();
            return 1;
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn PulseEvent(handle: usize) -> i32 {
    let r = SetEvent(handle);
    if r != 0 {
        ResetEvent(handle);
    }
    r
}

#[unsafe(no_mangle)]
pub extern "C" fn ResetEvent(handle: usize) -> i32 {
    if let Some(obj) = handles::get(handle) {
        if let KernelObject::Event { signaled, .. } = &*obj {
            *signaled.lock().unwrap() = false;
            return 1;
        }
    }
    0
}

// ---------- Mutexes ----------

#[unsafe(no_mangle)]
pub extern "C" fn CreateMutexA(_sec: *mut c_void, initial_owner: i32, _name: *const i8) -> usize {
    let owner = if initial_owner != 0 {
        Some(crate::time::GetCurrentThreadId())
    } else {
        None
    };
    let recursion = if initial_owner != 0 { 1 } else { 0 };
    handles::insert(KernelObject::Mutex {
        owner_thread: Mutex::new(owner),
        recursion: Mutex::new(recursion),
        cv: Condvar::new(),
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CreateMutexW(sec: *mut c_void, initial_owner: i32, _name: *const u16) -> usize {
    CreateMutexA(sec, initial_owner, core::ptr::null())
}

#[unsafe(no_mangle)]
pub extern "C" fn ReleaseMutex(handle: usize) -> i32 {
    if let Some(obj) = handles::get(handle) {
        if let KernelObject::Mutex {
            owner_thread,
            recursion,
            cv,
        } = &*obj
        {
            let tid = crate::time::GetCurrentThreadId();
            let mut owner = owner_thread.lock().unwrap();
            if *owner != Some(tid) {
                return 0;
            }
            let mut r = recursion.lock().unwrap();
            *r -= 1;
            if *r == 0 {
                *owner = None;
                cv.notify_one();
            }
            return 1;
        }
    }
    0
}

// ---------- Semaphores ----------

#[unsafe(no_mangle)]
pub extern "C" fn CreateSemaphoreA(
    _sec: *mut c_void,
    initial_count: i32,
    max_count: i32,
    _name: *const i8,
) -> usize {
    handles::insert(KernelObject::Semaphore {
        count: Mutex::new(initial_count),
        max: max_count,
        cv: Condvar::new(),
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn CreateSemaphoreW(
    sec: *mut c_void,
    initial_count: i32,
    max_count: i32,
    _name: *const u16,
) -> usize {
    CreateSemaphoreA(sec, initial_count, max_count, core::ptr::null())
}

#[unsafe(no_mangle)]
pub extern "C" fn ReleaseSemaphore(
    handle: usize,
    release_count: i32,
    previous_count_out: *mut i32,
) -> i32 {
    if let Some(obj) = handles::get(handle) {
        if let KernelObject::Semaphore { count, max, cv } = &*obj {
            let mut c = count.lock().unwrap();
            let prev = *c;
            if prev + release_count > *max {
                return 0;
            }
            *c += release_count;
            if !previous_count_out.is_null() {
                // SAFETY: caller pointer.
                unsafe {
                    *previous_count_out = prev;
                }
            }
            cv.notify_all();
            return 1;
        }
    }
    0
}

// ---------- Wait ----------

#[unsafe(no_mangle)]
pub extern "C" fn WaitForSingleObject(handle: usize, timeout_ms: u32) -> u32 {
    match handles::get(handle) {
        Some(obj) => handles::wait_single(&obj, timeout_ms),
        None => WAIT_FAILED,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn WaitForSingleObjectEx(handle: usize, timeout_ms: u32, _alertable: i32) -> u32 {
    WaitForSingleObject(handle, timeout_ms)
}

/// Simple multi-wait. For wait_all=true we wait sequentially on each;
/// for wait_all=false we poll. Both are correct but not maximally
/// fair / efficient — fine until a real game needs better behaviour.
#[unsafe(no_mangle)]
pub extern "C" fn WaitForMultipleObjects(
    count: u32,
    handles_arr: *const usize,
    wait_all: i32,
    timeout_ms: u32,
) -> u32 {
    if handles_arr.is_null() || count == 0 {
        return WAIT_FAILED;
    }
    // SAFETY: caller-supplied buffer of `count` handles.
    let arr = unsafe { core::slice::from_raw_parts(handles_arr, count as usize) };

    if wait_all != 0 {
        // Wait sequentially. Total elapsed not strictly tracked here.
        for &h in arr {
            let r = WaitForSingleObject(h, timeout_ms);
            if r != WAIT_OBJECT_0 {
                return r;
            }
        }
        WAIT_OBJECT_0
    } else {
        // Poll each every 1ms up to timeout.
        let deadline = if timeout_ms == INFINITE {
            None
        } else {
            Some(std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64))
        };
        loop {
            for (i, &h) in arr.iter().enumerate() {
                if WaitForSingleObject(h, 0) == WAIT_OBJECT_0 {
                    return WAIT_OBJECT_0 + i as u32;
                }
            }
            if let Some(d) = deadline {
                if std::time::Instant::now() >= d {
                    return WAIT_TIMEOUT;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}

// ---------- Generic CloseHandle / DuplicateHandle ----------

#[unsafe(no_mangle)]
pub extern "C" fn CloseHandle(handle: usize) -> i32 {
    if handles::remove(handle) { 1 } else { 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn DuplicateHandle(
    _src_proc: usize,
    src_handle: usize,
    _dst_proc: usize,
    dst_handle_out: *mut usize,
    _access: u32,
    _inherit: i32,
    _options: u32,
) -> i32 {
    if dst_handle_out.is_null() {
        return 0;
    }
    // For now we just return the same handle. Real DuplicateHandle
    // refcounts the underlying object; ours is Arc'd already.
    // SAFETY: caller pointer.
    unsafe {
        *dst_handle_out = src_handle;
    }
    1
}

// ---------- CreateThread placeholder ----------
//
// Real CreateThread needs a per-thread guest context + dispatcher
// loop running in a pthread. Until that lands we return a non-null
// handle and call the guest entry inline on the current thread —
// works for any program whose threads aren't load-bearing for
// liveness.

#[unsafe(no_mangle)]
pub extern "C" fn CreateThread(
    _sec: *mut c_void,
    _stack_size: usize,
    _start: *const c_void,
    _param: *mut c_void,
    _flags: u32,
    thread_id_out: *mut u32,
) -> usize {
    // Stub: return a fake handle and a fake tid. The thread doesn't
    // actually start — guest code that depends on the thread doing
    // anything will hang waiting on it. To be replaced with a real
    // pthread + dispatcher loop.
    if !thread_id_out.is_null() {
        // SAFETY: caller pointer.
        unsafe {
            *thread_id_out = 0xDEAD_BEEF;
        }
    }
    handles::insert(KernelObject::CurrentThread)
}

#[unsafe(no_mangle)]
pub extern "C" fn GetCurrentThread() -> usize {
    // Pseudo-handle in Win64 is the constant -2.
    -2isize as usize
}

#[unsafe(no_mangle)]
pub extern "C" fn GetCurrentProcess() -> usize {
    -1isize as usize
}

#[unsafe(no_mangle)]
pub extern "C" fn ExitThread(_code: u32) -> ! {
    loop {
        std::thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_set_then_wait_succeeds() {
        let h = CreateEventA(core::ptr::null_mut(), 1, 0, core::ptr::null());
        assert!(h != 0);
        assert_eq!(SetEvent(h), 1);
        assert_eq!(WaitForSingleObject(h, 0), WAIT_OBJECT_0);
        assert_eq!(CloseHandle(h), 1);
    }

    #[test]
    fn auto_reset_event_resets_after_wait() {
        let h = CreateEventA(core::ptr::null_mut(), 0, 1, core::ptr::null());
        assert_eq!(WaitForSingleObject(h, 0), WAIT_OBJECT_0);
        // After auto-reset, signal cleared.
        assert_eq!(WaitForSingleObject(h, 10), WAIT_TIMEOUT);
        assert_eq!(CloseHandle(h), 1);
    }

    #[test]
    fn mutex_re_entry_counts() {
        let h = CreateMutexA(core::ptr::null_mut(), 0, core::ptr::null());
        assert_eq!(WaitForSingleObject(h, 0), WAIT_OBJECT_0);
        assert_eq!(WaitForSingleObject(h, 0), WAIT_OBJECT_0); // recursion
        assert_eq!(ReleaseMutex(h), 1);
        assert_eq!(ReleaseMutex(h), 1);
        // Now unowned — releasing again should fail.
        assert_eq!(ReleaseMutex(h), 0);
        assert_eq!(CloseHandle(h), 1);
    }

    #[test]
    fn semaphore_release_count() {
        let h = CreateSemaphoreA(core::ptr::null_mut(), 0, 2, core::ptr::null());
        let mut prev: i32 = -1;
        assert_eq!(ReleaseSemaphore(h, 2, &mut prev), 1);
        assert_eq!(prev, 0);
        assert_eq!(WaitForSingleObject(h, 0), WAIT_OBJECT_0);
        assert_eq!(WaitForSingleObject(h, 0), WAIT_OBJECT_0);
        // Empty now.
        assert_eq!(WaitForSingleObject(h, 10), WAIT_TIMEOUT);
        assert_eq!(CloseHandle(h), 1);
    }
}

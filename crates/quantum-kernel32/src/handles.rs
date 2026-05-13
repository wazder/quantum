// See stubs.rs for rationale on these allow attributes.
#![allow(
    clippy::collapsible_if,
    clippy::collapsible_else_if,
    clippy::collapsible_match
)]

//! Generic HANDLE table for kernel objects (events, mutexes,
//! semaphores, files, threads). Windows uses an opaque pointer-sized
//! handle for every kernel object; we mint integer handles backed by
//! a global slot table.
//!
//! All thunks that create an object insert into HANDLES and return
//! the new handle; CloseHandle/WaitForSingleObject/etc look up by
//! handle. Handles are reusable after close (with a generation
//! counter mixed in so stale handles don't accidentally hit a
//! recycled slot).

use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::Duration;

/// The kinds of kernel object we currently model.
pub enum KernelObject {
    Event {
        manual_reset: bool,
        signaled: std::sync::Mutex<bool>,
        cv: std::sync::Condvar,
    },
    Mutex {
        owner_thread: std::sync::Mutex<Option<u32>>,
        recursion: std::sync::Mutex<u32>,
        cv: std::sync::Condvar,
    },
    Semaphore {
        count: std::sync::Mutex<i32>,
        max: i32,
        cv: std::sync::Condvar,
    },
    /// `HOSTFD(i32)` — wrapper for a POSIX file descriptor we opened.
    File(i32),
    /// Pseudo-handle for the current process.
    CurrentProcess,
    /// Pseudo-handle for the current thread.
    CurrentThread,
    /// Standard stream (stdin/stdout/stderr).
    StdStream(u32),
}

struct HandleTable {
    /// Each slot is Option<(generation, object)>. None == free.
    slots: Vec<Option<(u32, std::sync::Arc<KernelObject>)>>,
}

fn table() -> &'static Mutex<HandleTable> {
    static T: OnceLock<Mutex<HandleTable>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(HandleTable { slots: Vec::new() }))
}

/// Pack (index, generation) into a 64-bit handle. Low 32 = index,
/// high 32 = generation. Handles always start above 0x1000 so 0
/// keeps meaning "invalid".
fn pack(index: usize, generation: u32) -> usize {
    ((generation as usize) << 32) | (index + 0x1000)
}

fn unpack(handle: usize) -> Option<(usize, u32)> {
    if handle < 0x1000 {
        return None;
    }
    let generation = (handle >> 32) as u32;
    let idx = (handle & 0xFFFF_FFFF) - 0x1000;
    Some((idx, generation))
}

pub fn insert(obj: KernelObject) -> usize {
    let arc = std::sync::Arc::new(obj);
    let mut t = table().lock().unwrap();
    if let Some(idx) = t.slots.iter().position(Option::is_none) {
        // Reuse a free slot, bump generation.
        let new_gen = t.slots[idx].as_ref().map_or(1, |(g, _)| g.wrapping_add(1));
        t.slots[idx] = Some((new_gen, arc));
        pack(idx, new_gen)
    } else {
        let idx = t.slots.len();
        t.slots.push(Some((1, arc)));
        pack(idx, 1)
    }
}

pub fn get(handle: usize) -> Option<std::sync::Arc<KernelObject>> {
    let (idx, generation) = unpack(handle)?;
    let t = table().lock().unwrap();
    t.slots
        .get(idx)
        .and_then(|s| s.as_ref())
        .filter(|(g, _)| *g == generation)
        .map(|(_, arc)| arc.clone())
}

pub fn remove(handle: usize) -> bool {
    let (idx, generation) = match unpack(handle) {
        Some(t) => t,
        None => return false,
    };
    let mut t = table().lock().unwrap();
    let slot = match t.slots.get_mut(idx) {
        Some(s) => s,
        None => return false,
    };
    if let Some((g, obj)) = slot.as_ref() {
        if *g == generation {
            // Release POSIX fd if this was a File handle.
            if let KernelObject::File(fd) = &**obj {
                let fd = *fd;
                unsafe extern "C" {
                    fn close(fd: i32) -> i32;
                }
                unsafe {
                    let _ = close(fd);
                }
            }
            *slot = None;
            return true;
        }
    }
    false
}

// ---------- Wait results ----------

pub const WAIT_OBJECT_0: u32 = 0x0000_0000;
pub const WAIT_ABANDONED: u32 = 0x0000_0080;
pub const WAIT_TIMEOUT: u32 = 0x0000_0102;
pub const WAIT_FAILED: u32 = 0xFFFF_FFFF;
pub const INFINITE: u32 = 0xFFFF_FFFF;

/// Wait on a single kernel object. Returns WAIT_OBJECT_0 / WAIT_TIMEOUT /
/// WAIT_FAILED per Win32 spec.
pub fn wait_single(obj: &KernelObject, timeout_ms: u32) -> u32 {
    let deadline = if timeout_ms == INFINITE {
        None
    } else {
        Some(std::time::Instant::now() + Duration::from_millis(timeout_ms as u64))
    };

    match obj {
        KernelObject::Event {
            manual_reset,
            signaled,
            cv,
        } => {
            let mut s = signaled.lock().unwrap();
            while !*s {
                if let Some(d) = deadline {
                    let now = std::time::Instant::now();
                    if now >= d {
                        return WAIT_TIMEOUT;
                    }
                    let (g, t) = cv.wait_timeout(s, d - now).unwrap();
                    if t.timed_out() {
                        return WAIT_TIMEOUT;
                    }
                    s = g;
                } else {
                    s = cv.wait(s).unwrap();
                }
            }
            if !manual_reset {
                *s = false;
            }
            WAIT_OBJECT_0
        }
        KernelObject::Mutex {
            owner_thread,
            recursion,
            cv,
        } => {
            let tid = crate::time::GetCurrentThreadId();
            let mut owner = owner_thread.lock().unwrap();
            loop {
                match *owner {
                    None => {
                        *owner = Some(tid);
                        *recursion.lock().unwrap() = 1;
                        return WAIT_OBJECT_0;
                    }
                    Some(t) if t == tid => {
                        *recursion.lock().unwrap() += 1;
                        return WAIT_OBJECT_0;
                    }
                    Some(_) => {
                        if let Some(d) = deadline {
                            let now = std::time::Instant::now();
                            if now >= d {
                                return WAIT_TIMEOUT;
                            }
                            let (g, t) = cv.wait_timeout(owner, d - now).unwrap();
                            if t.timed_out() {
                                return WAIT_TIMEOUT;
                            }
                            owner = g;
                        } else {
                            owner = cv.wait(owner).unwrap();
                        }
                    }
                }
            }
        }
        KernelObject::Semaphore { count, max: _, cv } => {
            let mut c = count.lock().unwrap();
            while *c <= 0 {
                if let Some(d) = deadline {
                    let now = std::time::Instant::now();
                    if now >= d {
                        return WAIT_TIMEOUT;
                    }
                    let (g, t) = cv.wait_timeout(c, d - now).unwrap();
                    if t.timed_out() {
                        return WAIT_TIMEOUT;
                    }
                    c = g;
                } else {
                    c = cv.wait(c).unwrap();
                }
            }
            *c -= 1;
            WAIT_OBJECT_0
        }
        // Process/Thread/File pseudo-handles: never signal here.
        _ => WAIT_TIMEOUT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_round_trip() {
        let h = insert(KernelObject::Event {
            manual_reset: true,
            signaled: std::sync::Mutex::new(false),
            cv: std::sync::Condvar::new(),
        });
        assert!(h >= 0x1000);
        assert!(get(h).is_some());
        assert!(remove(h));
        assert!(get(h).is_none());
    }

    #[test]
    fn signaled_event_no_wait() {
        let h = insert(KernelObject::Event {
            manual_reset: true,
            signaled: std::sync::Mutex::new(true),
            cv: std::sync::Condvar::new(),
        });
        let obj = get(h).unwrap();
        assert_eq!(wait_single(&obj, 0), WAIT_OBJECT_0);
    }

    #[test]
    fn unsignaled_event_times_out() {
        let h = insert(KernelObject::Event {
            manual_reset: true,
            signaled: std::sync::Mutex::new(false),
            cv: std::sync::Condvar::new(),
        });
        let obj = get(h).unwrap();
        assert_eq!(wait_single(&obj, 50), WAIT_TIMEOUT);
    }
}

//! Process heap thunks.
//!
//! Real Windows has multiple HeapCreate-able heaps; we start with a
//! single default process heap because it's what every CRT and every
//! game's allocator end up using. The backing storage is a
//! `MachVmManager` region carved up by a bump allocator — no
//! reclamation yet. Good enough for the first real-app bring-up
//! since modern allocators (mimalloc, the CRT's debug heap, etc.)
//! tend to allocate large slabs from HeapAlloc and sub-allocate
//! internally; we only see the slab requests.

// These functions are guest-callable thunks, invoked as plain
// extern "C" pointers from JIT'd code. Clippy's not_unsafe_ptr_arg
// lint would force them to be `unsafe fn`s which would change the
// callable type and break the JIT marshaling. The reads/writes are
// bounded by the size the guest itself supplies.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::sync::{Mutex, OnceLock};

use quantum_runtime::{MachVmManager, MemoryManager, Protection, Region};

/// Default process heap size. 64 MiB is plenty for CLI-scale guests;
/// games will need a larger or growable heap (TODO: HeapCreate).
const DEFAULT_HEAP_BYTES: usize = 64 * 1024 * 1024;

/// Sentinel handle that `GetProcessHeap` returns. The thunks all
/// check the supplied handle against this value before touching the
/// underlying heap.
pub const DEFAULT_HEAP_HANDLE: usize = 0xDEAD_BEEFusize;

/// Flag bits accepted by HeapAlloc.
const HEAP_ZERO_MEMORY: u32 = 0x0000_0008;

struct Heap {
    region: Region,
    next: usize,
}

impl Heap {
    fn new(size: usize) -> Self {
        let mem = MachVmManager::new();
        let region = mem
            .allocate(None, size, Protection::RW)
            .expect("default heap mach_vm_allocate");
        Self { region, next: 0 }
    }

    fn alloc(&mut self, size: usize, zero: bool) -> *mut u8 {
        // 16-byte alignment for everything, matching Win64 alloc
        // expectations.
        let aligned = (size + 15) & !15;
        if self
            .next
            .checked_add(aligned)
            .is_none_or(|end| end > self.region.len())
        {
            return core::ptr::null_mut();
        }
        // SAFETY: index is within the owned region.
        let ptr = unsafe { self.region.base().add(self.next) };
        if zero {
            // SAFETY: we just bounds-checked `aligned` bytes from `ptr`.
            unsafe { core::ptr::write_bytes(ptr, 0, aligned) };
        }
        self.next += aligned;
        ptr
    }

    fn free(&mut self, _ptr: *mut u8) -> bool {
        // Bump allocator — frees are no-ops. Returning true preserves
        // Windows' API contract (success).
        true
    }
}

fn default_heap() -> &'static Mutex<Heap> {
    static HEAP: OnceLock<Mutex<Heap>> = OnceLock::new();
    HEAP.get_or_init(|| Mutex::new(Heap::new(DEFAULT_HEAP_BYTES)))
}

/// `HANDLE GetProcessHeap(void)`.
#[unsafe(no_mangle)]
pub extern "C" fn GetProcessHeap() -> usize {
    DEFAULT_HEAP_HANDLE
}

/// `LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)`.
#[unsafe(no_mangle)]
pub extern "C" fn HeapAlloc(handle: usize, flags: u32, size: usize) -> *mut u8 {
    if handle != DEFAULT_HEAP_HANDLE {
        return core::ptr::null_mut();
    }
    let zero = (flags & HEAP_ZERO_MEMORY) != 0;
    default_heap().lock().expect("heap mutex").alloc(size, zero)
}

/// `BOOL HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)`.
#[unsafe(no_mangle)]
pub extern "C" fn HeapFree(handle: usize, _flags: u32, ptr: *mut u8) -> i32 {
    if handle != DEFAULT_HEAP_HANDLE {
        return 0;
    }
    default_heap().lock().expect("heap mutex").free(ptr) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_returns_writable_pointer() {
        let h = GetProcessHeap();
        let p = HeapAlloc(h, 0, 64);
        assert!(!p.is_null());
        // SAFETY: HeapAlloc returned a 64-byte region.
        unsafe {
            for i in 0..64 {
                *p.add(i) = i as u8;
            }
            for i in 0..64 {
                assert_eq!(*p.add(i), i as u8);
            }
        }
        assert_eq!(HeapFree(h, 0, p), 1);
    }

    #[test]
    fn zero_flag_clears_memory() {
        let h = GetProcessHeap();
        let p = HeapAlloc(h, HEAP_ZERO_MEMORY, 32);
        assert!(!p.is_null());
        // SAFETY: 32 bytes.
        unsafe {
            for i in 0..32 {
                assert_eq!(*p.add(i), 0);
            }
        }
    }

    #[test]
    fn wrong_handle_returns_null() {
        let p = HeapAlloc(0, 0, 16);
        assert!(p.is_null());
    }
}

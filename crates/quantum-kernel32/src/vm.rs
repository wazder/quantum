//! Virtual memory thunks. Real apps use VirtualAlloc for things they
//! don't want going through the regular heap — graphics surfaces,
//! command buffers, custom allocators. Sekiro's engine, like every
//! modern game, allocates large reserved regions via VirtualAlloc and
//! commits pages as it grows them.
//!
//! Our model: every VirtualAlloc call backs onto `MachVmManager`.
//! MEM_RESERVE+MEM_COMMIT (the common case) maps to a single
//! mach_vm_allocate with the requested protection.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::sync::Mutex;
use std::sync::OnceLock;

use quantum_runtime::{MachVmManager, MemoryManager, Protection};

// flAllocationType bits.
const MEM_COMMIT: u32 = 0x0000_1000;
const MEM_RESERVE: u32 = 0x0000_2000;
const MEM_RELEASE: u32 = 0x0000_8000;
// MEM_DECOMMIT 0x4000 — accepted but no-op (we always commit up front).

// flProtect bits.
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

fn translate_protect(flags: u32) -> Protection {
    let base = flags & 0xFF;
    match base {
        PAGE_NOACCESS => Protection::NONE,
        PAGE_READONLY => Protection::R,
        PAGE_READWRITE => Protection::RW,
        PAGE_EXECUTE => Protection::RX,
        PAGE_EXECUTE_READ => Protection::RX,
        PAGE_EXECUTE_READWRITE => Protection::RWX,
        _ => Protection::RW,
    }
}

/// Track regions we've handed out so VirtualFree can release them.
struct VmTable {
    regions: Vec<(u64, usize)>, // (base, len) for each live allocation
}

fn vm_table() -> &'static Mutex<VmTable> {
    static T: OnceLock<Mutex<VmTable>> = OnceLock::new();
    T.get_or_init(|| {
        Mutex::new(VmTable {
            regions: Vec::new(),
        })
    })
}

/// `LPVOID VirtualAlloc(LPVOID, SIZE_T, DWORD allocType, DWORD protect)`.
#[unsafe(no_mangle)]
pub extern "C" fn VirtualAlloc(
    address: *mut u8,
    size: usize,
    alloc_type: u32,
    protect: u32,
) -> *mut u8 {
    if size == 0 {
        return core::ptr::null_mut();
    }
    // We support RESERVE, COMMIT, and RESERVE|COMMIT uniformly — every
    // allocation is fully committed. MEM_RESET and the large-page bits
    // are ignored.
    if alloc_type & (MEM_RESERVE | MEM_COMMIT) == 0 {
        return core::ptr::null_mut();
    }
    let prot = translate_protect(protect);
    let mem = MachVmManager::new();
    let hint = if address.is_null() {
        None
    } else {
        Some(address as u64)
    };
    let region = match mem.allocate(hint, size, prot) {
        Ok(r) => r,
        Err(_) => return core::ptr::null_mut(),
    };
    let base = region.base() as u64;
    let len = region.len();
    // Leak the Region — VirtualFree(MEM_RELEASE) will reclaim through
    // munmap directly. Tracking in vm_table lets us look up later.
    core::mem::forget(region);
    vm_table().lock().unwrap().regions.push((base, len));
    base as *mut u8
}

/// `BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)`.
#[unsafe(no_mangle)]
pub extern "C" fn VirtualFree(address: *mut u8, _size: usize, free_type: u32) -> i32 {
    if address.is_null() {
        return 0;
    }
    if free_type & MEM_RELEASE == 0 {
        // MEM_DECOMMIT — we treat it as a no-op since we always commit
        // up front. The Windows API contract allows this.
        return 1;
    }
    let addr = address as u64;
    let mut table = vm_table().lock().unwrap();
    if let Some(idx) = table.regions.iter().position(|&(b, _)| b == addr) {
        let (_, len) = table.regions.swap_remove(idx);
        // SAFETY: we know we mapped this region with mmap (via
        // mach_vm_allocate). munmap is the right way to release it
        // because Region::Drop also uses munmap.
        let rc = unsafe { quantum_runtime::sys::munmap(address.cast(), len) };
        if rc == 0 { 1 } else { 0 }
    } else {
        0
    }
}

/// `BOOL VirtualProtect(LPVOID, SIZE_T, DWORD newProtect, PDWORD oldProtect)`.
#[unsafe(no_mangle)]
pub extern "C" fn VirtualProtect(
    address: *mut u8,
    size: usize,
    new_protect: u32,
    old_protect_out: *mut u32,
) -> i32 {
    if address.is_null() || size == 0 {
        return 0;
    }
    let prot = translate_protect(new_protect);
    let mem = MachVmManager::new();
    match mem.protect(address, size, prot) {
        Ok(()) => {
            if !old_protect_out.is_null() {
                // SAFETY: caller-supplied pointer.
                unsafe {
                    *old_protect_out = PAGE_READWRITE;
                }
            }
            1
        }
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_write_free() {
        let p = VirtualAlloc(
            core::ptr::null_mut(),
            4096,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        );
        assert!(!p.is_null());
        // SAFETY: 4 KiB writable.
        unsafe {
            for i in 0..4096 {
                *p.add(i) = (i & 0xFF) as u8;
            }
            for i in 0..4096 {
                assert_eq!(*p.add(i), (i & 0xFF) as u8);
            }
        }
        assert_eq!(VirtualFree(p, 0, MEM_RELEASE), 1);
    }

    #[test]
    fn protect_to_readonly() {
        let p = VirtualAlloc(
            core::ptr::null_mut(),
            4096,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        );
        assert!(!p.is_null());
        let mut old: u32 = 0;
        assert_eq!(VirtualProtect(p, 4096, PAGE_READONLY, &mut old), 1);
        // SAFETY: page is at least readable.
        unsafe {
            let _ = *p;
        }
        assert_eq!(VirtualFree(p, 0, MEM_RELEASE), 1);
    }
}

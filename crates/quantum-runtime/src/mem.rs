//! Guest virtual memory. Backed by mach_vm and (for JIT pages) mmap+MAP_JIT.
//!
//! Implementations live in this file — agents fill in the bodies, but the
//! signatures here are the contract every other crate codes against.

use core::ptr::NonNull;

use quantum_core::{Error, Result};

/// Page protection bits used by the guest, in Win32 PAGE_* spirit but kept
/// small. The host translator maps these to VM_PROT_* / PROT_*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protection(u8);

impl Protection {
    pub const NONE: Self = Self(0);
    pub const R: Self = Self(0b001);
    pub const RW: Self = Self(0b011);
    pub const RX: Self = Self(0b101);
    pub const RWX: Self = Self(0b111);

    pub const fn bits(self) -> u8 {
        self.0
    }
    pub const fn readable(self) -> bool {
        self.0 & 0b001 != 0
    }
    pub const fn writable(self) -> bool {
        self.0 & 0b010 != 0
    }
    pub const fn executable(self) -> bool {
        self.0 & 0b100 != 0
    }
}

/// Owned guest memory region. Drop unmaps.
#[derive(Debug)]
pub struct Region {
    base: NonNull<u8>,
    len: usize,
    is_jit: bool,
}

// SAFETY: a Region simply owns a host VM allocation; sending it across
// threads is fine because every access goes through &mut self.
unsafe impl Send for Region {}
unsafe impl Sync for Region {}

impl Region {
    pub fn base(&self) -> *mut u8 {
        self.base.as_ptr()
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn is_jit(&self) -> bool {
        self.is_jit
    }

    /// Construct from raw parts. Used by the implementation in this module
    /// after a successful host allocation. Not part of the public API.
    pub(crate) fn from_raw(base: NonNull<u8>, len: usize, is_jit: bool) -> Self {
        Self { base, len, is_jit }
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        // Best-effort unmap. Agents implementing `MemoryManager` must keep
        // the unmap path infallible from the caller's perspective.
        let _ = unsafe { crate::sys::munmap(self.base.as_ptr().cast(), self.len) };
    }
}

/// Page-granular guest VM manager. One instance per guest process.
///
/// All addresses returned are host-virtual but live inside the layout the
/// guest expects (e.g. honouring `image_base`). The JIT calls back into
/// `protect` to flip RW <-> RX pages on Apple Silicon.
pub trait MemoryManager: Send + Sync {
    /// Allocate `size` bytes of guest VM. If `hint` is `Some`, try to place
    /// the region at that address (returning an error if it conflicts).
    fn allocate(&self, hint: Option<u64>, size: usize, prot: Protection) -> Result<Region>;

    /// Allocate a JIT-capable code region (uses `MAP_JIT` on Apple Silicon).
    /// The returned region starts in RW state; call `flip_jit` to make it
    /// executable.
    fn allocate_jit(&self, size: usize) -> Result<Region>;

    /// Change protection on `[addr, addr+size)`. Address must be page-aligned.
    fn protect(&self, addr: *mut u8, size: usize, prot: Protection) -> Result<()>;

    /// On Apple Silicon, toggle the per-thread JIT write-protect bit and
    /// invalidate the i-cache for the given range. `writable=true` makes JIT
    /// pages writable (and non-executable); `false` makes them executable.
    fn flip_jit(&self, range: *mut u8, len: usize, writable: bool);
}

/// Default implementation backed by mach_vm + mmap.
pub struct MachVmManager {
    task: crate::sys::mach_port_t,
}

impl MachVmManager {
    pub fn new() -> Self {
        Self {
            task: unsafe { crate::sys::mach_task_self() },
        }
    }
}

impl Default for MachVmManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryManager for MachVmManager {
    fn allocate(&self, hint: Option<u64>, size: usize, prot: Protection) -> Result<Region> {
        use crate::sys::*;
        let mut addr: mach_vm_address_t = hint.unwrap_or(0);
        let flags = if hint.is_some() {
            VM_FLAGS_FIXED
        } else {
            VM_FLAGS_ANYWHERE
        };
        let kr = unsafe { mach_vm_allocate(self.task, &mut addr, size as u64, flags) };
        if kr != KERN_SUCCESS {
            return Err(Error::Host {
                syscall: "mach_vm_allocate",
                code: kr,
            });
        }
        // mach_vm_allocate gives RW. Adjust if caller asked for less or for X.
        if prot != Protection::RW {
            let host_prot = host_vm_prot(prot);
            let kr = unsafe { mach_vm_protect(self.task, addr, size as u64, 0, host_prot) };
            if kr != KERN_SUCCESS {
                let _ = unsafe { mach_vm_deallocate(self.task, addr, size as u64) };
                return Err(Error::Host {
                    syscall: "mach_vm_protect",
                    code: kr,
                });
            }
        }
        let nn = NonNull::new(addr as *mut u8).ok_or(Error::Host {
            syscall: "mach_vm_allocate(null)",
            code: 0,
        })?;
        Ok(Region::from_raw(nn, size, false))
    }

    fn allocate_jit(&self, size: usize) -> Result<Region> {
        use crate::sys::*;
        let ptr = unsafe {
            mmap(
                core::ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANON | MAP_JIT,
                -1,
                0,
            )
        };
        if ptr == MAP_FAILED {
            return Err(Error::Host {
                syscall: "mmap(MAP_JIT)",
                code: errno(),
            });
        }
        let nn = NonNull::new(ptr.cast::<u8>()).ok_or(Error::Host {
            syscall: "mmap(MAP_JIT,null)",
            code: 0,
        })?;
        Ok(Region::from_raw(nn, size, true))
    }

    fn protect(&self, addr: *mut u8, size: usize, prot: Protection) -> Result<()> {
        use crate::sys::*;
        let kr =
            unsafe { mach_vm_protect(self.task, addr as u64, size as u64, 0, host_vm_prot(prot)) };
        if kr != KERN_SUCCESS {
            return Err(Error::Host {
                syscall: "mach_vm_protect",
                code: kr,
            });
        }
        Ok(())
    }

    fn flip_jit(&self, range: *mut u8, len: usize, writable: bool) {
        unsafe {
            crate::sys::pthread_jit_write_protect_np(if writable { 0 } else { 1 });
            if !writable {
                crate::sys::sys_icache_invalidate(range.cast(), len);
            }
        }
    }
}

fn host_vm_prot(p: Protection) -> crate::sys::vm_prot_t {
    use crate::sys::*;
    let mut v: vm_prot_t = VM_PROT_NONE;
    if p.readable() {
        v |= VM_PROT_READ;
    }
    if p.writable() {
        v |= VM_PROT_WRITE;
    }
    if p.executable() {
        v |= VM_PROT_EXECUTE;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_then_drop_roundtrip() {
        let m = MachVmManager::new();
        let r = m.allocate(None, 4096, Protection::RW).expect("alloc");
        assert_eq!(r.len(), 4096);
        unsafe {
            // Write and read back a byte.
            r.base().write(0xAB);
            assert_eq!(r.base().read(), 0xAB);
        }
    }

    #[test]
    fn protect_to_readonly_then_back() {
        let m = MachVmManager::new();
        let r = m.allocate(None, 4096, Protection::RW).expect("alloc");
        m.protect(r.base(), 4096, Protection::R).expect("ro");
        m.protect(r.base(), 4096, Protection::RW).expect("rw");
    }
}

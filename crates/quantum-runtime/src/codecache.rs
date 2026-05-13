//! JIT code cache. A growable RWX region (MAP_JIT on Apple Silicon)
//! that owns the host-side bytes of every translated guest basic block.
//!
//! Writers call `install` with a freshly assembled sequence of bytes;
//! the cache flips the page to writable, copies bytes, flips back to
//! executable, invalidates the i-cache for the range, and returns a
//! function pointer suitable for `transmute`-ing to the trampoline
//! signature.

use core::ptr::NonNull;

use quantum_core::{Error, Result};

use crate::mem::{MachVmManager, MemoryManager, Region};

pub struct CodeCache {
    region: Region,
    used: usize,
    mem: MachVmManager,
}

impl CodeCache {
    /// Allocate a JIT-capable region. `capacity` is rounded up to a
    /// page boundary by the kernel.
    pub fn new(capacity: usize) -> Result<Self> {
        let mem = MachVmManager::new();
        let region = mem.allocate_jit(capacity)?;
        Ok(Self {
            region,
            used: 0,
            mem,
        })
    }

    pub fn capacity(&self) -> usize {
        self.region.len()
    }

    pub fn used(&self) -> usize {
        self.used
    }

    /// Copy `bytes` into the cache and return a pointer to the start of
    /// the installed code. The pointer is RX-executable on return.
    pub fn install(&mut self, bytes: &[u8]) -> Result<NonNull<u8>> {
        if self.used + bytes.len() > self.region.len() {
            return Err(Error::Host {
                syscall: "codecache:install (oversize)",
                code: 0,
            });
        }
        // The whole MAP_JIT region's page protection is RWX, but the
        // hardware uses a per-thread mode (W^X) flipped via
        // pthread_jit_write_protect_np. Make it writable, write, then
        // flip back to executable and invalidate the i-cache for the
        // range we touched.
        // SAFETY: Region.base() is a valid host pointer for `region.len()`
        // bytes throughout the lifetime of `self`.
        let dst = unsafe { self.region.base().add(self.used) };
        self.mem.flip_jit(dst, bytes.len(), true);
        // SAFETY: `dst..dst+bytes.len()` is within the owned region.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
        }
        self.mem.flip_jit(dst, bytes.len(), false);
        self.used += bytes.len();
        // Round up to instruction alignment (4 bytes on AArch64) so the
        // next install starts on a valid boundary.
        let pad = (4 - (self.used & 3)) & 3;
        self.used += pad;
        Ok(NonNull::new(dst).expect("non-null"))
    }

    pub fn base(&self) -> *mut u8 {
        self.region.base()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the bytes for `mov x0, #imm; ret` and run them as a host
    /// function. This exercises the entire MAP_JIT → W^X flip → execute
    /// pipeline; failure here means codesigning or the entitlement is
    /// missing.
    #[test]
    fn live_executes_mov_x0_ret() {
        // movz x0, #imm16 -> sf=1, opc=10, hw=00, imm16, Rd=0
        //   = 0xD2800000 | (imm16 << 5)
        // ret -> 0xD65F03C0
        let imm: u16 = 0x4A2B;
        let movz = 0xD280_0000u32 | ((imm as u32) << 5);
        let ret = 0xD65F_03C0u32;
        let mut bytes = [0u8; 8];
        bytes[0..4].copy_from_slice(&movz.to_le_bytes());
        bytes[4..8].copy_from_slice(&ret.to_le_bytes());

        let mut cache = CodeCache::new(4096).expect("cache");
        let p = cache.install(&bytes).expect("install");
        // SAFETY: the installed code is `mov x0, #imm; ret` so the host
        // sees a `extern "C" fn() -> u64` with no side effects.
        let f: extern "C" fn() -> u64 = unsafe { core::mem::transmute(p.as_ptr()) };
        assert_eq!(f(), imm as u64);
    }
}

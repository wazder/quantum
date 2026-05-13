//! Build guest-readable `PEB` and `TEB` structures in real guest VM.
//!
//! Most Win64 programs touch the TEB through `gs:[…]` before they run
//! any real code (the MSVC C runtime, in particular, reads
//! `gs:[0x60]` for the PEB pointer, walks `PEB.Ldr` to find loaded
//! modules, and checks `PEB.ProcessHeap` against the heap the guest
//! is allowed to use). We allocate two pages of guest VM, fill the
//! well-known fields, and hand back the addresses.
//!
//! Today we only populate the fields a CLI-class guest's CRT
//! actually reads. Games will need ImageBase / Ldr lists, PEB image
//! callbacks, KUSER_SHARED_DATA — added when a real guest demands
//! them.

use core::ptr::write_unaligned;

use quantum_core::Result;

use crate::mem::{MachVmManager, MemoryManager, Protection, Region};

/// Offset of `TEB.NtTib.Self` within the TEB. Mirrors winnt.h.
const TEB_OFF_SELF: usize = 0x30;
/// Offset of `TEB.ProcessEnvironmentBlock`.
const TEB_OFF_PEB: usize = 0x60;
/// Offset of `TEB.LastErrorValue`.
const TEB_OFF_LAST_ERROR: usize = 0x68;
/// Offset of `TEB.ThreadId`.
const TEB_OFF_THREAD_ID: usize = 0x48;

/// Offset of `PEB.ImageBaseAddress`.
const PEB_OFF_IMAGE_BASE: usize = 0x10;
/// Offset of `PEB.ProcessHeap`.
const PEB_OFF_PROCESS_HEAP: usize = 0x30;

#[derive(Debug)]
pub struct ProcessControlBlock {
    /// Guest VA at which the PEB lives.
    pub peb_addr: u64,
    /// Guest VA at which the (single) TEB lives.
    pub teb_addr: u64,
    /// Owned backing storage. Dropping reclaims both pages.
    _backing: Region,
}

impl ProcessControlBlock {
    /// Allocate two pages (the kernel rounds to its native page size,
    /// 16 KiB on Apple Silicon) and lay out a minimal TEB followed by
    /// a PEB.
    ///
    /// `image_base` should be the actual load address of the main
    /// image — the loader writes this after relocating. `process_heap`
    /// is the handle quantum_kernel32 returns from `GetProcessHeap`
    /// (the guest reads this back through `PEB.ProcessHeap`).
    pub fn new(image_base: u64, process_heap: usize, thread_id: u32) -> Result<Self> {
        let mem = MachVmManager::new();
        // 16 KiB is enough for both structures; mach_vm rounds anyway.
        let region = mem.allocate(None, 16 * 1024, Protection::RW)?;
        let base = region.base() as u64;
        let teb_addr = base;
        // Lay the PEB out 4 KiB later so guests doing speculative
        // PEB-relative reads don't bleed into the TEB.
        let peb_addr = base + 0x1000;

        // SAFETY: We own the region for at least 16 KiB; both writes
        // are within bounds and use `write_unaligned` to be safe
        // against any future alignment surprises.
        unsafe {
            let teb = region.base();
            // TEB.NtTib.Self -> own address
            write_unaligned(teb.add(TEB_OFF_SELF).cast::<u64>(), teb_addr);
            // TEB.ProcessEnvironmentBlock -> peb_addr
            write_unaligned(teb.add(TEB_OFF_PEB).cast::<u64>(), peb_addr);
            // TEB.LastErrorValue = 0
            write_unaligned(teb.add(TEB_OFF_LAST_ERROR).cast::<u32>(), 0);
            // TEB.ThreadId
            write_unaligned(teb.add(TEB_OFF_THREAD_ID).cast::<u64>(), thread_id as u64);

            let peb = teb.add(0x1000);
            // PEB.ImageBaseAddress
            write_unaligned(peb.add(PEB_OFF_IMAGE_BASE).cast::<u64>(), image_base);
            // PEB.ProcessHeap
            write_unaligned(
                peb.add(PEB_OFF_PROCESS_HEAP).cast::<u64>(),
                process_heap as u64,
            );
        }

        Ok(Self {
            peb_addr,
            teb_addr,
            _backing: region,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn teb_self_and_peb_pointers_are_consistent() {
        let pcb = ProcessControlBlock::new(0x1_4000_0000, 0xDEAD_BEEF, 0x1234).expect("alloc");
        // SAFETY: pcb owns the backing region for the duration of the test.
        unsafe {
            let teb = pcb.teb_addr as *const u8;
            let self_ptr = teb.add(TEB_OFF_SELF).cast::<u64>().read_unaligned();
            assert_eq!(self_ptr, pcb.teb_addr);
            let peb_ptr = teb.add(TEB_OFF_PEB).cast::<u64>().read_unaligned();
            assert_eq!(peb_ptr, pcb.peb_addr);
            let thread_id = teb.add(TEB_OFF_THREAD_ID).cast::<u64>().read_unaligned();
            assert_eq!(thread_id, 0x1234);

            let peb = pcb.peb_addr as *const u8;
            let image_base = peb.add(PEB_OFF_IMAGE_BASE).cast::<u64>().read_unaligned();
            assert_eq!(image_base, 0x1_4000_0000);
            let heap = peb.add(PEB_OFF_PROCESS_HEAP).cast::<u64>().read_unaligned();
            assert_eq!(heap, 0xDEAD_BEEF);
        }
    }
}

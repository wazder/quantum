//! Mapping a parsed PE into guest memory.
//!
//! `load` allocates `size_of_image` bytes via the supplied
//! `MemoryManager`, copies the headers and each section into place,
//! and returns a `LoadedImage` that everyone else (`reloc`, `imports`,
//! the JIT) walks via RVA. The bytes are owned through `Region`, so
//! dropping the `LoadedImage` reclaims guest VM.
//!
//! Per-section protection is applied *after* relocation. The caller
//! calls `finalize_protections` once the IAT and base relocations have
//! been wired up. Until then the whole image is RW.

use alloc::vec::Vec;

use quantum_core::{Error, Result};
use quantum_runtime::{MemoryManager, Protection, Region};

use crate::pe::{DataDirectory, PeFile, SectionHeader};

/// PE Section characteristics bits we care about. Mirrors winnt.h
/// `IMAGE_SCN_MEM_*` constants exactly.
pub mod scn {
    pub const MEM_EXECUTE: u32 = 0x2000_0000;
    pub const MEM_READ: u32 = 0x4000_0000;
    pub const MEM_WRITE: u32 = 0x8000_0000;
    pub const CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
    pub const MEM_DISCARDABLE: u32 = 0x0200_0000;
}

#[derive(Debug, Clone, Copy)]
pub struct MappedSection {
    pub name: [u8; 8],
    pub rva: u32,
    pub vsize: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

impl MappedSection {
    pub fn name_str(&self) -> &str {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        core::str::from_utf8(&self.name[..end]).unwrap_or("?")
    }

    pub fn protection(&self) -> Protection {
        let c = self.characteristics;
        let r = (c & scn::MEM_READ) != 0;
        let w = (c & scn::MEM_WRITE) != 0;
        let x = (c & scn::MEM_EXECUTE) != 0;
        match (r, w, x) {
            (_, true, true) => Protection::RWX,
            (_, true, false) => Protection::RW,
            (_, false, true) => Protection::RX,
            (true, false, false) => Protection::R,
            (false, false, false) => Protection::NONE,
        }
    }

    pub fn contains_rva(&self, rva: u32) -> bool {
        rva >= self.rva && rva < self.rva.saturating_add(self.vsize.max(self.raw_size))
    }
}

/// Width of the guest ISA the image was compiled for. PE32 → 32-bit,
/// PE32+ → 64-bit. We re-export it from the loader so the JIT can
/// pick the right decoder rules without having to keep the original
/// `PeFile` alive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bitness {
    X86,
    X86_64,
}

#[derive(Debug)]
pub struct LoadedImage {
    region: Region,
    pub preferred_base: u64,
    pub actual_base: u64,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub entry_rva: u32,
    pub subsystem: u16,
    pub bitness: Bitness,
    pub sections: Vec<MappedSection>,
    pub data_directories: [DataDirectory; 16],
}

// SAFETY: LoadedImage wraps a `Region` whose `*mut u8` is the base of a
// VM mapping owned for the lifetime of the image. After construction the
// only mutators are `rva_to_slice_mut` and `apply_relocations`/IAT-wire,
// all of which take `&mut self` and run synchronously on the main thread
// before any worker thread is spawned. Once a worker thread holds an
// `Arc<LoadedImage>`, only `&self` methods are reachable, so concurrent
// access is to *immutable* mapped memory. That's safe to share.
unsafe impl Send for LoadedImage {}
unsafe impl Sync for LoadedImage {}

impl LoadedImage {
    pub fn base(&self) -> *mut u8 {
        self.region.base()
    }

    pub fn len(&self) -> usize {
        self.region.len()
    }

    pub fn is_empty(&self) -> bool {
        self.region.len() == 0
    }

    /// Get a raw pointer to `rva`. Returns `None` if the RVA is outside
    /// the image. Bounds-checked against `size_of_image` rather than any
    /// particular section so headers and gaps remain reachable.
    pub fn rva_to_ptr(&self, rva: u32) -> Option<*mut u8> {
        if (rva as usize) >= self.region.len() {
            return None;
        }
        // SAFETY: rva is in-bounds for the region; pointer arithmetic
        // within an allocation is well-defined.
        Some(unsafe { self.region.base().add(rva as usize) })
    }

    /// Borrow `len` bytes at `rva`. Range-checked.
    pub fn rva_to_slice(&self, rva: u32, len: usize) -> Option<&[u8]> {
        let end = (rva as usize).checked_add(len)?;
        if end > self.region.len() {
            return None;
        }
        // SAFETY: slice is fully contained in the owned region and the
        // region is alive for at least `&self`.
        Some(unsafe { core::slice::from_raw_parts(self.region.base().add(rva as usize), len) })
    }

    /// Mutably borrow `len` bytes at `rva`. Range-checked.
    pub fn rva_to_slice_mut(&mut self, rva: u32, len: usize) -> Option<&mut [u8]> {
        let end = (rva as usize).checked_add(len)?;
        if end > self.region.len() {
            return None;
        }
        // SAFETY: see `rva_to_slice`. `&mut self` ensures no aliasing.
        Some(unsafe { core::slice::from_raw_parts_mut(self.region.base().add(rva as usize), len) })
    }

    /// Find the section that contains `rva`, if any.
    pub fn section_at(&self, rva: u32) -> Option<&MappedSection> {
        self.sections.iter().find(|s| s.contains_rva(rva))
    }

    pub fn data_dir(&self, index: usize) -> Option<DataDirectory> {
        self.data_directories
            .get(index)
            .copied()
            .filter(|d| d.virtual_address != 0 && d.size != 0)
    }

    /// Apply each section's `IMAGE_SCN_MEM_*` bits as host VM protections.
    /// Section RVAs are rounded down / sizes rounded up to the host page.
    pub fn finalize_protections(&self, mem: &dyn MemoryManager) -> Result<()> {
        let page = host_page_size();
        for s in &self.sections {
            let prot = s.protection();
            let start_rva = (s.rva as usize) & !(page - 1);
            let end_rva = align_up((s.rva as usize) + s.vsize.max(s.raw_size) as usize, page);
            let len = end_rva - start_rva;
            if len == 0 {
                continue;
            }
            // SAFETY: pointer derived from the same allocation.
            let p = unsafe { self.region.base().add(start_rva) };
            mem.protect(p, len, prot)?;
        }
        Ok(())
    }
}

fn host_page_size() -> usize {
    // Apple Silicon uses 16 KiB pages in user space; Intel macOS uses 4 KiB.
    // We always round to the larger to stay safe on both.
    16 * 1024
}

fn align_up(x: usize, align: usize) -> usize {
    (x + align - 1) & !(align - 1)
}

/// Load a parsed PE file into guest VM. Tries `preferred_base` first;
/// on failure (address already mapped or kernel rejection) falls back to
/// `ANYWHERE`. Callers then run base relocations themselves.
pub fn load(pe: &PeFile<'_>, mem: &dyn MemoryManager) -> Result<LoadedImage> {
    let size = pe.opt.size_of_image as usize;
    if size == 0 || size > 2 * 1024 * 1024 * 1024 {
        return Err(Error::Malformed {
            what: "size_of_image",
            at: 0,
        });
    }

    // Allocate. Start RW so we can scribble headers and section data.
    let region = match mem.allocate(Some(pe.opt.image_base), size, Protection::RW) {
        Ok(r) => r,
        Err(_) => mem.allocate(None, size, Protection::RW)?,
    };

    // Copy headers (everything up to SizeOfHeaders).
    let headers_len = pe.opt.size_of_headers as usize;
    if headers_len > region.len() {
        return Err(Error::Malformed {
            what: "size_of_headers",
            at: 0,
        });
    }
    let raw = pe.raw();
    let copy_from_header = headers_len.min(raw.len());
    // SAFETY: in-bounds writes into the owned region.
    unsafe {
        core::ptr::copy_nonoverlapping(raw.as_ptr(), region.base(), copy_from_header);
        if copy_from_header < headers_len {
            core::ptr::write_bytes(
                region.base().add(copy_from_header),
                0,
                headers_len - copy_from_header,
            );
        }
    }

    // Copy each section.
    let mut sections: Vec<MappedSection> = Vec::with_capacity(pe.coff.number_of_sections as usize);
    for sh in pe.sections() {
        copy_section(&sh, raw, &region)?;
        sections.push(MappedSection {
            name: sh.name,
            rva: sh.virtual_address,
            vsize: sh.virtual_size,
            raw_size: sh.size_of_raw_data,
            characteristics: sh.characteristics,
        });
    }

    let actual_base = region.base() as u64;

    let bitness = match pe.opt.kind {
        crate::pe::PeKind::Pe32 => Bitness::X86,
        crate::pe::PeKind::Pe32Plus => Bitness::X86_64,
    };

    Ok(LoadedImage {
        region,
        preferred_base: pe.opt.image_base,
        actual_base,
        size_of_image: pe.opt.size_of_image,
        size_of_headers: pe.opt.size_of_headers,
        entry_rva: pe.opt.address_of_entry_point,
        subsystem: pe.opt.subsystem,
        bitness,
        sections,
        data_directories: pe.opt.data_directories,
    })
}

fn copy_section(sh: &SectionHeader, raw: &[u8], region: &Region) -> Result<()> {
    let dst_off = sh.virtual_address as usize;
    let vsize = sh.virtual_size.max(sh.size_of_raw_data) as usize;
    if dst_off
        .checked_add(vsize)
        .map(|e| e > region.len())
        .unwrap_or(true)
    {
        return Err(Error::Malformed {
            what: "section virtual range",
            at: dst_off,
        });
    }

    let raw_off = sh.pointer_to_raw_data as usize;
    let raw_size = sh.size_of_raw_data as usize;

    // SAFETY: in-bounds writes into the owned region.
    unsafe {
        let dst = region.base().add(dst_off);
        if raw_size > 0 {
            let src_end = raw_off.checked_add(raw_size).ok_or(Error::Malformed {
                what: "section raw range",
                at: raw_off,
            })?;
            if src_end > raw.len() {
                return Err(Error::Malformed {
                    what: "section raw oob",
                    at: raw_off,
                });
            }
            core::ptr::copy_nonoverlapping(raw.as_ptr().add(raw_off), dst, raw_size);
        }
        // Zero-fill BSS (virtual_size > raw_size).
        if vsize > raw_size {
            core::ptr::write_bytes(dst.add(raw_size), 0, vsize - raw_size);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::PeFile;
    use alloc::vec;
    use alloc::vec::Vec;
    use quantum_runtime::MachVmManager;
    extern crate std;

    /// Build a tiny valid PE32+ that the loader can actually map. Single
    /// `.text` section with a known byte pattern at `+0` of its raw data.
    fn build_pe() -> Vec<u8> {
        let mut v = vec![0u8; 0x800];
        v[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes()); // MZ
        v[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let pe = 0x80;
        v[pe..pe + 4].copy_from_slice(&0x0000_4550u32.to_le_bytes());
        let coff = pe + 4;
        v[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        v[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        v[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
        v[coff + 18..coff + 20].copy_from_slice(&0x22u16.to_le_bytes());
        let opt = coff + 20;
        v[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
        v[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry
        v[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes()); // image base
        v[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // sec align
        v[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file align
        v[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // size of image
        v[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes()); // size of headers
        v[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // subsystem
        v[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // num rva

        let sec = opt + 240;
        v[sec..sec + 5].copy_from_slice(b".text");
        v[sec + 8..sec + 12].copy_from_slice(&0x10u32.to_le_bytes()); // vsize
        v[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // rva
        v[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
        v[sec + 20..sec + 24].copy_from_slice(&0x400u32.to_le_bytes()); // raw ptr
        v[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // CODE|EXEC|READ

        // Section raw data: 16 bytes starting at offset 0x400.
        for i in 0..16 {
            v[0x400 + i] = (i as u8) ^ 0xA5;
        }
        v
    }

    #[test]
    fn maps_image_and_copies_section() {
        let bytes = build_pe();
        let pe = PeFile::parse(&bytes).expect("parse");
        let mem = MachVmManager::new();
        let img = load(&pe, &mem).expect("load");

        assert_eq!(img.size_of_image, 0x2000);
        assert_eq!(img.entry_rva, 0x1000);
        assert_eq!(img.sections.len(), 1);
        assert_eq!(img.sections[0].name_str(), ".text");

        // Section content should be at RVA 0x1000.
        let s = img.rva_to_slice(0x1000, 16).expect("slice");
        for (i, b) in s.iter().enumerate() {
            assert_eq!(*b, (i as u8) ^ 0xA5);
        }

        // BSS region of the section (vsize > raw_size? here equal, so skip).
        // Verify protection mapping works.
        img.finalize_protections(&mem).expect("protect");
    }

    #[test]
    fn protection_translates_section_flags() {
        let mut s = MappedSection {
            name: *b".text\0\0\0",
            rva: 0,
            vsize: 0,
            raw_size: 0,
            characteristics: 0,
        };
        s.characteristics = scn::MEM_READ | scn::MEM_EXECUTE;
        assert_eq!(s.protection(), Protection::RX);
        s.characteristics = scn::MEM_READ | scn::MEM_WRITE;
        assert_eq!(s.protection(), Protection::RW);
        s.characteristics = scn::MEM_READ;
        assert_eq!(s.protection(), Protection::R);
        s.characteristics = scn::MEM_READ | scn::MEM_WRITE | scn::MEM_EXECUTE;
        assert_eq!(s.protection(), Protection::RWX);
    }
}

//! Base relocations.
//!
//! Format reference: PE spec, "The .reloc Section". Each block starts with
//! `IMAGE_BASE_RELOCATION { VirtualAddress: u32, SizeOfBlock: u32 }`
//! followed by `(SizeOfBlock - 8) / 2` u16 entries. Top 4 bits of each
//! entry = relocation type; bottom 12 bits = offset within the page.

use quantum_core::{Error, Result};

use crate::image::LoadedImage;
use crate::pe::dir;

pub const REL_ABSOLUTE: u16 = 0;
pub const REL_HIGH: u16 = 1;
pub const REL_LOW: u16 = 2;
pub const REL_HIGHLOW: u16 = 3;
pub const REL_HIGHADJ: u16 = 4;
pub const REL_DIR64: u16 = 10;

#[derive(Debug, Default, Clone, Copy)]
pub struct RelocStats {
    pub blocks: u32,
    pub absolute: u32,
    pub dir64: u32,
    pub highlow: u32,
}

/// Apply base relocations against the supplied delta
/// (`actual_base - preferred_base`). Idempotent if delta is zero.
pub fn apply(image: &mut LoadedImage) -> Result<RelocStats> {
    let delta = image
        .actual_base
        .wrapping_sub(image.preferred_base);
    if delta == 0 {
        return Ok(RelocStats::default());
    }

    let dir = match image.data_dir(dir::BASERELOC) {
        Some(d) => d,
        None => return Ok(RelocStats::default()),
    };

    let mut stats = RelocStats::default();
    let mut cursor = dir.virtual_address;
    let end = dir.virtual_address.saturating_add(dir.size);

    while cursor < end {
        let header = image
            .rva_to_slice(cursor, 8)
            .ok_or(Error::Malformed { what: "reloc block header", at: cursor as usize })?;
        let page_rva = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let block_size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        if block_size < 8 {
            return Err(Error::Malformed { what: "reloc block_size < 8", at: cursor as usize });
        }
        if cursor.saturating_add(block_size) > end {
            return Err(Error::Malformed { what: "reloc block past dir", at: cursor as usize });
        }

        stats.blocks += 1;

        let entry_count = ((block_size - 8) / 2) as usize;
        let entries_off = cursor + 8;
        // We need to grab entry bytes immutably, then apply mutably below.
        // Snapshot them so we don't alias the image while writing.
        let mut entries = [0u16; 4096 / 2];
        if entry_count > entries.len() {
            return Err(Error::Malformed { what: "reloc block oversized", at: cursor as usize });
        }
        {
            let raw = image
                .rva_to_slice(entries_off, entry_count * 2)
                .ok_or(Error::Malformed { what: "reloc entries", at: entries_off as usize })?;
            for i in 0..entry_count {
                entries[i] = u16::from_le_bytes([raw[i * 2], raw[i * 2 + 1]]);
            }
        }

        for &raw in &entries[..entry_count] {
            let ty = (raw >> 12) & 0xF;
            let off = (raw & 0x0FFF) as u32;
            let target_rva = page_rva.saturating_add(off);
            match ty {
                REL_ABSOLUTE => {
                    stats.absolute += 1;
                }
                REL_DIR64 => {
                    let slot = image
                        .rva_to_slice_mut(target_rva, 8)
                        .ok_or(Error::Malformed { what: "DIR64 oob", at: target_rva as usize })?;
                    let old = u64::from_le_bytes(slot.try_into().unwrap());
                    let new = old.wrapping_add(delta);
                    slot.copy_from_slice(&new.to_le_bytes());
                    stats.dir64 += 1;
                }
                REL_HIGHLOW => {
                    let slot = image
                        .rva_to_slice_mut(target_rva, 4)
                        .ok_or(Error::Malformed { what: "HIGHLOW oob", at: target_rva as usize })?;
                    let old = u32::from_le_bytes(slot.try_into().unwrap());
                    let new = old.wrapping_add(delta as u32);
                    slot.copy_from_slice(&new.to_le_bytes());
                    stats.highlow += 1;
                }
                _ => {
                    return Err(Error::Unsupported(
                        "unsupported base relocation type (HIGH/LOW/HIGHADJ are PE32-era)",
                    ));
                }
            }
        }

        cursor = cursor.saturating_add(block_size);
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::load;
    use crate::pe::PeFile;
    use alloc::vec;
    use alloc::vec::Vec;
    use quantum_runtime::MachVmManager;

    /// Build a PE32+ image with one .reloc DIR64 entry targeting a slot we
    /// can inspect after the loader applies relocations.
    fn build_pe_with_reloc(preferred_base: u64) -> Vec<u8> {
        let mut v = vec![0u8; 0x1000];
        v[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes());
        v[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let pe = 0x80;
        v[pe..pe + 4].copy_from_slice(&0x0000_4550u32.to_le_bytes());
        let coff = pe + 4;
        v[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        v[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes()); // .text + .reloc
        v[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
        v[coff + 18..coff + 20].copy_from_slice(&0x22u16.to_le_bytes());
        let opt = coff + 20;
        v[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
        v[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        v[opt + 24..opt + 32].copy_from_slice(&preferred_base.to_le_bytes());
        v[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        v[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        v[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // size of image
        v[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
        v[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
        v[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

        // Data directory entry [5] (BASERELOC) points at RVA 0x2000, size 0x0C
        // (one block: 8 byte header + 2 entries [DIR64 + ABSOLUTE pad]).
        let dd5_off = opt + 112 + 5 * 8;
        v[dd5_off..dd5_off + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        v[dd5_off + 4..dd5_off + 8].copy_from_slice(&0x0Cu32.to_le_bytes());

        // .text section
        let sec = opt + 240;
        v[sec..sec + 5].copy_from_slice(b".text");
        v[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes());
        v[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        v[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes());
        v[sec + 20..sec + 24].copy_from_slice(&0x400u32.to_le_bytes());
        v[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

        // .reloc section header
        let sec2 = sec + 40;
        v[sec2..sec2 + 6].copy_from_slice(b".reloc");
        v[sec2 + 8..sec2 + 12].copy_from_slice(&0x10u32.to_le_bytes());
        v[sec2 + 12..sec2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        v[sec2 + 16..sec2 + 20].copy_from_slice(&0x200u32.to_le_bytes());
        v[sec2 + 20..sec2 + 24].copy_from_slice(&0x600u32.to_le_bytes());
        v[sec2 + 36..sec2 + 40].copy_from_slice(&0x4200_0040u32.to_le_bytes()); // INIT_DATA|READ|DISCARDABLE

        // Place a relocatable 64-bit pointer inside .text at file 0x408 (RVA 0x1008)
        // initialized to (preferred_base + 0x1234).
        v[0x408..0x410].copy_from_slice(&(preferred_base + 0x1234).to_le_bytes());

        // .reloc raw data at file 0x600
        v[0x600..0x604].copy_from_slice(&0x1000u32.to_le_bytes()); // page RVA
        v[0x604..0x608].copy_from_slice(&0x0Cu32.to_le_bytes()); // block size
        // Entry 0: type=DIR64 (10) << 12 | offset 0x008
        v[0x608..0x60A].copy_from_slice(&((REL_DIR64 << 12) | 0x008).to_le_bytes());
        // Entry 1: ABSOLUTE (pad)
        v[0x60A..0x60C].copy_from_slice(&0u16.to_le_bytes());

        v
    }

    #[test]
    fn dir64_relocation_applied_when_base_changes() {
        let preferred = 0x1_4000_0000u64;
        let bytes = build_pe_with_reloc(preferred);
        let pe = PeFile::parse(&bytes).expect("parse");
        let mem = MachVmManager::new();
        let mut img = load(&pe, &mem).expect("load");

        // Force a known, non-zero delta so the test exercises the apply path
        // regardless of whether mach_vm honoured the preferred image base.
        let delta: u64 = 0x10_0000;
        img.actual_base = img.preferred_base.wrapping_add(delta);

        let pointer_rva = 0x1008u32;
        let before = u64::from_le_bytes(
            img.rva_to_slice(pointer_rva, 8).unwrap().try_into().unwrap(),
        );
        assert_eq!(before, preferred + 0x1234);

        let stats = apply(&mut img).expect("apply");
        assert_eq!(stats.blocks, 1);
        assert_eq!(stats.dir64, 1);
        assert_eq!(stats.absolute, 1);

        let after = u64::from_le_bytes(
            img.rva_to_slice(pointer_rva, 8).unwrap().try_into().unwrap(),
        );
        assert_eq!(after, (preferred + 0x1234).wrapping_add(delta));
    }

    #[test]
    fn no_op_when_no_delta() {
        // Make preferred base match anywhere allocation by manually equating
        // actual=preferred after the fact: easiest path is to verify the
        // early-return branch via inspecting stats.
        let bytes = build_pe_with_reloc(0x1_4000_0000);
        let pe = PeFile::parse(&bytes).expect("parse");
        let mem = MachVmManager::new();
        let mut img = load(&pe, &mem).expect("load");
        img.actual_base = img.preferred_base;
        let stats = apply(&mut img).expect("apply");
        assert_eq!(stats.blocks, 0);
        assert_eq!(stats.dir64, 0);
    }
}

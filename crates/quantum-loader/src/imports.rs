//! Import directory parsing.
//!
//! The import directory is an array of `IMAGE_IMPORT_DESCRIPTOR`s
//! terminated by an all-zero descriptor:
//!
//! ```text
//! struct IMAGE_IMPORT_DESCRIPTOR {
//!   u32 OriginalFirstThunk; // RVA -> ILT (Import Lookup Table)
//!   u32 TimeDateStamp;
//!   u32 ForwarderChain;
//!   u32 Name;               // RVA -> ASCII DLL name
//!   u32 FirstThunk;         // RVA -> IAT (Import Address Table)
//! }
//! ```
//!
//! ILT and IAT are parallel arrays of u64 thunks (for PE32+). Each thunk:
//!   - high bit set : import by ordinal, low 16 bits = ordinal
//!   - high bit clr : RVA -> IMAGE_IMPORT_BY_NAME { u16 Hint; char Name[]; }
//!
//! At load time the loader fills the IAT slots in place; the IAT is what
//! call sites in `.text` reference (via `call [rip + iat_disp]`).

use alloc::string::String;
use alloc::vec::Vec;

use quantum_core::{Error, Result};

use crate::image::LoadedImage;
use crate::pe::dir;

const IMPORT_DESCRIPTOR_SIZE: u32 = 20;
const IMPORT_BY_ORDINAL_FLAG_64: u64 = 1u64 << 63;
const IMPORT_ORDINAL_MASK_64: u64 = 0xFFFF;

#[derive(Debug, Clone)]
pub struct ImportTable {
    pub dlls: Vec<DllImports>,
}

#[derive(Debug, Clone)]
pub struct DllImports {
    pub name: String,
    pub iat_rva: u32,
    pub ilt_rva: u32,
    pub entries: Vec<ImportEntry>,
}

#[derive(Debug, Clone)]
pub enum ImportEntry {
    /// Import by name (or hint + name).
    Name {
        hint: u16,
        name: String,
        /// Byte offset of the corresponding IAT slot inside the image.
        iat_slot_rva: u32,
    },
    /// Import by ordinal only.
    Ordinal {
        ordinal: u16,
        iat_slot_rva: u32,
    },
}

impl ImportEntry {
    pub fn iat_slot_rva(&self) -> u32 {
        match self {
            Self::Name { iat_slot_rva, .. } | Self::Ordinal { iat_slot_rva, .. } => *iat_slot_rva,
        }
    }
}

pub fn parse(image: &LoadedImage) -> Result<ImportTable> {
    parse_with_directory(image, dir::IMPORT)
}

/// Walk every import and stamp the resolved host address into its IAT
/// slot. The resolver receives `(dll, name)` for named imports and
/// `(dll, "#NNN")` for ordinal imports. A resolver returning `None`
/// fails the wiring.
pub fn wire_iat<F>(image: &mut LoadedImage, imports: &ImportTable, mut resolver: F) -> Result<()>
where
    F: FnMut(&str, &str) -> Option<u64>,
{
    use alloc::string::String;
    for dll in &imports.dlls {
        for entry in &dll.entries {
            let lookup_name: String = match entry {
                ImportEntry::Name { name, .. } => name.clone(),
                ImportEntry::Ordinal { ordinal, .. } => {
                    let mut s = String::from("#");
                    s.push_str(&alloc::format!("{ordinal}"));
                    s
                }
            };
            let target = resolver(&dll.name, &lookup_name).ok_or_else(|| Error::Malformed {
                what: "unresolved import",
                at: entry.iat_slot_rva() as usize,
            })?;
            let slot = image
                .rva_to_slice_mut(entry.iat_slot_rva(), 8)
                .ok_or(Error::Malformed {
                    what: "iat slot oob",
                    at: entry.iat_slot_rva() as usize,
                })?;
            slot.copy_from_slice(&target.to_le_bytes());
        }
    }
    Ok(())
}

pub(crate) fn parse_with_directory(image: &LoadedImage, directory: usize) -> Result<ImportTable> {
    let dir = match image.data_dir(directory) {
        Some(d) => d,
        None => return Ok(ImportTable { dlls: Vec::new() }),
    };

    let mut dlls = Vec::new();
    let mut cursor = dir.virtual_address;
    let end = dir.virtual_address.saturating_add(dir.size);

    loop {
        if cursor.saturating_add(IMPORT_DESCRIPTOR_SIZE) > end {
            return Err(Error::Malformed {
                what: "import descriptor past directory",
                at: cursor as usize,
            });
        }
        let bytes = image
            .rva_to_slice(cursor, IMPORT_DESCRIPTOR_SIZE as usize)
            .ok_or(Error::Malformed { what: "import descriptor", at: cursor as usize })?;

        let original_first_thunk = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let name_rva = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let first_thunk = u32::from_le_bytes(bytes[16..20].try_into().unwrap());

        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        let dll_name = read_cstr(image, name_rva)?;
        let entries = parse_thunk_array(image, original_first_thunk, first_thunk)?;

        dlls.push(DllImports {
            name: dll_name,
            iat_rva: first_thunk,
            ilt_rva: original_first_thunk,
            entries,
        });

        cursor = cursor.saturating_add(IMPORT_DESCRIPTOR_SIZE);
    }

    Ok(ImportTable { dlls })
}

pub(crate) fn parse_thunk_array_pub(
    image: &LoadedImage,
    ilt_rva: u32,
    iat_rva: u32,
) -> Result<Vec<ImportEntry>> {
    parse_thunk_array(image, ilt_rva, iat_rva)
}

pub(crate) fn read_cstr_pub(image: &LoadedImage, rva: u32) -> Result<String> {
    read_cstr(image, rva)
}

fn parse_thunk_array(
    image: &LoadedImage,
    ilt_rva: u32,
    iat_rva: u32,
) -> Result<Vec<ImportEntry>> {
    // Use ILT if present (preserves original thunks even after IAT is filled),
    // otherwise fall back to IAT.
    let array_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };
    if array_rva == 0 {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    let mut idx: u32 = 0;
    loop {
        let off = array_rva
            .checked_add(idx.checked_mul(8).ok_or(Error::Malformed {
                what: "thunk index overflow",
                at: array_rva as usize,
            })?)
            .ok_or(Error::Malformed { what: "thunk rva overflow", at: array_rva as usize })?;
        let slot = image
            .rva_to_slice(off, 8)
            .ok_or(Error::Malformed { what: "thunk slot oob", at: off as usize })?;
        let thunk = u64::from_le_bytes(slot.try_into().unwrap());
        if thunk == 0 {
            break;
        }

        let iat_slot_rva = iat_rva.checked_add(idx * 8).ok_or(Error::Malformed {
            what: "iat slot rva overflow",
            at: iat_rva as usize,
        })?;

        if thunk & IMPORT_BY_ORDINAL_FLAG_64 != 0 {
            let ordinal = (thunk & IMPORT_ORDINAL_MASK_64) as u16;
            entries.push(ImportEntry::Ordinal { ordinal, iat_slot_rva });
        } else {
            let by_name_rva = (thunk & 0x7FFF_FFFF) as u32;
            // Layout: u16 Hint; char Name[];
            let hint_bytes = image
                .rva_to_slice(by_name_rva, 2)
                .ok_or(Error::Malformed { what: "by-name hint", at: by_name_rva as usize })?;
            let hint = u16::from_le_bytes([hint_bytes[0], hint_bytes[1]]);
            let name = read_cstr(image, by_name_rva + 2)?;
            entries.push(ImportEntry::Name { hint, name, iat_slot_rva });
        }

        idx += 1;
        if idx > 65536 {
            return Err(Error::Malformed {
                what: "thunk array unbounded",
                at: array_rva as usize,
            });
        }
    }

    Ok(entries)
}

fn read_cstr(image: &LoadedImage, rva: u32) -> Result<String> {
    let mut out = Vec::new();
    let mut off = rva;
    loop {
        let b = image
            .rva_to_slice(off, 1)
            .ok_or(Error::Malformed { what: "cstr oob", at: off as usize })?[0];
        if b == 0 {
            break;
        }
        out.push(b);
        off = off
            .checked_add(1)
            .ok_or(Error::Malformed { what: "cstr overflow", at: off as usize })?;
        if out.len() > 4096 {
            return Err(Error::Malformed { what: "cstr unbounded", at: rva as usize });
        }
    }
    String::from_utf8(out).map_err(|_| Error::Malformed { what: "cstr utf8", at: rva as usize })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::load;
    use crate::pe::PeFile;
    use alloc::vec;
    use alloc::vec::Vec;
    use quantum_runtime::MachVmManager;

    /// Build a PE32+ with a single import: KERNEL32!ExitProcess.
    fn build_pe_with_one_import() -> Vec<u8> {
        let mut v = vec![0u8; 0x1000];
        v[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes());
        v[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let pe = 0x80;
        v[pe..pe + 4].copy_from_slice(&0x0000_4550u32.to_le_bytes());
        let coff = pe + 4;
        v[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        v[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        v[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
        v[coff + 18..coff + 20].copy_from_slice(&0x22u16.to_le_bytes());
        let opt = coff + 20;
        v[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
        v[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        v[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        v[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        v[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        v[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        v[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
        v[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
        v[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

        // Data directory [1] (IMPORT) -> RVA 0x1000, size = 2 descriptors * 20 = 40
        let dd1 = opt + 112 + 8;
        v[dd1..dd1 + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        v[dd1 + 4..dd1 + 8].copy_from_slice(&40u32.to_le_bytes());

        // Single .text section covers 0x1000..0x2000 in virtual space
        let sec = opt + 240;
        v[sec..sec + 5].copy_from_slice(b".text");
        v[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes());
        v[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        v[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes());
        v[sec + 20..sec + 24].copy_from_slice(&0x400u32.to_le_bytes());
        v[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

        // Layout inside the section's raw data (starts at file 0x400, mapped at RVA 0x1000):
        //   0x1000: IMAGE_IMPORT_DESCRIPTOR (20 bytes)
        //   0x1014: terminator (20 bytes of zeros)
        //   0x1028: ILT (u64, then 0 terminator) -> by-name @ 0x1040
        //   0x1038: IAT (u64, then 0 terminator) -> by-name @ 0x1040
        //   0x1048: dll name "KERNEL32.DLL\0"
        //   0x1040: hint(u16=0) + "ExitProcess\0"
        //   0x1058: padding
        let raw = 0x400u32;
        let to_raw = |rva: u32| (rva - 0x1000 + raw) as usize;

        // IMPORT_DESCRIPTOR
        // OriginalFirstThunk = ILT RVA = 0x1028
        v[to_raw(0x1000)..to_raw(0x1000) + 4].copy_from_slice(&0x1028u32.to_le_bytes());
        // Name = 0x1048
        v[to_raw(0x1000) + 12..to_raw(0x1000) + 16].copy_from_slice(&0x1048u32.to_le_bytes());
        // FirstThunk = IAT RVA = 0x1038
        v[to_raw(0x1000) + 16..to_raw(0x1000) + 20].copy_from_slice(&0x1038u32.to_le_bytes());
        // (terminator is already zero)

        // ILT[0] = RVA 0x1040 (low 31 bits), high bit clear
        v[to_raw(0x1028)..to_raw(0x1028) + 8].copy_from_slice(&0x1040u64.to_le_bytes());
        // ILT[1] = 0 (already)

        // IAT[0] mirrors ILT[0] at load time
        v[to_raw(0x1038)..to_raw(0x1038) + 8].copy_from_slice(&0x1040u64.to_le_bytes());

        // IMAGE_IMPORT_BY_NAME at RVA 0x1040: hint=0, name="ExitProcess\0"
        v[to_raw(0x1040)..to_raw(0x1040) + 2].copy_from_slice(&0u16.to_le_bytes());
        let name = b"ExitProcess\0";
        v[to_raw(0x1042)..to_raw(0x1042) + name.len()].copy_from_slice(name);

        // DLL name at RVA 0x1048: but 0x1042 + 12 = 0x104E overlaps with 0x1048!
        // Move DLL name to a safe RVA, say 0x1050.
        v[to_raw(0x1000) + 12..to_raw(0x1000) + 16].copy_from_slice(&0x1058u32.to_le_bytes());
        let dll = b"KERNEL32.DLL\0";
        v[to_raw(0x1058)..to_raw(0x1058) + dll.len()].copy_from_slice(dll);

        v
    }

    #[test]
    fn parses_single_import_by_name() {
        let bytes = build_pe_with_one_import();
        let pe = PeFile::parse(&bytes).expect("parse");
        let mem = MachVmManager::new();
        let img = load(&pe, &mem).expect("load");
        let table = parse(&img).expect("imports");
        assert_eq!(table.dlls.len(), 1);
        let dll = &table.dlls[0];
        assert_eq!(dll.name, "KERNEL32.DLL");
        assert_eq!(dll.entries.len(), 1);
        match &dll.entries[0] {
            ImportEntry::Name { hint, name, iat_slot_rva } => {
                assert_eq!(*hint, 0);
                assert_eq!(name, "ExitProcess");
                assert_eq!(*iat_slot_rva, 0x1038);
            }
            _ => panic!("expected named import"),
        }
        assert_eq!(dll.iat_rva, 0x1038);
        assert_eq!(dll.ilt_rva, 0x1028);
    }
}

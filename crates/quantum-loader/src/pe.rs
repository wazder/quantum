//! Read-only PE/COFF parsing. References:
//!  - PE Format spec: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
//!  - winnt.h IMAGE_* structs
//!
//! Designed to fail loudly on malformed input rather than panic.

use quantum_core::{Error, Result};

pub const DOS_SIG: u16 = 0x5A4D; // "MZ"
pub const PE_SIG: u32 = 0x0000_4550; // "PE\0\0"

pub const MACHINE_AMD64: u16 = 0x8664;
pub const MACHINE_I386: u16 = 0x014C;
pub const MACHINE_ARM64: u16 = 0xAA64;

pub const OPT_MAGIC_PE32: u16 = 0x010B;
pub const OPT_MAGIC_PE32PLUS: u16 = 0x020B;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeKind {
    Pe32,
    Pe32Plus,
}

#[derive(Debug, Clone, Copy)]
pub struct CoffHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct OptionalHeader {
    pub kind: PeKind,
    pub address_of_entry_point: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub subsystem: u16,
    pub number_of_rva_and_sizes: u32,
    pub data_directories: [DataDirectory; 16],
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// Indices into `OptionalHeader::data_directories`. Mirrors winnt.h
/// `IMAGE_DIRECTORY_ENTRY_*`.
pub mod dir {
    pub const EXPORT: usize = 0;
    pub const IMPORT: usize = 1;
    pub const RESOURCE: usize = 2;
    pub const EXCEPTION: usize = 3;
    pub const SECURITY: usize = 4;
    pub const BASERELOC: usize = 5;
    pub const DEBUG: usize = 6;
    pub const TLS: usize = 9;
    pub const LOAD_CONFIG: usize = 10;
    pub const IAT: usize = 12;
    pub const DELAY_IMPORT: usize = 13;
    pub const COM_DESCRIPTOR: usize = 14;
}

#[derive(Debug, Clone, Copy)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

impl SectionHeader {
    pub fn name_str(&self) -> &str {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        core::str::from_utf8(&self.name[..end]).unwrap_or("?")
    }
}

/// Borrowed view over a PE image already loaded into a contiguous byte slice.
#[derive(Debug)]
pub struct PeFile<'a> {
    bytes: &'a [u8],
    pe_header_offset: usize,
    pub coff: CoffHeader,
    pub opt: OptionalHeader,
    sections_offset: usize,
}

impl<'a> PeFile<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let dos_sig = read_u16(bytes, 0)?;
        if dos_sig != DOS_SIG {
            return Err(Error::Malformed { what: "DOS signature", at: 0 });
        }

        let e_lfanew = read_u32(bytes, 0x3C)? as usize;
        let pe_sig = read_u32(bytes, e_lfanew)?;
        if pe_sig != PE_SIG {
            return Err(Error::Malformed { what: "PE signature", at: e_lfanew });
        }

        let coff_off = e_lfanew + 4;
        let coff = CoffHeader {
            machine: read_u16(bytes, coff_off)?,
            number_of_sections: read_u16(bytes, coff_off + 2)?,
            time_date_stamp: read_u32(bytes, coff_off + 4)?,
            pointer_to_symbol_table: read_u32(bytes, coff_off + 8)?,
            number_of_symbols: read_u32(bytes, coff_off + 12)?,
            size_of_optional_header: read_u16(bytes, coff_off + 16)?,
            characteristics: read_u16(bytes, coff_off + 18)?,
        };

        let opt_off = coff_off + 20;
        let magic = read_u16(bytes, opt_off)?;
        let kind = match magic {
            OPT_MAGIC_PE32 => PeKind::Pe32,
            OPT_MAGIC_PE32PLUS => PeKind::Pe32Plus,
            _ => return Err(Error::Malformed { what: "optional header magic", at: opt_off }),
        };

        let opt = Self::parse_optional(bytes, opt_off, kind)?;

        let sections_offset = opt_off + coff.size_of_optional_header as usize;
        // Validate section table is within the slice.
        let sections_end = sections_offset + 40 * coff.number_of_sections as usize;
        if sections_end > bytes.len() {
            return Err(Error::Malformed { what: "section table", at: sections_offset });
        }

        Ok(Self {
            bytes,
            pe_header_offset: e_lfanew,
            coff,
            opt,
            sections_offset,
        })
    }

    fn parse_optional(bytes: &[u8], off: usize, kind: PeKind) -> Result<OptionalHeader> {
        // Layout differs between PE32 and PE32+: ImageBase widens from u32 to
        // u64, which shifts every later field. We branch only on that delta.
        let aoep = read_u32(bytes, off + 16)?;
        let (image_base, fixed_off) = match kind {
            PeKind::Pe32 => {
                // PE32: BaseOfData (u32) at off+24, then ImageBase u32 at off+28.
                let ib = read_u32(bytes, off + 28)? as u64;
                (ib, off + 32)
            }
            PeKind::Pe32Plus => {
                // PE32+: no BaseOfData; ImageBase u64 at off+24.
                let ib = read_u64(bytes, off + 24)?;
                (ib, off + 32)
            }
        };

        let section_alignment = read_u32(bytes, fixed_off)?;
        let file_alignment = read_u32(bytes, fixed_off + 4)?;
        let size_of_image = read_u32(bytes, fixed_off + 24)?;
        let size_of_headers = read_u32(bytes, fixed_off + 28)?;
        let subsystem = read_u16(bytes, fixed_off + 36)?;

        // NumberOfRvaAndSizes sits at a different offset per kind because
        // SizeOfStackReserve/Commit/HeapReserve/Commit widen from u32 to u64.
        let (number_of_rva_and_sizes_off, data_dir_off) = match kind {
            PeKind::Pe32 => (fixed_off + 60, fixed_off + 64),
            PeKind::Pe32Plus => (fixed_off + 76, fixed_off + 80),
        };
        let number_of_rva_and_sizes = read_u32(bytes, number_of_rva_and_sizes_off)?;

        let mut data_directories = [DataDirectory::default(); 16];
        let count = (number_of_rva_and_sizes as usize).min(16);
        for (i, slot) in data_directories.iter_mut().enumerate().take(count) {
            let entry_off = data_dir_off + i * 8;
            *slot = DataDirectory {
                virtual_address: read_u32(bytes, entry_off)?,
                size: read_u32(bytes, entry_off + 4)?,
            };
        }

        Ok(OptionalHeader {
            kind,
            address_of_entry_point: aoep,
            image_base,
            section_alignment,
            file_alignment,
            size_of_image,
            size_of_headers,
            subsystem,
            number_of_rva_and_sizes,
            data_directories,
        })
    }

    pub fn sections(&self) -> SectionIter<'_> {
        SectionIter {
            bytes: self.bytes,
            offset: self.sections_offset,
            remaining: self.coff.number_of_sections,
        }
    }

    pub fn raw(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn pe_header_offset(&self) -> usize {
        self.pe_header_offset
    }
}

pub struct SectionIter<'a> {
    bytes: &'a [u8],
    offset: usize,
    remaining: u16,
}

impl Iterator for SectionIter<'_> {
    type Item = SectionHeader;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let off = self.offset;
        // Section headers are fixed 40 bytes.
        let mut name = [0u8; 8];
        name.copy_from_slice(self.bytes.get(off..off + 8)?);
        let sh = SectionHeader {
            name,
            virtual_size: read_u32(self.bytes, off + 8).ok()?,
            virtual_address: read_u32(self.bytes, off + 12).ok()?,
            size_of_raw_data: read_u32(self.bytes, off + 16).ok()?,
            pointer_to_raw_data: read_u32(self.bytes, off + 20).ok()?,
            characteristics: read_u32(self.bytes, off + 36).ok()?,
        };
        self.offset += 40;
        self.remaining -= 1;
        Some(sh)
    }
}

#[inline]
fn read_u16(b: &[u8], off: usize) -> Result<u16> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(Error::Malformed { what: "u16 read", at: off })
}

#[inline]
fn read_u32(b: &[u8], off: usize) -> Result<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(Error::Malformed { what: "u32 read", at: off })
}

#[inline]
fn read_u64(b: &[u8], off: usize) -> Result<u64> {
    b.get(off..off + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
        .ok_or(Error::Malformed { what: "u64 read", at: off })
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    /// Build a minimal valid PE32+ image just large enough to parse.
    /// Not runnable — just enough bytes to exercise the parser.
    fn synth_pe64() -> Vec<u8> {
        let mut v = vec![0u8; 0x400];
        // DOS header.
        v[0..2].copy_from_slice(&DOS_SIG.to_le_bytes());
        let e_lfanew: u32 = 0x80;
        v[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

        let pe = e_lfanew as usize;
        v[pe..pe + 4].copy_from_slice(&PE_SIG.to_le_bytes());
        let coff = pe + 4;
        v[coff..coff + 2].copy_from_slice(&MACHINE_AMD64.to_le_bytes()); // machine
        v[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // sections
        v[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes()); // size of opt hdr
        v[coff + 18..coff + 20].copy_from_slice(&0x22u16.to_le_bytes()); // characteristics

        let opt = coff + 20;
        v[opt..opt + 2].copy_from_slice(&OPT_MAGIC_PE32PLUS.to_le_bytes());
        // AddressOfEntryPoint at opt+16
        v[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        // ImageBase u64 at opt+24
        v[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
        // SectionAlignment, FileAlignment at opt+32, +36
        v[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        v[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        // SizeOfImage at opt+56
        v[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        // SizeOfHeaders at opt+60
        v[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
        // Subsystem at opt+68
        v[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // WINDOWS_CUI
        // NumberOfRvaAndSizes at opt+108 (fixed_off = opt+32, +76 = opt+108)
        v[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

        // Single section header at opt + 240
        let sec = opt + 240;
        v[sec..sec + 6].copy_from_slice(b".text\0");
        v[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes()); // virt size
        v[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virt addr
        v[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
        v[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes()); // raw ptr
        v[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // CODE|EXEC|READ

        v
    }

    #[test]
    fn parses_minimal_pe64() {
        let bytes = synth_pe64();
        let pe = PeFile::parse(&bytes).expect("parse");
        assert_eq!(pe.coff.machine, MACHINE_AMD64);
        assert_eq!(pe.coff.number_of_sections, 1);
        assert_eq!(pe.opt.kind, PeKind::Pe32Plus);
        assert_eq!(pe.opt.image_base, 0x140000000);
        assert_eq!(pe.opt.address_of_entry_point, 0x1000);

        let secs: Vec<_> = pe.sections().collect();
        assert_eq!(secs.len(), 1);
        assert_eq!(secs[0].name_str(), ".text");
        assert_eq!(secs[0].virtual_address, 0x1000);
    }

    #[test]
    fn rejects_bad_dos_sig() {
        let bytes = vec![0u8; 0x400];
        assert!(matches!(PeFile::parse(&bytes), Err(Error::Malformed { .. })));
    }
}

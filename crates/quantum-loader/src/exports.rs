//! Export directory parser. Layout (per PE spec):
//!
//! ```text
//! IMAGE_EXPORT_DIRECTORY {
//!   u32 Characteristics;
//!   u32 TimeDateStamp;
//!   u16 MajorVersion;
//!   u16 MinorVersion;
//!   u32 Name;                  // RVA -> ASCII module name
//!   u32 Base;                  // ordinal base
//!   u32 NumberOfFunctions;
//!   u32 NumberOfNames;
//!   u32 AddressOfFunctions;    // RVA -> u32[NumberOfFunctions] of function RVAs
//!   u32 AddressOfNames;        // RVA -> u32[NumberOfNames] of name RVAs
//!   u32 AddressOfNameOrdinals; // RVA -> u16[NumberOfNames] of biased ordinals
//! }
//! ```
//!
//! A function RVA that falls inside the export directory itself is a
//! *forwarded export*; the bytes there are an ASCII `Dll.Name` string.

use alloc::string::String;
use alloc::vec::Vec;

use quantum_core::{Error, Result};

use crate::image::LoadedImage;
use crate::pe::dir;

#[derive(Debug, Clone)]
pub struct ExportTable {
    pub module_name: String,
    pub ordinal_base: u32,
    pub entries: Vec<Export>,
    pub names: Vec<NamedExport>,
}

#[derive(Debug, Clone)]
pub struct Export {
    pub ordinal: u32,
    pub target: ExportTarget,
}

#[derive(Debug, Clone)]
pub enum ExportTarget {
    /// RVA inside the image.
    Rva(u32),
    /// `Dll.Name` or `Dll.#Ordinal` forwarder string.
    Forwarded(String),
}

#[derive(Debug, Clone)]
pub struct NamedExport {
    pub name: String,
    pub ordinal: u32,
}

pub fn parse(image: &LoadedImage) -> Result<Option<ExportTable>> {
    let dir_entry = match image.data_dir(dir::EXPORT) {
        Some(d) => d,
        None => return Ok(None),
    };

    let header = image
        .rva_to_slice(dir_entry.virtual_address, 40)
        .ok_or(Error::Malformed {
            what: "export directory",
            at: dir_entry.virtual_address as usize,
        })?;

    let name_rva = u32::from_le_bytes(header[12..16].try_into().unwrap());
    let base = u32::from_le_bytes(header[16..20].try_into().unwrap());
    let num_funcs = u32::from_le_bytes(header[20..24].try_into().unwrap());
    let num_names = u32::from_le_bytes(header[24..28].try_into().unwrap());
    let funcs_rva = u32::from_le_bytes(header[28..32].try_into().unwrap());
    let names_rva = u32::from_le_bytes(header[32..36].try_into().unwrap());
    let ordinals_rva = u32::from_le_bytes(header[36..40].try_into().unwrap());

    let module_name = if name_rva != 0 {
        read_cstr(image, name_rva)?
    } else {
        String::new()
    };

    let dir_start = dir_entry.virtual_address;
    let dir_end = dir_start.saturating_add(dir_entry.size);

    let mut entries = Vec::with_capacity(num_funcs as usize);
    for i in 0..num_funcs {
        let off = funcs_rva
            .checked_add(i.checked_mul(4).ok_or(Error::Malformed {
                what: "export funcs overflow",
                at: funcs_rva as usize,
            })?)
            .ok_or(Error::Malformed {
                what: "export funcs offset",
                at: funcs_rva as usize,
            })?;
        let bytes = image.rva_to_slice(off, 4).ok_or(Error::Malformed {
            what: "export func entry",
            at: off as usize,
        })?;
        let target_rva = u32::from_le_bytes(bytes.try_into().unwrap());

        let target = if target_rva >= dir_start && target_rva < dir_end {
            ExportTarget::Forwarded(read_cstr(image, target_rva)?)
        } else if target_rva == 0 {
            // Skip empty slots? PE spec says they exist; represent as RVA 0.
            ExportTarget::Rva(0)
        } else {
            ExportTarget::Rva(target_rva)
        };

        entries.push(Export {
            ordinal: base + i,
            target,
        });
    }

    let mut names = Vec::with_capacity(num_names as usize);
    for i in 0..num_names {
        let name_off = names_rva.saturating_add(i * 4);
        let ord_off = ordinals_rva.saturating_add(i * 2);
        let name_rva_bytes = image.rva_to_slice(name_off, 4).ok_or(Error::Malformed {
            what: "export name entry",
            at: name_off as usize,
        })?;
        let ord_bytes = image.rva_to_slice(ord_off, 2).ok_or(Error::Malformed {
            what: "export ordinal entry",
            at: ord_off as usize,
        })?;
        let name_rva_i = u32::from_le_bytes(name_rva_bytes.try_into().unwrap());
        let biased = u16::from_le_bytes([ord_bytes[0], ord_bytes[1]]) as u32;
        let name = read_cstr(image, name_rva_i)?;
        names.push(NamedExport {
            name,
            ordinal: base + biased,
        });
    }

    Ok(Some(ExportTable {
        module_name,
        ordinal_base: base,
        entries,
        names,
    }))
}

fn read_cstr(image: &LoadedImage, rva: u32) -> Result<String> {
    let mut out = Vec::new();
    let mut off = rva;
    loop {
        let b = image.rva_to_slice(off, 1).ok_or(Error::Malformed {
            what: "export cstr",
            at: off as usize,
        })?[0];
        if b == 0 {
            break;
        }
        out.push(b);
        off = off.checked_add(1).ok_or(Error::Malformed {
            what: "export cstr overflow",
            at: off as usize,
        })?;
        if out.len() > 4096 {
            return Err(Error::Malformed {
                what: "export cstr unbounded",
                at: rva as usize,
            });
        }
    }
    String::from_utf8(out).map_err(|_| Error::Malformed {
        what: "export cstr utf8",
        at: rva as usize,
    })
}

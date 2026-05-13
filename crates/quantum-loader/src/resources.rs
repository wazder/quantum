//! Resource directory tree. Three-level lookup: Type → Name → Language.
//! Each level uses `IMAGE_RESOURCE_DIRECTORY` (16 byte header) followed
//! by `NumberOfNamedEntries + NumberOfIdEntries` of
//! `IMAGE_RESOURCE_DIRECTORY_ENTRY` (8 bytes each).
//!
//! Leaf entries point to `IMAGE_RESOURCE_DATA_ENTRY`:
//!   `u32 OffsetToData (RVA); u32 Size; u32 CodePage; u32 Reserved`.
//!
//! We don't crack bitmap/icon/version blobs here — we just expose the
//! tree so callers can navigate it.

use alloc::string::String;
use alloc::vec::Vec;

use quantum_core::{Error, Result};

use crate::image::LoadedImage;
use crate::pe::dir;

const DIR_HEADER_SIZE: u32 = 16;
const DIR_ENTRY_SIZE: u32 = 8;
const DATA_ENTRY_SIZE: u32 = 16;

#[derive(Debug, Clone)]
pub struct ResourceTree {
    pub root: ResourceDir,
}

#[derive(Debug, Clone)]
pub struct ResourceDir {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub entries: Vec<ResourceEntry>,
}

#[derive(Debug, Clone)]
pub struct ResourceEntry {
    pub id: ResourceId,
    pub kind: ResourceKind,
}

#[derive(Debug, Clone)]
pub enum ResourceId {
    Name(String),
    Integer(u32),
}

#[derive(Debug, Clone)]
pub enum ResourceKind {
    Dir(ResourceDir),
    Data(ResourceData),
}

#[derive(Debug, Clone, Copy)]
pub struct ResourceData {
    pub data_rva: u32,
    pub size: u32,
    pub code_page: u32,
}

pub fn parse(image: &LoadedImage) -> Result<Option<ResourceTree>> {
    let dir_entry = match image.data_dir(dir::RESOURCE) {
        Some(d) => d,
        None => return Ok(None),
    };
    let root = parse_dir(
        image,
        dir_entry.virtual_address,
        dir_entry.virtual_address,
        0,
    )?;
    Ok(Some(ResourceTree { root }))
}

fn parse_dir(image: &LoadedImage, base_rva: u32, dir_rva: u32, depth: u32) -> Result<ResourceDir> {
    if depth > 5 {
        return Err(Error::Malformed {
            what: "resource depth",
            at: dir_rva as usize,
        });
    }
    let bytes = image
        .rva_to_slice(dir_rva, DIR_HEADER_SIZE as usize)
        .ok_or(Error::Malformed {
            what: "resource dir header",
            at: dir_rva as usize,
        })?;
    let characteristics = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let time_date_stamp = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let major_version = u16::from_le_bytes([bytes[8], bytes[9]]);
    let minor_version = u16::from_le_bytes([bytes[10], bytes[11]]);
    let named = u16::from_le_bytes([bytes[12], bytes[13]]) as u32;
    let id = u16::from_le_bytes([bytes[14], bytes[15]]) as u32;
    let total = named + id;

    let mut entries = Vec::with_capacity(total as usize);
    for i in 0..total {
        let off = dir_rva + DIR_HEADER_SIZE + i * DIR_ENTRY_SIZE;
        let entry_bytes =
            image
                .rva_to_slice(off, DIR_ENTRY_SIZE as usize)
                .ok_or(Error::Malformed {
                    what: "resource entry oob",
                    at: off as usize,
                })?;
        let id_raw = u32::from_le_bytes(entry_bytes[0..4].try_into().unwrap());
        let kind_raw = u32::from_le_bytes(entry_bytes[4..8].try_into().unwrap());

        let resource_id = if id_raw & 0x8000_0000 != 0 {
            // High bit set: offset (from resource section base) to a
            // length-prefixed UTF-16LE string.
            let name_off = base_rva + (id_raw & 0x7FFF_FFFF);
            let len_bytes = image.rva_to_slice(name_off, 2).ok_or(Error::Malformed {
                what: "resource name len",
                at: name_off as usize,
            })?;
            let len = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
            let chars_bytes =
                image
                    .rva_to_slice(name_off + 2, len * 2)
                    .ok_or(Error::Malformed {
                        what: "resource name body",
                        at: name_off as usize,
                    })?;
            let mut name = String::new();
            let mut i = 0;
            while i < chars_bytes.len() {
                let u = u16::from_le_bytes([chars_bytes[i], chars_bytes[i + 1]]);
                if let Some(c) = core::char::from_u32(u as u32) {
                    name.push(c);
                }
                i += 2;
            }
            ResourceId::Name(name)
        } else {
            ResourceId::Integer(id_raw)
        };

        let kind = if kind_raw & 0x8000_0000 != 0 {
            // Subdirectory.
            let child_rva = base_rva + (kind_raw & 0x7FFF_FFFF);
            ResourceKind::Dir(parse_dir(image, base_rva, child_rva, depth + 1)?)
        } else {
            // Data entry.
            let data_off = base_rva + kind_raw;
            let data_bytes = image
                .rva_to_slice(data_off, DATA_ENTRY_SIZE as usize)
                .ok_or(Error::Malformed {
                    what: "resource data entry",
                    at: data_off as usize,
                })?;
            ResourceKind::Data(ResourceData {
                data_rva: u32::from_le_bytes(data_bytes[0..4].try_into().unwrap()),
                size: u32::from_le_bytes(data_bytes[4..8].try_into().unwrap()),
                code_page: u32::from_le_bytes(data_bytes[8..12].try_into().unwrap()),
            })
        };

        entries.push(ResourceEntry {
            id: resource_id,
            kind,
        });
    }

    Ok(ResourceDir {
        characteristics,
        time_date_stamp,
        major_version,
        minor_version,
        entries,
    })
}

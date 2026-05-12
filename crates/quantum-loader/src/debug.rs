//! Debug directory. Array of `IMAGE_DEBUG_DIRECTORY` (28 bytes each):
//!
//! ```text
//! u32 Characteristics
//! u32 TimeDateStamp
//! u16 MajorVersion, MinorVersion
//! u32 Type           // 2 = IMAGE_DEBUG_TYPE_CODEVIEW
//! u32 SizeOfData
//! u32 AddressOfRawData (RVA)
//! u32 PointerToRawData (file offset, ignored after mapping)
//! ```
//!
//! For CODEVIEW (RSDS) entries we crack the payload:
//!   `u32 sig ('RSDS') + GUID (16) + u32 age + char path[]`.

use alloc::string::String;
use alloc::vec::Vec;

use quantum_core::{Error, Result};

use crate::image::LoadedImage;
use crate::pe::dir;

pub const TYPE_COFF: u32 = 1;
pub const TYPE_CODEVIEW: u32 = 2;
pub const TYPE_FPO: u32 = 3;
pub const TYPE_MISC: u32 = 4;
pub const TYPE_REPRO: u32 = 16;

#[derive(Debug, Clone)]
pub struct DebugEntry {
    pub kind: u32,
    pub time_date_stamp: u32,
    pub size_of_data: u32,
    pub address_of_raw_data: u32,
    pub codeview: Option<CodeView>,
}

#[derive(Debug, Clone)]
pub struct CodeView {
    pub guid: [u8; 16],
    pub age: u32,
    pub pdb_path: String,
}

pub fn parse(image: &LoadedImage) -> Result<Vec<DebugEntry>> {
    let dir_entry = match image.data_dir(dir::DEBUG) {
        Some(d) => d,
        None => return Ok(Vec::new()),
    };

    if dir_entry.size % 28 != 0 {
        return Err(Error::Malformed {
            what: "debug directory size not multiple of 28",
            at: dir_entry.virtual_address as usize,
        });
    }
    let count = (dir_entry.size / 28) as usize;

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = dir_entry.virtual_address + (i as u32) * 28;
        let bytes = image
            .rva_to_slice(off, 28)
            .ok_or(Error::Malformed { what: "debug entry oob", at: off as usize })?;
        let kind = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let time_date_stamp = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let size_of_data = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let address_of_raw_data = u32::from_le_bytes(bytes[20..24].try_into().unwrap());

        let codeview = if kind == TYPE_CODEVIEW && size_of_data >= 24 {
            parse_codeview(image, address_of_raw_data, size_of_data)?
        } else {
            None
        };

        out.push(DebugEntry {
            kind,
            time_date_stamp,
            size_of_data,
            address_of_raw_data,
            codeview,
        });
    }

    Ok(out)
}

fn parse_codeview(image: &LoadedImage, rva: u32, size: u32) -> Result<Option<CodeView>> {
    let bytes = image
        .rva_to_slice(rva, size as usize)
        .ok_or(Error::Malformed { what: "codeview blob", at: rva as usize })?;
    if bytes.len() < 24 || &bytes[0..4] != b"RSDS" {
        // Not RSDS; could be NB10 (older). We only handle RSDS today.
        return Ok(None);
    }
    let mut guid = [0u8; 16];
    guid.copy_from_slice(&bytes[4..20]);
    let age = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
    let path_bytes = &bytes[24..];
    let end = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
    let pdb_path = core::str::from_utf8(&path_bytes[..end])
        .map_err(|_| Error::Malformed { what: "codeview path utf8", at: (rva as usize) + 24 })?
        .into();
    Ok(Some(CodeView { guid, age, pdb_path }))
}

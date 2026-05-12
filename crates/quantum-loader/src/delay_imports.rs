//! Delay-load import directory (`IMAGE_DELAYLOAD_DESCRIPTOR`). Same shape
//! as the regular import table conceptually, but each descriptor is 32
//! bytes and uses RVAs (not VAs) on modern toolchains.
//!
//! ```text
//! struct IMAGE_DELAYLOAD_DESCRIPTOR {
//!   u32 Attributes;          // 1 = RvaBased
//!   u32 DllNameRVA;
//!   u32 ModuleHandleRVA;
//!   u32 ImportAddressTableRVA;
//!   u32 ImportNameTableRVA;
//!   u32 BoundImportAddressTableRVA;
//!   u32 UnloadInformationTableRVA;
//!   u32 TimeDateStamp;
//! }
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use quantum_core::{Error, Result};

use crate::image::LoadedImage;
use crate::imports::{ImportEntry, parse_thunk_array_pub};
use crate::pe::dir;

const DELAY_DESCRIPTOR_SIZE: u32 = 32;

#[derive(Debug, Clone)]
pub struct DelayImportTable {
    pub dlls: Vec<DelayDllImports>,
}

#[derive(Debug, Clone)]
pub struct DelayDllImports {
    pub name: String,
    pub attributes: u32,
    pub module_handle_rva: u32,
    pub iat_rva: u32,
    pub int_rva: u32,
    pub bound_iat_rva: u32,
    pub unload_iat_rva: u32,
    pub time_date_stamp: u32,
    pub entries: Vec<ImportEntry>,
}

pub fn parse(image: &LoadedImage) -> Result<DelayImportTable> {
    let dir = match image.data_dir(dir::DELAY_IMPORT) {
        Some(d) => d,
        None => return Ok(DelayImportTable { dlls: Vec::new() }),
    };

    let mut dlls = Vec::new();
    let mut cursor = dir.virtual_address;
    let end = dir.virtual_address.saturating_add(dir.size);

    loop {
        if cursor.saturating_add(DELAY_DESCRIPTOR_SIZE) > end {
            return Err(Error::Malformed {
                what: "delay-load descriptor past directory",
                at: cursor as usize,
            });
        }
        let bytes = image
            .rva_to_slice(cursor, DELAY_DESCRIPTOR_SIZE as usize)
            .ok_or(Error::Malformed { what: "delay-load descriptor", at: cursor as usize })?;

        let attributes = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let name_rva = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let module_handle_rva = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let iat_rva = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let int_rva = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let bound_iat_rva = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
        let unload_iat_rva = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
        let time_date_stamp = u32::from_le_bytes(bytes[28..32].try_into().unwrap());

        if attributes == 0
            && name_rva == 0
            && iat_rva == 0
            && int_rva == 0
        {
            break;
        }

        let dll_name = crate::imports::read_cstr_pub(image, name_rva)?;
        let entries = parse_thunk_array_pub(image, int_rva, iat_rva)?;

        dlls.push(DelayDllImports {
            name: dll_name,
            attributes,
            module_handle_rva,
            iat_rva,
            int_rva,
            bound_iat_rva,
            unload_iat_rva,
            time_date_stamp,
            entries,
        });

        cursor = cursor.saturating_add(DELAY_DESCRIPTOR_SIZE);
    }

    Ok(DelayImportTable { dlls })
}

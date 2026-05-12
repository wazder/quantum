//! TLS directory parser. PE32+ layout:
//!
//! ```text
//! IMAGE_TLS_DIRECTORY64 {
//!   u64 StartAddressOfRawData;     // VA, NOT an RVA
//!   u64 EndAddressOfRawData;
//!   u64 AddressOfIndex;
//!   u64 AddressOfCallBacks;        // VA -> NULL-terminated u64 array of callback VAs
//!   u32 SizeOfZeroFill;
//!   u32 Characteristics;
//! }
//! ```
//!
//! VA values are absolute virtual addresses calculated against the
//! *preferred* image base, so callers must subtract `preferred_base` to
//! reach the RVA.

use alloc::vec::Vec;

use quantum_core::{Error, Result};

use crate::image::LoadedImage;
use crate::pe::dir;

#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub raw_start_rva: u32,
    pub raw_end_rva: u32,
    pub index_rva: u32,
    pub callbacks_rva: u32,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
    pub callbacks: Vec<u32>,
}

pub fn parse(image: &LoadedImage) -> Result<Option<TlsInfo>> {
    let dir_entry = match image.data_dir(dir::TLS) {
        Some(d) => d,
        None => return Ok(None),
    };

    let bytes = image
        .rva_to_slice(dir_entry.virtual_address, 40)
        .ok_or(Error::Malformed { what: "TLS directory", at: dir_entry.virtual_address as usize })?;

    let raw_start_va = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let raw_end_va = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let index_va = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let callbacks_va = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    let size_of_zero_fill = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
    let characteristics = u32::from_le_bytes(bytes[36..40].try_into().unwrap());

    let base = image.preferred_base;
    let to_rva = |va: u64| -> u32 {
        va.wrapping_sub(base) as u32
    };

    let raw_start_rva = to_rva(raw_start_va);
    let raw_end_rva = to_rva(raw_end_va);
    let index_rva = to_rva(index_va);
    let callbacks_rva = to_rva(callbacks_va);

    let mut callbacks = Vec::new();
    if callbacks_va != 0 {
        let mut off = callbacks_rva;
        loop {
            let slot = image
                .rva_to_slice(off, 8)
                .ok_or(Error::Malformed { what: "tls callback slot", at: off as usize })?;
            let va = u64::from_le_bytes(slot.try_into().unwrap());
            if va == 0 {
                break;
            }
            callbacks.push(to_rva(va));
            off = off
                .checked_add(8)
                .ok_or(Error::Malformed { what: "tls callbacks overflow", at: off as usize })?;
            if callbacks.len() > 256 {
                return Err(Error::Malformed {
                    what: "tls callbacks unbounded",
                    at: callbacks_rva as usize,
                });
            }
        }
    }

    Ok(Some(TlsInfo {
        raw_start_rva,
        raw_end_rva,
        index_rva,
        callbacks_rva,
        size_of_zero_fill,
        characteristics,
        callbacks,
    }))
}

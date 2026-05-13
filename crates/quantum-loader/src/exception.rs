//! Exception directory parser. PE32+ stores an array of
//! `RUNTIME_FUNCTION { BeginAddress, EndAddress, UnwindInfoAddress }`,
//! each entry 12 bytes. We park the array for SEH later — no unwind
//! interpretation tonight.

use alloc::vec::Vec;

use quantum_core::{Error, Result};

use crate::image::LoadedImage;
use crate::pe::dir;

const RUNTIME_FUNCTION_SIZE: u32 = 12;

#[derive(Debug, Clone, Copy)]
pub struct RuntimeFunction {
    pub begin_rva: u32,
    pub end_rva: u32,
    pub unwind_info_rva: u32,
}

pub fn parse(image: &LoadedImage) -> Result<Vec<RuntimeFunction>> {
    let dir_entry = match image.data_dir(dir::EXCEPTION) {
        Some(d) => d,
        None => return Ok(Vec::new()),
    };

    if dir_entry.size % RUNTIME_FUNCTION_SIZE != 0 {
        return Err(Error::Malformed {
            what: "exception directory size not multiple of 12",
            at: dir_entry.virtual_address as usize,
        });
    }

    let count = (dir_entry.size / RUNTIME_FUNCTION_SIZE) as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = dir_entry.virtual_address + (i as u32) * RUNTIME_FUNCTION_SIZE;
        let bytes = image
            .rva_to_slice(off, RUNTIME_FUNCTION_SIZE as usize)
            .ok_or(Error::Malformed {
                what: "RUNTIME_FUNCTION oob",
                at: off as usize,
            })?;
        let begin_rva = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let end_rva = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let unwind_info_rva = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        out.push(RuntimeFunction {
            begin_rva,
            end_rva,
            unwind_info_rva,
        });
    }

    Ok(out)
}

//! Exception directory parser. PE32+ stores an array of
//! `RUNTIME_FUNCTION { BeginAddress, EndAddress, UnwindInfoAddress }`,
//! each entry 12 bytes, plus per-function `UNWIND_INFO` records at the
//! pointed-to RVAs. We parse both so the SEH dispatcher can find the
//! exception handler for any RIP at fault time.
//!
//! Layout reference: <winnt.h>'s `_RUNTIME_FUNCTION` and `_UNWIND_INFO`
//! / `_UNWIND_CODE` plus Microsoft's "x64 exception handling" docs.

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

/// UNWIND_INFO flag bits.
pub const UNW_FLAG_EHANDLER: u8 = 0x1;
pub const UNW_FLAG_UHANDLER: u8 = 0x2;
pub const UNW_FLAG_CHAININFO: u8 = 0x4;

/// Parsed `UNWIND_INFO` header. The trailing `UNWIND_CODE` array is
/// stored as a raw byte slice the dispatcher can interpret on demand;
/// we don't replay codes for unwinding yet, but the header carries the
/// fields we need to (a) locate the exception handler RVA and (b)
/// follow a CHAININFO link to the next RUNTIME_FUNCTION.
#[derive(Debug, Clone)]
pub struct UnwindInfo {
    /// Always 1 or 2 on Windows x64.
    pub version: u8,
    pub flags: u8,
    pub size_of_prolog: u8,
    pub count_of_codes: u8,
    /// 0 if no frame pointer; otherwise the index of the register used.
    pub frame_register: u8,
    /// Scaled by 16; multiply by 16 to get the actual offset.
    pub frame_offset: u8,
    /// Raw bytes of the UNWIND_CODE array. Each code is 2 bytes;
    /// `count_of_codes` codes are stored, padded to an even total.
    pub unwind_codes: Vec<u8>,
    /// Present if `UNW_FLAG_EHANDLER` or `UNW_FLAG_UHANDLER` is set.
    /// RVA of the language-specific exception handler function.
    pub handler_rva: Option<u32>,
    /// Present if `UNW_FLAG_CHAININFO` is set. Encodes a nested
    /// RUNTIME_FUNCTION the SEH dispatcher should follow.
    pub chained_function: Option<RuntimeFunction>,
}

impl UnwindInfo {
    pub fn has_exception_handler(&self) -> bool {
        self.flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0
    }
}

/// Parse the `UNWIND_INFO` at the given image RVA.
pub fn parse_unwind_info(image: &LoadedImage, unwind_rva: u32) -> Result<UnwindInfo> {
    let header = image.rva_to_slice(unwind_rva, 4).ok_or(Error::Malformed {
        what: "UNWIND_INFO header oob",
        at: unwind_rva as usize,
    })?;
    let ver_flags = header[0];
    let version = ver_flags & 0x07;
    let flags = (ver_flags >> 3) & 0x1F;
    let size_of_prolog = header[1];
    let count_of_codes = header[2];
    let frame_byte = header[3];
    let frame_register = frame_byte & 0x0F;
    let frame_offset = (frame_byte >> 4) & 0x0F;

    if version != 1 && version != 2 {
        return Err(Error::Malformed {
            what: "UNWIND_INFO version unsupported",
            at: unwind_rva as usize,
        });
    }

    // UNWIND_CODE array: `count_of_codes` entries, 2 bytes each. The
    // *array* is padded to an even number of slots so the trailing
    // ExceptionHandler / FunctionEntry sits on a 4-byte boundary.
    let codes_padded_count = (count_of_codes as u32).div_ceil(2) * 2;
    let codes_size = codes_padded_count as usize * 2;
    let codes_off = unwind_rva + 4;
    let unwind_codes = image
        .rva_to_slice(codes_off, codes_size)
        .ok_or(Error::Malformed {
            what: "UNWIND_INFO codes oob",
            at: codes_off as usize,
        })?
        .to_vec();

    let mut handler_rva = None;
    let mut chained_function = None;
    let trailer_off = codes_off + codes_size as u32;
    if flags & UNW_FLAG_CHAININFO != 0 {
        // 12 bytes: nested RUNTIME_FUNCTION.
        let b = image
            .rva_to_slice(trailer_off, RUNTIME_FUNCTION_SIZE as usize)
            .ok_or(Error::Malformed {
                what: "UNWIND_INFO chained RUNTIME_FUNCTION oob",
                at: trailer_off as usize,
            })?;
        chained_function = Some(RuntimeFunction {
            begin_rva: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            end_rva: u32::from_le_bytes(b[4..8].try_into().unwrap()),
            unwind_info_rva: u32::from_le_bytes(b[8..12].try_into().unwrap()),
        });
    } else if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
        // 4 bytes: ExceptionHandler RVA, followed by handler-specific
        // language data we don't need to parse here.
        let b = image.rva_to_slice(trailer_off, 4).ok_or(Error::Malformed {
            what: "UNWIND_INFO handler RVA oob",
            at: trailer_off as usize,
        })?;
        handler_rva = Some(u32::from_le_bytes(b[0..4].try_into().unwrap()));
    }

    Ok(UnwindInfo {
        version,
        flags,
        size_of_prolog,
        count_of_codes,
        frame_register,
        frame_offset,
        unwind_codes,
        handler_rva,
        chained_function,
    })
}

/// Binary-search the `funcs` array (sorted by begin_rva, per the PE
/// spec) for the RUNTIME_FUNCTION covering `rva`. Returns `None` if no
/// entry matches — caller treats that as "no SEH handler, propagate".
pub fn lookup_runtime_function(funcs: &[RuntimeFunction], rva: u32) -> Option<&RuntimeFunction> {
    let idx = funcs
        .binary_search_by(|f| {
            if rva < f.begin_rva {
                core::cmp::Ordering::Greater
            } else if rva >= f.end_rva {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Equal
            }
        })
        .ok()?;
    Some(&funcs[idx])
}

/// Follow CHAININFO links to the terminal UNWIND_INFO — the one that
/// actually carries the exception handler RVA (if any). Returns the
/// final parsed UnwindInfo plus the RUNTIME_FUNCTION whose unwind info
/// it came from, so callers can map RIP-during-handler back to the
/// physical function.
pub fn resolve_handler(
    image: &LoadedImage,
    starting: &RuntimeFunction,
) -> Result<(UnwindInfo, RuntimeFunction)> {
    let mut current = *starting;
    let mut seen = 0u32;
    loop {
        seen += 1;
        if seen > 16 {
            // Pathological chain — bail out.
            return Err(Error::Malformed {
                what: "UNWIND_INFO chain too deep",
                at: current.unwind_info_rva as usize,
            });
        }
        let ui = parse_unwind_info(image, current.unwind_info_rva)?;
        if let Some(next) = ui.chained_function {
            current = next;
            continue;
        }
        return Ok((ui, current));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_picks_covering_entry() {
        let funcs = vec![
            RuntimeFunction {
                begin_rva: 0x1000,
                end_rva: 0x1040,
                unwind_info_rva: 0x2000,
            },
            RuntimeFunction {
                begin_rva: 0x1050,
                end_rva: 0x1080,
                unwind_info_rva: 0x2010,
            },
        ];
        assert!(lookup_runtime_function(&funcs, 0x0FFF).is_none());
        assert_eq!(
            lookup_runtime_function(&funcs, 0x1000).unwrap().begin_rva,
            0x1000
        );
        assert_eq!(
            lookup_runtime_function(&funcs, 0x103F).unwrap().begin_rva,
            0x1000
        );
        assert!(lookup_runtime_function(&funcs, 0x1040).is_none());
        assert_eq!(
            lookup_runtime_function(&funcs, 0x1050).unwrap().begin_rva,
            0x1050
        );
        assert!(lookup_runtime_function(&funcs, 0x1080).is_none());
    }

    #[test]
    fn unwind_flag_bits() {
        let mut ui = UnwindInfo {
            version: 1,
            flags: 0,
            size_of_prolog: 0,
            count_of_codes: 0,
            frame_register: 0,
            frame_offset: 0,
            unwind_codes: Vec::new(),
            handler_rva: None,
            chained_function: None,
        };
        assert!(!ui.has_exception_handler());
        ui.flags = UNW_FLAG_EHANDLER;
        assert!(ui.has_exception_handler());
        ui.flags = UNW_FLAG_UHANDLER;
        assert!(ui.has_exception_handler());
        ui.flags = UNW_FLAG_CHAININFO;
        assert!(!ui.has_exception_handler());
    }
}

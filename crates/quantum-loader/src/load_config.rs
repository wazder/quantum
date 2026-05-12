//! Load Configuration directory. Only the header fields we need tonight
//! (size, security cookie, CFG guard pointers); we don't enforce CFG.
//!
//! `IMAGE_LOAD_CONFIG_DIRECTORY64` is variable-length, growing across
//! Windows versions. The first field is `Size` (u32) which tells us how
//! far it actually goes — we read only what `Size` says is present.

use quantum_core::{Error, Result};

use crate::image::LoadedImage;
use crate::pe::dir;

#[derive(Debug, Clone, Copy, Default)]
pub struct LoadConfig {
    pub size: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub global_flags_clear: u32,
    pub global_flags_set: u32,
    pub critical_section_default_timeout: u32,
    pub decommit_free_block_threshold: u64,
    pub decommit_total_free_threshold: u64,
    pub lock_prefix_table: u64,
    pub maximum_allocation_size: u64,
    pub virtual_memory_threshold: u64,
    pub process_affinity_mask: u64,
    pub process_heap_flags: u32,
    pub csd_version: u16,
    pub dependent_load_flags: u16,
    pub edit_list: u64,
    pub security_cookie_va: u64,
    pub seh_handler_table_va: u64,
    pub seh_handler_count: u64,
    pub guard_cf_check_function_pointer_va: u64,
    pub guard_cf_dispatch_function_pointer_va: u64,
    pub guard_cf_function_table_va: u64,
    pub guard_cf_function_count: u64,
    pub guard_flags: u32,
}

pub fn parse(image: &LoadedImage) -> Result<Option<LoadConfig>> {
    let dir_entry = match image.data_dir(dir::LOAD_CONFIG) {
        Some(d) => d,
        None => return Ok(None),
    };

    // The first u32 is `Size`. Read the whole declared region but bail if
    // it overruns the directory.
    let head = image
        .rva_to_slice(dir_entry.virtual_address, 4)
        .ok_or(Error::Malformed { what: "load_config head", at: dir_entry.virtual_address as usize })?;
    let size = u32::from_le_bytes(head.try_into().unwrap());
    if size < 0x70 || size > dir_entry.size {
        return Err(Error::Malformed {
            what: "load_config size out of range",
            at: dir_entry.virtual_address as usize,
        });
    }

    let bytes = image
        .rva_to_slice(dir_entry.virtual_address, size as usize)
        .ok_or(Error::Malformed { what: "load_config body", at: dir_entry.virtual_address as usize })?;

    // Helper to read fields and return Default when the truncated record
    // doesn't carry them (older binaries).
    let u32_at = |off: usize| {
        bytes
            .get(off..off + 4)
            .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
            .unwrap_or(0)
    };
    let u16_at = |off: usize| {
        bytes
            .get(off..off + 2)
            .map(|s| u16::from_le_bytes([s[0], s[1]]))
            .unwrap_or(0)
    };
    let u64_at = |off: usize| {
        bytes
            .get(off..off + 8)
            .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
            .unwrap_or(0)
    };

    Ok(Some(LoadConfig {
        size,
        time_date_stamp: u32_at(4),
        major_version: u16_at(8),
        minor_version: u16_at(10),
        global_flags_clear: u32_at(12),
        global_flags_set: u32_at(16),
        critical_section_default_timeout: u32_at(20),
        decommit_free_block_threshold: u64_at(24),
        decommit_total_free_threshold: u64_at(32),
        lock_prefix_table: u64_at(40),
        maximum_allocation_size: u64_at(48),
        virtual_memory_threshold: u64_at(56),
        process_affinity_mask: u64_at(64),
        process_heap_flags: u32_at(72),
        csd_version: u16_at(76),
        dependent_load_flags: u16_at(78),
        edit_list: u64_at(80),
        security_cookie_va: u64_at(88),
        seh_handler_table_va: u64_at(96),
        seh_handler_count: u64_at(104),
        guard_cf_check_function_pointer_va: u64_at(112),
        guard_cf_dispatch_function_pointer_va: u64_at(120),
        guard_cf_function_table_va: u64_at(128),
        guard_cf_function_count: u64_at(136),
        guard_flags: u32_at(144),
    }))
}

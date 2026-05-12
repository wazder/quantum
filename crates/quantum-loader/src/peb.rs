//! Process Environment Block / Thread Environment Block construction.
//!
//! On Win64 the guest reads its TEB through `GS:[0]` and PEB through
//! `TEB.ProcessEnvironmentBlock` (GS:[0x60]). We do not aim for ABI-perfect
//! mirrors tonight — we set up enough of these structures that the
//! kernel32 thunks can hand out a `GetModuleHandle`-style image base and
//! return early from `RtlAddFunctionTable`.

use alloc::string::String;
use alloc::vec::Vec;

use crate::image::LoadedImage;

/// Minimal mirror of `_PEB` in winternl.h. Field offsets are kept exact so
/// guest code that walks PEB by hand still works. Fields we don't model
/// stay zeroed.
#[repr(C)]
#[derive(Debug)]
pub struct GuestPeb {
    pub inherited_address_space: u8,
    pub read_image_file_exec_options: u8,
    pub being_debugged: u8,
    pub bit_field: u8,
    pub padding0: [u8; 4],
    pub mutant: u64,
    pub image_base_address: u64,
    pub ldr: u64, // -> GuestPebLdrData
    pub process_parameters: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct GuestPebLdrData {
    pub length: u32,
    pub initialized: u32,
    pub ss_handle: u64,
    pub in_load_order_module_list_flink: u64,
    pub in_load_order_module_list_blink: u64,
    pub in_memory_order_module_list_flink: u64,
    pub in_memory_order_module_list_blink: u64,
    pub in_initialization_order_module_list_flink: u64,
    pub in_initialization_order_module_list_blink: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct GuestTeb {
    pub nt_tib_exception_list: u64,
    pub nt_tib_stack_base: u64,
    pub nt_tib_stack_limit: u64,
    pub nt_tib_sub_system_tib: u64,
    pub nt_tib_fiber_data: u64,
    pub nt_tib_arbitrary_user_pointer: u64,
    pub nt_tib_self: u64,
    pub environment_pointer: u64,
    pub client_id_uniq_process: u64,
    pub client_id_uniq_thread: u64,
    pub active_rpc_handle: u64,
    pub thread_local_storage_pointer: u64,
    pub process_environment_block: u64,
    pub last_error_value: u32,
    pub padding0: u32,
}

#[derive(Debug)]
pub struct GuestImageRecord {
    pub base_va: u64,
    pub size: u32,
    pub entry_va: u64,
    pub dll_name: String,
    pub full_path: String,
}

impl GuestImageRecord {
    pub fn from_loaded(name: impl Into<String>, image: &LoadedImage) -> Self {
        let entry_va = image.actual_base.wrapping_add(image.entry_rva as u64);
        Self {
            base_va: image.actual_base,
            size: image.size_of_image,
            entry_va,
            dll_name: name.into(),
            full_path: String::new(),
        }
    }
}

#[derive(Debug, Default)]
pub struct GuestProcessLayout {
    pub modules: Vec<GuestImageRecord>,
}

impl GuestProcessLayout {
    pub fn push_module(&mut self, m: GuestImageRecord) {
        self.modules.push(m);
    }
}

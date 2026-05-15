//! `ntdll.dll` surface — Rtl* helpers and Nt* syscall thunks.
//!
//! Real games import a long tail of ntdll symbols even when they use
//! the kernel32 wrappers, because the MSVC CRT and Windows itself
//! reach in directly for the cheaper paths. The names covered here
//! are the ones we've actually seen in DX11 games' import tables.
//!
//! Most are thin redirections to our existing kernel32 implementations
//! plus a few zero-arg constants. `Nt*` syscall thunks return
//! `STATUS_SUCCESS` (0) or `STATUS_NOT_IMPLEMENTED` (0xC0000002) so
//! the calling code can choose its fallback path.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::ffi::c_void;

const STATUS_SUCCESS: i32 = 0;
const STATUS_NOT_IMPLEMENTED: i32 = 0xC0000002u32 as i32;

// ---------- Heap (most-used) ----------

#[unsafe(no_mangle)]
pub extern "C" fn RtlAllocateHeap(_heap: usize, _flags: u32, size: usize) -> *mut c_void {
    crate::heap::HeapAlloc(0, 0, size) as *mut c_void
}

#[unsafe(no_mangle)]
pub extern "C" fn RtlReAllocateHeap(
    _heap: usize,
    _flags: u32,
    mem: *mut c_void,
    size: usize,
) -> *mut c_void {
    crate::heap::HeapReAlloc(0, 0, mem as *mut u8, size) as *mut c_void
}

#[unsafe(no_mangle)]
pub extern "C" fn RtlFreeHeap(_heap: usize, _flags: u32, mem: *mut c_void) -> i32 {
    crate::heap::HeapFree(0, 0, mem as *mut u8)
}

#[unsafe(no_mangle)]
pub extern "C" fn RtlSizeHeap(_heap: usize, _flags: u32, mem: *mut c_void) -> usize {
    crate::heap::HeapSize(0, 0, mem as *const u8)
}

// ---------- Critical sections ----------
//
// We funnel through the kernel32 critical-section helpers; the Rtl*
// variants share the same RTL_CRITICAL_SECTION layout the kernel32
// thunks already populate.

#[unsafe(no_mangle)]
pub extern "C" fn RtlInitializeCriticalSection(cs: *mut c_void) -> i32 {
    crate::sync::InitializeCriticalSection(cs as *mut u8);
    STATUS_SUCCESS
}

#[unsafe(no_mangle)]
pub extern "C" fn RtlInitializeCriticalSectionAndSpinCount(
    cs: *mut c_void,
    _spin: u32,
) -> i32 {
    crate::sync::InitializeCriticalSection(cs as *mut u8);
    STATUS_SUCCESS
}

#[unsafe(no_mangle)]
pub extern "C" fn RtlEnterCriticalSection(cs: *mut c_void) {
    crate::sync::EnterCriticalSection(cs as *mut u8);
}

#[unsafe(no_mangle)]
pub extern "C" fn RtlLeaveCriticalSection(cs: *mut c_void) {
    crate::sync::LeaveCriticalSection(cs as *mut u8);
}

#[unsafe(no_mangle)]
pub extern "C" fn RtlDeleteCriticalSection(cs: *mut c_void) {
    crate::sync::DeleteCriticalSection(cs as *mut u8);
}

// ---------- Version ----------

#[repr(C)]
pub struct RtlOsVersionInfoExW {
    pub dw_os_version_info_size: u32,
    pub dw_major_version: u32,
    pub dw_minor_version: u32,
    pub dw_build_number: u32,
    pub dw_platform_id: u32,
    pub sz_csd_version: [u16; 128],
    pub w_service_pack_major: u16,
    pub w_service_pack_minor: u16,
    pub w_suite_mask: u16,
    pub w_product_type: u8,
    pub w_reserved: u8,
}

#[unsafe(no_mangle)]
pub extern "C" fn RtlGetVersion(lp_version_info: *mut RtlOsVersionInfoExW) -> i32 {
    if lp_version_info.is_null() {
        return STATUS_NOT_IMPLEMENTED;
    }
    // Pretend to be Windows 10 1809 (build 17763) — the modal target
    // for DX11 games today.
    unsafe {
        (*lp_version_info).dw_major_version = 10;
        (*lp_version_info).dw_minor_version = 0;
        (*lp_version_info).dw_build_number = 17763;
        (*lp_version_info).dw_platform_id = 2; // VER_PLATFORM_WIN32_NT
        (*lp_version_info).w_product_type = 1; // VER_NT_WORKSTATION
    }
    STATUS_SUCCESS
}

// ---------- Misc Rtl ----------

#[unsafe(no_mangle)]
pub extern "C" fn RtlZeroMemory(dst: *mut c_void, n: usize) {
    if dst.is_null() {
        return;
    }
    // SAFETY: caller asserts dst is writable for n bytes.
    unsafe {
        core::ptr::write_bytes(dst as *mut u8, 0, n);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn RtlCopyMemory(dst: *mut c_void, src: *const c_void, n: usize) {
    if dst.is_null() || src.is_null() {
        return;
    }
    // SAFETY: same contract.
    unsafe {
        core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, n);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn RtlMoveMemory(dst: *mut c_void, src: *const c_void, n: usize) {
    if dst.is_null() || src.is_null() {
        return;
    }
    // SAFETY: copy semantics allow overlap.
    unsafe {
        core::ptr::copy(src as *const u8, dst as *mut u8, n);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn RtlFillMemory(dst: *mut c_void, n: usize, fill: u8) {
    if dst.is_null() {
        return;
    }
    // SAFETY: caller asserts writability.
    unsafe {
        core::ptr::write_bytes(dst as *mut u8, fill, n);
    }
}

// ---------- Nt syscall thunks (stubs) ----------

#[unsafe(no_mangle)]
pub extern "C" fn NtClose(_handle: usize) -> i32 {
    STATUS_SUCCESS
}

#[unsafe(no_mangle)]
pub extern "C" fn NtQuerySystemInformation(
    _info_class: u32,
    _info: *mut c_void,
    _length: u32,
    return_length: *mut u32,
) -> i32 {
    if !return_length.is_null() {
        unsafe {
            *return_length = 0;
        }
    }
    STATUS_NOT_IMPLEMENTED
}

#[unsafe(no_mangle)]
pub extern "C" fn NtQueryInformationProcess(
    _process: usize,
    _info_class: u32,
    _info: *mut c_void,
    _length: u32,
    return_length: *mut u32,
) -> i32 {
    if !return_length.is_null() {
        unsafe {
            *return_length = 0;
        }
    }
    STATUS_NOT_IMPLEMENTED
}

/// Resolver for ntdll.dll imports.
pub fn resolve(function: &str) -> Option<u64> {
    let p: *const () = match function {
        "RtlAllocateHeap" => RtlAllocateHeap as *const (),
        "RtlReAllocateHeap" => RtlReAllocateHeap as *const (),
        "RtlFreeHeap" => RtlFreeHeap as *const (),
        "RtlSizeHeap" => RtlSizeHeap as *const (),
        "RtlInitializeCriticalSection" => RtlInitializeCriticalSection as *const (),
        "RtlInitializeCriticalSectionAndSpinCount" => {
            RtlInitializeCriticalSectionAndSpinCount as *const ()
        }
        "RtlEnterCriticalSection" => RtlEnterCriticalSection as *const (),
        "RtlLeaveCriticalSection" => RtlLeaveCriticalSection as *const (),
        "RtlDeleteCriticalSection" => RtlDeleteCriticalSection as *const (),
        "RtlGetVersion" => RtlGetVersion as *const (),
        "RtlZeroMemory" => RtlZeroMemory as *const (),
        "RtlCopyMemory" => RtlCopyMemory as *const (),
        "RtlMoveMemory" => RtlMoveMemory as *const (),
        "RtlFillMemory" => RtlFillMemory as *const (),
        "NtClose" => NtClose as *const (),
        "NtQuerySystemInformation" => NtQuerySystemInformation as *const (),
        "NtQueryInformationProcess" => NtQueryInformationProcess as *const (),
        _ => return None,
    };
    Some(p as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtl_zero_memory_clears_buffer() {
        let mut buf = [0xAAu8; 16];
        RtlZeroMemory(buf.as_mut_ptr() as *mut c_void, 16);
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn rtl_get_version_reports_windows_10() {
        let mut info = RtlOsVersionInfoExW {
            dw_os_version_info_size: core::mem::size_of::<RtlOsVersionInfoExW>() as u32,
            dw_major_version: 0,
            dw_minor_version: 0,
            dw_build_number: 0,
            dw_platform_id: 0,
            sz_csd_version: [0; 128],
            w_service_pack_major: 0,
            w_service_pack_minor: 0,
            w_suite_mask: 0,
            w_product_type: 0,
            w_reserved: 0,
        };
        let rc = RtlGetVersion(&mut info as *mut _);
        assert_eq!(rc, STATUS_SUCCESS);
        assert_eq!(info.dw_major_version, 10);
        assert_eq!(info.dw_build_number, 17763);
    }

    #[test]
    fn resolve_routes_named_thunks() {
        assert!(resolve("RtlAllocateHeap").is_some());
        assert!(resolve("NtClose").is_some());
        assert!(resolve("RtlGetVersion").is_some());
        assert!(resolve("not_a_real_ntdll_thing").is_none());
    }
}

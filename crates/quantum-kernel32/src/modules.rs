//! Dynamic module loading thunks: LoadLibrary{A,W,Ex{A,W}},
//! FreeLibrary, GetModuleHandle{A,W,Ex{A,W}}, GetProcAddress.
//!
//! Real programs use these in two patterns:
//!
//! 1. **Built-in DLL queries** — pass a name like "kernel32.dll" or
//!    "user32.dll" to obtain a handle, then GetProcAddress against
//!    that handle for a specific function. Sekiro does exactly this
//!    for `d3d11.dll`.
//! 2. **Dynamic plugin loading** — pass an arbitrary path. Out of
//!    scope today; we return NULL for unknown DLL names so callers
//!    notice the failure cleanly.
//!
//! We expose a fixed table of "known modules". Each entry has a
//! sentinel handle the guest can pass back to GetProcAddress, plus
//! a per-DLL function-name resolver. Adding a new DLL is one entry
//! in `MODULES`; the per-DLL resolver lives in that DLL's module.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::ffi::c_void;

/// Handles are sentinel pointer-sized values that the guest treats
/// as opaque. We use unique high values that won't collide with
/// real allocations.
pub const HANDLE_KERNEL32: usize = 0x4000_0000_0000_0000;
pub const HANDLE_USER32: usize = 0x4000_0000_0000_0001;
pub const HANDLE_DXGI: usize = 0x4000_0000_0000_0002;
pub const HANDLE_D3D11: usize = 0x4000_0000_0000_0003;
pub const HANDLE_D3DCOMPILER_43: usize = 0x4000_0000_0000_0004;
pub const HANDLE_ADVAPI32: usize = 0x4000_0000_0000_0005;
pub const HANDLE_WINMM: usize = 0x4000_0000_0000_0006;
pub const HANDLE_GDI32: usize = 0x4000_0000_0000_0007;
pub const HANDLE_WS2_32: usize = 0x4000_0000_0000_0008;
pub const HANDLE_CRYPT32: usize = 0x4000_0000_0000_0009;
pub const HANDLE_WLDAP32: usize = 0x4000_0000_0000_000A;
pub const HANDLE_OLE32: usize = 0x4000_0000_0000_000B;
pub const HANDLE_OLEAUT32: usize = 0x4000_0000_0000_000C;
pub const HANDLE_SHELL32: usize = 0x4000_0000_0000_000D;
pub const HANDLE_IMM32: usize = 0x4000_0000_0000_000E;
pub const HANDLE_XINPUT1_3: usize = 0x4000_0000_0000_000F;
pub const HANDLE_DINPUT8: usize = 0x4000_0000_0000_0010;
pub const HANDLE_STEAM_API64: usize = 0x4000_0000_0000_0011;
pub const HANDLE_NTDLL: usize = 0x4000_0000_0000_0012;
pub const HANDLE_D3D9: usize = 0x4000_0000_0000_0013;
pub const HANDLE_D3DX11: usize = 0x4000_0000_0000_0014;

/// One entry in our known-DLL table.
struct ModuleEntry {
    /// Canonical lowercase name including extension, e.g. "kernel32.dll".
    name: &'static str,
    handle: usize,
    /// Resolver for individual function lookups. Returns the host
    /// function address as a u64 (the IAT slot's value).
    resolve: fn(&str) -> Option<u64>,
}

static MODULES: &[ModuleEntry] = &[
    ModuleEntry {
        name: "kernel32.dll",
        handle: HANDLE_KERNEL32,
        resolve: kernel32_resolve,
    },
    ModuleEntry {
        name: "kernelbase.dll",
        handle: HANDLE_KERNEL32,
        resolve: kernel32_resolve,
    },
    ModuleEntry {
        name: "user32.dll",
        handle: HANDLE_USER32,
        resolve: stub_resolve,
    },
    ModuleEntry {
        name: "dxgi.dll",
        handle: HANDLE_DXGI,
        resolve: stub_resolve,
    },
    ModuleEntry {
        name: "d3d11.dll",
        handle: HANDLE_D3D11,
        resolve: crate::d3d11::resolve,
    },
    ModuleEntry {
        name: "d3dcompiler_43.dll",
        handle: HANDLE_D3DCOMPILER_43,
        resolve: crate::d3d11::resolve_d3dcompiler,
    },
    ModuleEntry {
        name: "d3d9.dll",
        handle: HANDLE_D3D9,
        resolve: crate::d3d11::resolve_d3d9,
    },
    ModuleEntry {
        name: "d3dx11_43.dll",
        handle: HANDLE_D3DX11,
        resolve: crate::d3d11::resolve_d3dx11,
    },
    ModuleEntry {
        name: "advapi32.dll",
        handle: HANDLE_ADVAPI32,
        resolve: stub_resolve,
    },
    ModuleEntry {
        name: "winmm.dll",
        handle: HANDLE_WINMM,
        resolve: stub_resolve,
    },
    ModuleEntry {
        name: "gdi32.dll",
        handle: HANDLE_GDI32,
        resolve: stub_resolve,
    },
    ModuleEntry {
        name: "ws2_32.dll",
        handle: HANDLE_WS2_32,
        resolve: stub_resolve,
    },
    ModuleEntry {
        name: "crypt32.dll",
        handle: HANDLE_CRYPT32,
        resolve: stub_resolve,
    },
    ModuleEntry {
        name: "wldap32.dll",
        handle: HANDLE_WLDAP32,
        resolve: stub_resolve,
    },
    ModuleEntry {
        name: "ole32.dll",
        handle: HANDLE_OLE32,
        resolve: stub_resolve,
    },
    ModuleEntry {
        name: "oleaut32.dll",
        handle: HANDLE_OLEAUT32,
        resolve: stub_resolve,
    },
    ModuleEntry {
        name: "shell32.dll",
        handle: HANDLE_SHELL32,
        resolve: stub_resolve,
    },
    ModuleEntry {
        name: "imm32.dll",
        handle: HANDLE_IMM32,
        resolve: stub_resolve,
    },
    ModuleEntry {
        name: "xinput1_3.dll",
        handle: HANDLE_XINPUT1_3,
        resolve: stub_resolve,
    },
    ModuleEntry {
        name: "dinput8.dll",
        handle: HANDLE_DINPUT8,
        resolve: stub_resolve,
    },
    ModuleEntry {
        name: "steam_api64.dll",
        handle: HANDLE_STEAM_API64,
        resolve: crate::steam::resolve,
    },
    ModuleEntry {
        name: "ntdll.dll",
        handle: HANDLE_NTDLL,
        resolve: stub_resolve,
    },
];

fn kernel32_resolve(function: &str) -> Option<u64> {
    crate::thunks::resolve("kernel32.dll", function)
}

/// Placeholder resolver for DLLs we haven't started yet. Returns None
/// for every lookup; the guest will see GetProcAddress fail and (most
/// often) print an error to its log without crashing.
fn stub_resolve(_function: &str) -> Option<u64> {
    None
}

fn lookup_module(name: &str) -> Option<&'static ModuleEntry> {
    let stripped = strip_path(name);
    let lowered: String = stripped.to_lowercase();
    // Tolerate the common ".dll"-omitted form.
    MODULES.iter().find(|m| {
        m.name.eq_ignore_ascii_case(&lowered)
            || m.name
                .strip_suffix(".dll")
                .is_some_and(|stem| stem.eq_ignore_ascii_case(&lowered))
    })
}

fn lookup_handle(handle: usize) -> Option<&'static ModuleEntry> {
    MODULES.iter().find(|m| m.handle == handle)
}

/// Remove any directory prefix from a DLL path so "C:\\Windows\\System32\\
/// kernel32.dll" matches "kernel32.dll".
fn strip_path(p: &str) -> &str {
    p.rsplit(['\\', '/']).next().unwrap_or(p)
}

unsafe fn read_cstr_a(p: *const i8) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut len = 0usize;
    // SAFETY: caller-supplied; we walk until NUL or up to a 4096-byte
    // bound to avoid runaway reads on a malformed input.
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
            if len > 4096 {
                return None;
            }
        }
        let bytes = core::slice::from_raw_parts(p.cast::<u8>(), len);
        Some(String::from_utf8_lossy(bytes).into_owned())
    }
}

unsafe fn read_cstr_w(p: *const u16) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut len = 0usize;
    // SAFETY: caller-supplied, bounded.
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
            if len > 4096 {
                return None;
            }
        }
        let slice = core::slice::from_raw_parts(p, len);
        Some(String::from_utf16_lossy(slice))
    }
}

/// `HMODULE LoadLibraryA(LPCSTR lpLibFileName)`.
#[unsafe(no_mangle)]
pub extern "C" fn LoadLibraryA(name: *const i8) -> usize {
    // SAFETY: caller-supplied C string, bounded by read_cstr_a.
    let n = unsafe { read_cstr_a(name) };
    n.and_then(|s| lookup_module(&s)).map_or(0, |m| m.handle)
}

#[unsafe(no_mangle)]
pub extern "C" fn LoadLibraryW(name: *const u16) -> usize {
    // SAFETY: caller-supplied UTF-16 string, bounded.
    let n = unsafe { read_cstr_w(name) };
    n.and_then(|s| lookup_module(&s)).map_or(0, |m| m.handle)
}

#[unsafe(no_mangle)]
pub extern "C" fn LoadLibraryExA(name: *const i8, _file: *mut c_void, _flags: u32) -> usize {
    LoadLibraryA(name)
}

#[unsafe(no_mangle)]
pub extern "C" fn LoadLibraryExW(name: *const u16, _file: *mut c_void, _flags: u32) -> usize {
    LoadLibraryW(name)
}

#[unsafe(no_mangle)]
pub extern "C" fn FreeLibrary(_handle: usize) -> i32 {
    // We never unload built-in modules. Return TRUE (success).
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetModuleHandleA(name: *const i8) -> usize {
    if name.is_null() {
        // Per docs: NULL returns the handle of the calling .exe. We
        // don't track that yet; return KERNEL32 as a survivable
        // placeholder.
        return HANDLE_KERNEL32;
    }
    LoadLibraryA(name)
}

#[unsafe(no_mangle)]
pub extern "C" fn GetModuleHandleW(name: *const u16) -> usize {
    if name.is_null() {
        return HANDLE_KERNEL32;
    }
    LoadLibraryW(name)
}

/// `FARPROC GetProcAddress(HMODULE, LPCSTR proc)`. `proc` is either a
/// C string or a 16-bit ordinal in the low bits (IS_INTRESOURCE).
#[unsafe(no_mangle)]
pub extern "C" fn GetProcAddress(handle: usize, proc_name: *const i8) -> *const c_void {
    let module = match lookup_handle(handle) {
        Some(m) => m,
        None => return core::ptr::null(),
    };
    // Ordinal form: low 16 bits set, high bits zero.
    if (proc_name as usize) >> 16 == 0 {
        // We don't have an ordinal table for any module yet; fail.
        return core::ptr::null();
    }
    // SAFETY: caller-supplied C string.
    let name = match unsafe { read_cstr_a(proc_name) } {
        Some(n) => n,
        None => return core::ptr::null(),
    };
    (module.resolve)(&name)
        .map(|addr| addr as *const c_void)
        .unwrap_or(core::ptr::null())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cstr(s: &'static str) -> *const i8 {
        // Test-only — every literal already terminates with nul because
        // we append it explicitly.
        let bytes = s.as_bytes();
        assert!(bytes.last() == Some(&0));
        bytes.as_ptr().cast()
    }

    #[test]
    fn load_library_known_dll() {
        let h = LoadLibraryA(cstr("kernel32.dll\0"));
        assert_eq!(h, HANDLE_KERNEL32);
        // Path form
        let h2 = LoadLibraryA(cstr("C:\\Windows\\System32\\d3d11.dll\0"));
        assert_eq!(h2, HANDLE_D3D11);
        // Forward slashes
        let h3 = LoadLibraryA(cstr("C:/Windows/System32/dxgi.dll\0"));
        assert_eq!(h3, HANDLE_DXGI);
        // Case insensitive
        let h4 = LoadLibraryA(cstr("KERNEL32.DLL\0"));
        assert_eq!(h4, HANDLE_KERNEL32);
        // Without .dll suffix
        let h5 = LoadLibraryA(cstr("kernel32\0"));
        assert_eq!(h5, HANDLE_KERNEL32);
    }

    #[test]
    fn load_library_unknown_returns_zero() {
        let h = LoadLibraryA(cstr("NoSuchLibrary.dll\0"));
        assert_eq!(h, 0);
    }

    #[test]
    fn get_proc_address_kernel32_exitprocess() {
        let h = LoadLibraryA(cstr("kernel32.dll\0"));
        let p = GetProcAddress(h, cstr("ExitProcess\0"));
        assert!(!p.is_null());
        assert_eq!(
            p as usize,
            crate::process::ExitProcess as *const () as usize
        );
    }

    #[test]
    fn get_proc_address_unknown_function_null() {
        let h = LoadLibraryA(cstr("kernel32.dll\0"));
        let p = GetProcAddress(h, cstr("NoSuchFunction\0"));
        assert!(p.is_null());
    }

    #[test]
    fn free_library_returns_true() {
        let h = LoadLibraryA(cstr("kernel32.dll\0"));
        assert_eq!(FreeLibrary(h), 1);
    }

    #[test]
    fn get_module_handle_null_returns_self() {
        let h = GetModuleHandleA(core::ptr::null());
        assert_eq!(h, HANDLE_KERNEL32);
    }
}

//! Small Win32 DLL surfaces with handful-of-functions each.
//! Grouped here to avoid one tiny file per DLL.
//!
//! Coverage:
//! - shell32: SHGetFolderPathW, CommandLineToArgvW
//! - ole32:   CoInitializeEx, CoCreateInstance, CoTaskMemAlloc/Free, CoUninitialize
//! - imm32:   ImmDisableIME
//! - crypt32: certificate APIs (most stubbed to NULL/failure)
//! - dinput8: DirectInput8Create
//!
//! WLDAP32, OLEAUT32, XINPUT1_3 import by ordinal only on Sekiro; an
//! ordinal-aware resolver path is a separate task.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::ffi::c_void;

// ---------- shell32 ----------

#[allow(dead_code)]
const FAKE_HANDLE: usize = 0x4000_0000_0004_0000;

/// `HRESULT SHGetFolderPathW(HWND, int csidl, HANDLE token, DWORD flags, LPWSTR path)`.
/// Returns a default home-style path written in UTF-16. CSIDL distinctions
/// (Documents vs AppData vs LocalAppData) all map to the same default for now.
#[unsafe(no_mangle)]
pub extern "C" fn SHGetFolderPathW(
    _hwnd: usize,
    _csidl: i32,
    _token: usize,
    _flags: u32,
    path: *mut u16,
) -> i32 {
    if !path.is_null() {
        // "C:\\Users\\user\0" — a generic location.
        let s: [u16; 13] = [
            b'C' as u16,
            b':' as u16,
            b'\\' as u16,
            b'U' as u16,
            b's' as u16,
            b'e' as u16,
            b'r' as u16,
            b's' as u16,
            b'\\' as u16,
            b'u' as u16,
            b's' as u16,
            b'e' as u16,
            b'r' as u16,
        ];
        unsafe {
            core::ptr::copy_nonoverlapping(s.as_ptr(), path, s.len());
            *path.add(s.len()) = 0;
        }
    }
    0
}

/// `LPWSTR *CommandLineToArgvW(LPCWSTR cmdline, int *numargs)`.
/// We return a pointer to a static one-element array; almost every
/// caller just walks numargs/argv until cleanup. Real parsing is a
/// future enhancement.
#[unsafe(no_mangle)]
pub extern "C" fn CommandLineToArgvW(_cmdline: *const u16, numargs: *mut i32) -> *mut *mut u16 {
    if !numargs.is_null() {
        unsafe {
            *numargs = 0;
        }
    }
    core::ptr::null_mut()
}

// ---------- ole32 ----------

#[unsafe(no_mangle)]
pub extern "C" fn CoInitialize(_reserved: *mut c_void) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn CoInitializeEx(_reserved: *mut c_void, _coinit: u32) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn CoUninitialize() {}

#[unsafe(no_mangle)]
pub extern "C" fn CoCreateInstance(
    _rclsid: *const c_void,
    _outer: *mut c_void,
    _ctx: u32,
    _riid: *const c_void,
    pp_v: *mut *mut c_void,
) -> i32 {
    if !pp_v.is_null() {
        unsafe {
            *pp_v = core::ptr::null_mut();
        }
    }
    // E_NOINTERFACE — caller treats as "no implementation".
    0x8000_4002u32 as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn CoTaskMemAlloc(cb: usize) -> *mut c_void {
    crate::heap::HeapAlloc(crate::heap::GetProcessHeap(), 0, cb) as *mut c_void
}

#[unsafe(no_mangle)]
pub extern "C" fn CoTaskMemFree(mem: *mut c_void) {
    if !mem.is_null() {
        crate::heap::HeapFree(crate::heap::GetProcessHeap(), 0, mem as *mut u8);
    }
}

// ---------- imm32 ----------

#[unsafe(no_mangle)]
pub extern "C" fn ImmDisableIME(_thread_id: u32) -> i32 {
    1
}

// ---------- crypt32 ----------

#[unsafe(no_mangle)]
pub extern "C" fn CertDuplicateCertificateContext(_ctx: *mut c_void) -> *mut c_void {
    core::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub extern "C" fn CertGetCertificateContextProperty(
    _ctx: *mut c_void,
    _prop_id: u32,
    _data: *mut c_void,
    _data_len: *mut u32,
) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn CertFreeCertificateContext(_ctx: *mut c_void) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn CryptDecodeObjectEx(
    _encoding: u32,
    _struct_type: *const c_void,
    _encoded: *const u8,
    _encoded_len: u32,
    _flags: u32,
    _decoder: *mut c_void,
    _info: *mut c_void,
    _info_len: *mut u32,
) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn CertOpenStore(
    _store_provider: *const i8,
    _encoding: u32,
    _crypt_prov: usize,
    _flags: u32,
    _para: *const c_void,
) -> *mut c_void {
    core::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub extern "C" fn CertCloseStore(_store: *mut c_void, _flags: u32) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn CertEnumCertificatesInStore(
    _store: *mut c_void,
    _prev: *mut c_void,
) -> *mut c_void {
    core::ptr::null_mut()
}

// ---------- dinput8 ----------

#[unsafe(no_mangle)]
pub extern "C" fn DirectInput8Create(
    _h_inst: *mut c_void,
    _version: u32,
    _riid: *const c_void,
    pp_v: *mut *mut c_void,
    _outer: *mut c_void,
) -> i32 {
    if !pp_v.is_null() {
        unsafe {
            *pp_v = core::ptr::null_mut();
        }
    }
    // DIERR_NOTAVAIL — caller falls back gracefully.
    0x8004_0220u32 as i32
}

// ---------- Resolvers ----------

pub fn resolve_shell32(function: &str) -> Option<u64> {
    let p: *const () = match function {
        "SHGetFolderPathW" => SHGetFolderPathW as *const (),
        "CommandLineToArgvW" => CommandLineToArgvW as *const (),
        _ => return None,
    };
    Some(p as u64)
}

pub fn resolve_ole32(function: &str) -> Option<u64> {
    let p: *const () = match function {
        "CoInitialize" => CoInitialize as *const (),
        "CoInitializeEx" => CoInitializeEx as *const (),
        "CoUninitialize" => CoUninitialize as *const (),
        "CoCreateInstance" => CoCreateInstance as *const (),
        "CoTaskMemAlloc" => CoTaskMemAlloc as *const (),
        "CoTaskMemFree" => CoTaskMemFree as *const (),
        _ => return None,
    };
    Some(p as u64)
}

pub fn resolve_imm32(function: &str) -> Option<u64> {
    match function {
        "ImmDisableIME" => Some(ImmDisableIME as *const () as u64),
        _ => None,
    }
}

pub fn resolve_crypt32(function: &str) -> Option<u64> {
    let p: *const () = match function {
        "CertDuplicateCertificateContext" => CertDuplicateCertificateContext as *const (),
        "CertGetCertificateContextProperty" => CertGetCertificateContextProperty as *const (),
        "CertFreeCertificateContext" => CertFreeCertificateContext as *const (),
        "CryptDecodeObjectEx" => CryptDecodeObjectEx as *const (),
        "CertOpenStore" => CertOpenStore as *const (),
        "CertCloseStore" => CertCloseStore as *const (),
        "CertEnumCertificatesInStore" => CertEnumCertificatesInStore as *const (),
        _ => return None,
    };
    Some(p as u64)
}

pub fn resolve_dinput8(function: &str) -> Option<u64> {
    match function {
        "DirectInput8Create" => Some(DirectInput8Create as *const () as u64),
        _ => None,
    }
}

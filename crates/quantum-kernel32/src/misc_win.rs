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

// ---------- Ordinal-only DLLs ----------
//
// Some DLLs Sekiro pulls export functions only by ordinal: WLDAP32,
// OLEAUT32, XINPUT1_3. The loader's resolver receives `"#NNN"` for
// these, so we match the same way.

/// `BSTR SysAllocString(const OLECHAR *psz)` — OLEAUT32 ord 2.
/// Allocate a length-prefixed UTF-16 string. We use HeapAlloc.
#[unsafe(no_mangle)]
pub extern "C" fn SysAllocString(psz: *const u16) -> *mut u16 {
    if psz.is_null() {
        return core::ptr::null_mut();
    }
    // Walk to find length.
    let mut len: usize = 0;
    unsafe {
        while *psz.add(len) != 0 {
            len += 1;
        }
    }
    let byte_len = len * 2;
    // BSTR layout: u32 byte_len, then UTF-16 chars, then NUL.
    let total = 4 + byte_len + 2;
    let raw = crate::heap::HeapAlloc(crate::heap::GetProcessHeap(), 0, total);
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        *(raw as *mut u32) = byte_len as u32;
        let chars = raw.add(4) as *mut u16;
        core::ptr::copy_nonoverlapping(psz, chars, len);
        *chars.add(len) = 0;
        chars
    }
}

/// `void SysFreeString(BSTR)` — OLEAUT32 ord 6.
#[unsafe(no_mangle)]
pub extern "C" fn SysFreeString(bstr: *mut u16) {
    if bstr.is_null() {
        return;
    }
    // The allocation started 4 bytes before the char pointer.
    let raw = unsafe { (bstr as *mut u8).sub(4) };
    crate::heap::HeapFree(crate::heap::GetProcessHeap(), 0, raw);
}

#[repr(C)]
#[derive(Default)]
pub struct XInputState {
    packet_number: u32,
    gamepad: XInputGamepad,
}

#[repr(C)]
#[derive(Default)]
pub struct XInputGamepad {
    buttons: u16,
    left_trigger: u8,
    right_trigger: u8,
    thumb_lx: i16,
    thumb_ly: i16,
    thumb_rx: i16,
    thumb_ry: i16,
}

/// `DWORD XInputGetState(DWORD dwUserIndex, XINPUT_STATE *pState)` — ord 3.
/// No controller wired today; return ERROR_DEVICE_NOT_CONNECTED so the
/// game falls back to keyboard input.
#[unsafe(no_mangle)]
pub extern "C" fn XInputGetState(_user_index: u32, state: *mut XInputState) -> u32 {
    if !state.is_null() {
        unsafe {
            core::ptr::write_bytes(state, 0, 1);
        }
    }
    // ERROR_DEVICE_NOT_CONNECTED = 0x48F (1167).
    1167
}

#[repr(C)]
#[derive(Default)]
pub struct XInputCapabilities {
    typ: u8,
    sub_type: u8,
    flags: u16,
    gamepad: XInputGamepad,
    vibration: [u16; 2],
}

/// `DWORD XInputGetCapabilities(DWORD dwUserIndex, DWORD dwFlags, XINPUT_CAPABILITIES *pCaps)` — ord 2.
#[unsafe(no_mangle)]
pub extern "C" fn XInputGetCapabilities(
    _user_index: u32,
    _flags: u32,
    caps: *mut XInputCapabilities,
) -> u32 {
    if !caps.is_null() {
        unsafe {
            core::ptr::write_bytes(caps, 0, 1);
        }
    }
    1167
}

/// Generic "this ordinal isn't implemented yet" thunk. WLDAP32's
/// ordinals (#26, #27, etc.) point here so IAT wiring succeeds; if the
/// guest actually invokes one we return 0 (most LDAP error codes are
/// positive integers but 0 happens to be LDAP_SUCCESS, so callers
/// proceed; later sites that depend on real results will error
/// gracefully somewhere downstream).
#[unsafe(no_mangle)]
pub extern "C" fn ordinal_stub_zero() -> u64 {
    0
}

pub fn resolve_oleaut32(function: &str) -> Option<u64> {
    match function {
        "#2" => Some(SysAllocString as *const () as u64),
        "#6" => Some(SysFreeString as *const () as u64),
        _ => None,
    }
}

pub fn resolve_xinput1_3(function: &str) -> Option<u64> {
    match function {
        "#2" => Some(XInputGetCapabilities as *const () as u64),
        "#3" => Some(XInputGetState as *const () as u64),
        _ => None,
    }
}

/// WLDAP32 ordinal -> generic noop. All 16 Sekiro ordinal imports here
/// route to a single zero-returning thunk. A real LDAP client comes if
/// the game ever actually exercises this path.
pub fn resolve_wldap32(function: &str) -> Option<u64> {
    if function.starts_with('#') {
        Some(ordinal_stub_zero as *const () as u64)
    } else {
        None
    }
}

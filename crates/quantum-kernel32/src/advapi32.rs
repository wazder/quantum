//! `advapi32.dll` surface — security, crypto, event log.
//!
//! Stubs:
//! - Crypto*: most return 0 (failure) so callers fall back to a CPU
//!   path. CryptGenRandom is the exception — we wire it through to
//!   /dev/urandom on macOS so guests get usable entropy without
//!   needing a full crypto implementation.
//! - Security descriptors: zero-init the buffer and return success.
//! - ReportEventW / RegisterEventSourceW: no-op success — the Event
//!   Log is purely a logging concept on Windows.
//! - GetUserName: fill in "user" / "User" and return success.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::ffi::c_void;

const FAKE_HANDLE: usize = 0x4000_0000_0003_0000;

// ---------- Crypt* ----------

#[unsafe(no_mangle)]
pub extern "C" fn CryptAcquireContextA(
    out_prov: *mut usize,
    _container: *const i8,
    _provider: *const i8,
    _prov_type: u32,
    _flags: u32,
) -> i32 {
    if !out_prov.is_null() {
        unsafe {
            *out_prov = FAKE_HANDLE;
        }
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn CryptAcquireContextW(
    out_prov: *mut usize,
    _container: *const u16,
    _provider: *const u16,
    _prov_type: u32,
    _flags: u32,
) -> i32 {
    if !out_prov.is_null() {
        unsafe {
            *out_prov = FAKE_HANDLE;
        }
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn CryptReleaseContext(_prov: usize, _flags: u32) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn CryptCreateHash(
    _prov: usize,
    _algid: u32,
    _key: usize,
    _flags: u32,
    out_hash: *mut usize,
) -> i32 {
    if !out_hash.is_null() {
        unsafe {
            *out_hash = FAKE_HANDLE;
        }
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn CryptHashData(_hash: usize, _data: *const u8, _len: u32, _flags: u32) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn CryptGetHashParam(
    _hash: usize,
    _param: u32,
    _data: *mut u8,
    _data_len: *mut u32,
    _flags: u32,
) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn CryptDestroyHash(_hash: usize) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn CryptSignHashW(
    _hash: usize,
    _key_spec: u32,
    _desc: *const u16,
    _flags: u32,
    _signature: *mut u8,
    _sig_len: *mut u32,
) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn CryptDecrypt(
    _key: usize,
    _hash: usize,
    _final_: i32,
    _flags: u32,
    _data: *mut u8,
    _data_len: *mut u32,
) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn CryptExportKey(
    _key: usize,
    _exp_key: usize,
    _blob_type: u32,
    _flags: u32,
    _data: *mut u8,
    _data_len: *mut u32,
) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn CryptGetUserKey(_prov: usize, _key_spec: u32, _key: *mut usize) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn CryptGetProvParam(
    _prov: usize,
    _param: u32,
    _data: *mut u8,
    _data_len: *mut u32,
    _flags: u32,
) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn CryptSetHashParam(
    _hash: usize,
    _param: u32,
    _data: *const u8,
    _flags: u32,
) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn CryptDestroyKey(_key: usize) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn CryptEnumProvidersW(
    _index: u32,
    _reserved: *mut u32,
    _flags: u32,
    _prov_type: *mut u32,
    _name: *mut u16,
    _name_len: *mut u32,
) -> i32 {
    // ERROR_NO_MORE_ITEMS — caller stops enumeration immediately.
    0
}

/// `BOOL CryptGenRandom(HCRYPTPROV, DWORD len, BYTE *buf)`.
/// Fills `buf` with bytes from /dev/urandom. Used by every modern game
/// for any seed / nonce / GUID.
#[unsafe(no_mangle)]
pub extern "C" fn CryptGenRandom(_prov: usize, len: u32, buf: *mut u8) -> i32 {
    if buf.is_null() || len == 0 {
        return 1;
    }
    unsafe {
        let slice = core::slice::from_raw_parts_mut(buf, len as usize);
        fill_random(slice);
    }
    1
}

/// `BOOLEAN SystemFunction036(PVOID buffer, ULONG len)` — RtlGenRandom
/// in disguise. Same semantics as CryptGenRandom.
#[unsafe(no_mangle)]
pub extern "C" fn SystemFunction036(buf: *mut u8, len: u32) -> u8 {
    if buf.is_null() || len == 0 {
        return 1;
    }
    unsafe {
        let slice = core::slice::from_raw_parts_mut(buf, len as usize);
        fill_random(slice);
    }
    1
}

fn fill_random(buf: &mut [u8]) {
    use std::io::Read;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(buf);
    } else {
        // Fallback: deterministic-by-elapsed-time. Better than zero.
        let mut seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        for byte in buf.iter_mut() {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *byte = (seed >> 32) as u8;
        }
    }
}

// ---------- Event log ----------

#[unsafe(no_mangle)]
pub extern "C" fn RegisterEventSourceW(_server: *const u16, _source: *const u16) -> usize {
    FAKE_HANDLE
}

#[unsafe(no_mangle)]
pub extern "C" fn DeregisterEventSource(_log: usize) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn ReportEventW(
    _log: usize,
    _type: u16,
    _category: u16,
    _event_id: u32,
    _sid: *const c_void,
    _strings_count: u16,
    _data_size: u32,
    _strings: *const *const u16,
    _data: *const c_void,
) -> i32 {
    1
}

// ---------- Security ----------

#[unsafe(no_mangle)]
pub extern "C" fn InitializeSecurityDescriptor(sd: *mut u8, _revision: u32) -> i32 {
    if !sd.is_null() {
        unsafe {
            // SECURITY_DESCRIPTOR is 20 bytes on Win64; zero it for safety.
            core::ptr::write_bytes(sd, 0, 20);
        }
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn SetSecurityDescriptorDacl(
    _sd: *mut u8,
    _present: i32,
    _dacl: *const c_void,
    _defaulted: i32,
) -> i32 {
    1
}

// ---------- User info ----------

#[unsafe(no_mangle)]
pub extern "C" fn GetUserNameA(buf: *mut u8, len: *mut u32) -> i32 {
    let name = b"user\0";
    if !len.is_null() {
        unsafe {
            let avail = *len as usize;
            if !buf.is_null() && avail >= name.len() {
                core::ptr::copy_nonoverlapping(name.as_ptr(), buf, name.len());
            }
            *len = name.len() as u32;
        }
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetUserNameW(buf: *mut u16, len: *mut u32) -> i32 {
    let name: [u16; 5] = [b'u' as u16, b's' as u16, b'e' as u16, b'r' as u16, 0];
    if !len.is_null() {
        unsafe {
            let avail = *len as usize;
            if !buf.is_null() && avail >= name.len() {
                core::ptr::copy_nonoverlapping(name.as_ptr(), buf, name.len());
            }
            *len = name.len() as u32;
        }
    }
    1
}

pub fn resolve(function: &str) -> Option<u64> {
    let p: *const () = match function {
        "CryptAcquireContextA" => CryptAcquireContextA as *const (),
        "CryptAcquireContextW" => CryptAcquireContextW as *const (),
        "CryptReleaseContext" => CryptReleaseContext as *const (),
        "CryptCreateHash" => CryptCreateHash as *const (),
        "CryptHashData" => CryptHashData as *const (),
        "CryptGetHashParam" => CryptGetHashParam as *const (),
        "CryptDestroyHash" => CryptDestroyHash as *const (),
        "CryptSignHashW" => CryptSignHashW as *const (),
        "CryptDecrypt" => CryptDecrypt as *const (),
        "CryptExportKey" => CryptExportKey as *const (),
        "CryptGetUserKey" => CryptGetUserKey as *const (),
        "CryptGetProvParam" => CryptGetProvParam as *const (),
        "CryptSetHashParam" => CryptSetHashParam as *const (),
        "CryptDestroyKey" => CryptDestroyKey as *const (),
        "CryptEnumProvidersW" => CryptEnumProvidersW as *const (),
        "CryptGenRandom" => CryptGenRandom as *const (),
        "SystemFunction036" => SystemFunction036 as *const (),
        "RegisterEventSourceW" => RegisterEventSourceW as *const (),
        "DeregisterEventSource" => DeregisterEventSource as *const (),
        "ReportEventW" => ReportEventW as *const (),
        "InitializeSecurityDescriptor" => InitializeSecurityDescriptor as *const (),
        "SetSecurityDescriptorDacl" => SetSecurityDescriptorDacl as *const (),
        "GetUserNameA" => GetUserNameA as *const (),
        "GetUserNameW" => GetUserNameW as *const (),
        _ => return None,
    };
    Some(p as u64)
}

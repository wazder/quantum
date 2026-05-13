//! `gdi32.dll` surface — minimal text-rendering / drawing stubs.
//! All Sekiro imports are font / bitmap helpers; return success-shaped
//! values without doing any real drawing.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::ffi::c_void;

const FAKE_HANDLE: usize = 0x4000_0000_0002_0000;

#[unsafe(no_mangle)]
pub extern "C" fn CreateFontW(
    _height: i32,
    _width: i32,
    _escapement: i32,
    _orientation: i32,
    _weight: i32,
    _italic: u32,
    _underline: u32,
    _strikeout: u32,
    _charset: u32,
    _out_prec: u32,
    _clip_prec: u32,
    _quality: u32,
    _pitch_family: u32,
    _face: *const u16,
) -> usize {
    FAKE_HANDLE
}

#[unsafe(no_mangle)]
pub extern "C" fn SelectObject(_hdc: usize, _obj: usize) -> usize {
    FAKE_HANDLE
}

#[unsafe(no_mangle)]
pub extern "C" fn DeleteObject(_obj: usize) -> i32 {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn CreateBitmap(
    _w: i32,
    _h: i32,
    _planes: u32,
    _bit_count: u32,
    _bits: *const c_void,
) -> usize {
    FAKE_HANDLE
}

#[unsafe(no_mangle)]
pub extern "C" fn GetTextMetricsW(_hdc: usize, metrics: *mut c_void) -> i32 {
    // Zero-fill the TEXTMETRICW struct (60 bytes). Callers reading
    // tmHeight etc. get sane zeros; rendering won't use them anyway.
    if !metrics.is_null() {
        unsafe {
            core::ptr::write_bytes(metrics as *mut u8, 0, 60);
        }
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetGlyphOutlineW(
    _hdc: usize,
    _ch: u32,
    _format: u32,
    _metrics: *mut c_void,
    _buf_size: u32,
    _buf: *mut c_void,
    _xform: *const c_void,
) -> u32 {
    // GDI_ERROR — caller treats this as "glyph not available".
    0xFFFF_FFFF
}

#[unsafe(no_mangle)]
pub extern "C" fn GetKerningPairsW(_hdc: usize, _table_size: u32, _pairs: *mut c_void) -> u32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn EnumFontFamiliesExW(
    _hdc: usize,
    _logfont: *const c_void,
    _proc: *mut c_void,
    _l_param: usize,
    _flags: u32,
) -> i32 {
    // Return 0 = no fonts enumerated; callback never invoked.
    0
}

pub fn resolve(function: &str) -> Option<u64> {
    let p: *const () = match function {
        "CreateFontW" => CreateFontW as *const (),
        "SelectObject" => SelectObject as *const (),
        "DeleteObject" => DeleteObject as *const (),
        "CreateBitmap" => CreateBitmap as *const (),
        "GetTextMetricsW" => GetTextMetricsW as *const (),
        "GetGlyphOutlineW" => GetGlyphOutlineW as *const (),
        "GetKerningPairsW" => GetKerningPairsW as *const (),
        "EnumFontFamiliesExW" => EnumFontFamiliesExW as *const (),
        _ => return None,
    };
    Some(p as u64)
}

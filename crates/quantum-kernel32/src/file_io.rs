//! Real file I/O: CreateFileW / ReadFile / WriteFile etc. backed by
//! POSIX file descriptors. Path translation is intentionally simple:
//!
//!   * `\\` → `/`
//!   * leading `[A-Z]:` drive letter stripped (treated as relative)
//!
//! Sekiro's game data lives next to the EXE, and the CLI chdirs to the
//! EXE directory before launching, so relative-path semantics are what
//! we want.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::ffi::c_void;
use std::ffi::CString;

use crate::handles::{self, KernelObject};

const INVALID_HANDLE_VALUE: usize = usize::MAX;

/// Translate a Windows-style path into a POSIX one.
fn translate_path(win: &str) -> String {
    let mut s = win.replace('\\', "/");
    // Strip drive-letter prefix "X:" if present.
    if s.len() >= 2 {
        let b = s.as_bytes();
        if (b[0].is_ascii_alphabetic()) && b[1] == b':' {
            s = s.split_off(2);
        }
    }
    s
}

fn wide_to_string(wide: *const u16) -> Option<String> {
    if wide.is_null() {
        return None;
    }
    unsafe {
        let mut len = 0;
        while *wide.add(len) != 0 {
            len += 1;
            if len > 4096 {
                return None;
            }
        }
        let slice = core::slice::from_raw_parts(wide, len);
        String::from_utf16(slice).ok()
    }
}

fn cstr_to_string(p: *const i8) -> Option<String> {
    if p.is_null() {
        return None;
    }
    unsafe {
        let mut len = 0;
        while *p.add(len) != 0 {
            len += 1;
            if len > 4096 {
                return None;
            }
        }
        let bytes = core::slice::from_raw_parts(p as *const u8, len);
        Some(String::from_utf8_lossy(bytes).into_owned())
    }
}

/// Win32 `dwDesiredAccess` flags.
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
/// `dwCreationDisposition` values.
const CREATE_NEW: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;
const OPEN_ALWAYS: u32 = 4;
const TRUNCATE_EXISTING: u32 = 5;

fn open_file(path: &str, access: u32, disp: u32) -> Option<i32> {
    let posix = translate_path(path);
    let mut flags: i32 = 0;
    let want_read = access & GENERIC_READ != 0;
    let want_write = access & GENERIC_WRITE != 0;
    match (want_read, want_write) {
        (true, true) => flags |= 0o2,  // O_RDWR
        (false, true) => flags |= 0o1, // O_WRONLY
        _ => {}                        // default O_RDONLY = 0
    }
    match disp {
        CREATE_NEW => flags |= 0o100 | 0o200,     // O_CREAT | O_EXCL
        CREATE_ALWAYS => flags |= 0o100 | 0o1000, // O_CREAT | O_TRUNC
        OPEN_EXISTING => {}
        OPEN_ALWAYS => flags |= 0o100,        // O_CREAT
        TRUNCATE_EXISTING => flags |= 0o1000, // O_TRUNC
        _ => return None,
    }
    let cstr = CString::new(posix).ok()?;
    let fd = unsafe { libc_open(cstr.as_ptr(), flags, 0o644) };
    if fd < 0 { None } else { Some(fd) }
}

unsafe extern "C" {
    #[link_name = "open"]
    fn libc_open(path: *const i8, flags: i32, mode: u32) -> i32;
    #[link_name = "close"]
    #[allow(dead_code)]
    fn libc_close(fd: i32) -> i32;
    #[link_name = "read"]
    fn libc_read(fd: i32, buf: *mut c_void, count: usize) -> isize;
    #[link_name = "write"]
    fn libc_write(fd: i32, buf: *const c_void, count: usize) -> isize;
    #[link_name = "lseek"]
    fn libc_lseek(fd: i32, offset: i64, whence: i32) -> i64;
    #[link_name = "fstat"]
    fn libc_fstat(fd: i32, statbuf: *mut StatBuf) -> i32;
}

/// Darwin's `struct stat` partial layout — we only read `st_size`.
#[repr(C)]
struct StatBuf {
    _pad_before_size: [u8; 96],
    pub st_size: i64,
    _pad_after_size: [u8; 32],
}

#[unsafe(no_mangle)]
pub extern "C" fn CreateFileA(
    name: *const i8,
    access: u32,
    _share: u32,
    _sa: *mut c_void,
    disp: u32,
    _flags: u32,
    _tmpl: usize,
) -> usize {
    let path = match cstr_to_string(name) {
        Some(p) => p,
        None => return INVALID_HANDLE_VALUE,
    };
    match open_file(&path, access, disp) {
        Some(fd) => handles::insert(KernelObject::File(fd)),
        None => INVALID_HANDLE_VALUE,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn CreateFileW(
    name: *const u16,
    access: u32,
    _share: u32,
    _sa: *mut c_void,
    disp: u32,
    _flags: u32,
    _tmpl: usize,
) -> usize {
    let path = match wide_to_string(name) {
        Some(p) => p,
        None => return INVALID_HANDLE_VALUE,
    };
    match open_file(&path, access, disp) {
        Some(fd) => handles::insert(KernelObject::File(fd)),
        None => INVALID_HANDLE_VALUE,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ReadFile(
    handle: usize,
    buf: *mut c_void,
    count: u32,
    bytes_read_out: *mut u32,
    _ovl: *mut c_void,
) -> i32 {
    let obj = match handles::get(handle) {
        Some(o) => o,
        None => return 0,
    };
    let fd = match &*obj {
        KernelObject::File(fd) => *fd,
        _ => return 0,
    };
    let n = unsafe { libc_read(fd, buf, count as usize) };
    if n < 0 {
        return 0;
    }
    if !bytes_read_out.is_null() {
        unsafe {
            *bytes_read_out = n as u32;
        }
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn WriteFile(
    handle: usize,
    buf: *const c_void,
    count: u32,
    bytes_written_out: *mut u32,
    _ovl: *mut c_void,
) -> i32 {
    // Stdio path: delegate to io::write_stdio (HostFd-backed).
    let fd_i = handle as i32;
    if (0..=2).contains(&fd_i) {
        return crate::io::write_stdio(handle, buf as *const u8, count, bytes_written_out, 0);
    }
    let obj = match handles::get(handle) {
        Some(o) => o,
        None => return 0,
    };
    let fd = match &*obj {
        KernelObject::File(fd) => *fd,
        _ => return 0,
    };
    let n = unsafe { libc_write(fd, buf, count as usize) };
    if n < 0 {
        return 0;
    }
    if !bytes_written_out.is_null() {
        unsafe {
            *bytes_written_out = n as u32;
        }
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn GetFileSize(handle: usize, high: *mut u32) -> u32 {
    let obj = match handles::get(handle) {
        Some(o) => o,
        None => return 0xFFFF_FFFF,
    };
    let fd = match &*obj {
        KernelObject::File(fd) => *fd,
        _ => return 0xFFFF_FFFF,
    };
    let mut st: StatBuf = unsafe { core::mem::zeroed() };
    let r = unsafe { libc_fstat(fd, &mut st as *mut _) };
    if r < 0 {
        return 0xFFFF_FFFF;
    }
    if !high.is_null() {
        unsafe {
            *high = (st.st_size >> 32) as u32;
        }
    }
    st.st_size as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn GetFileSizeEx(handle: usize, size_out: *mut i64) -> i32 {
    let obj = match handles::get(handle) {
        Some(o) => o,
        None => return 0,
    };
    let fd = match &*obj {
        KernelObject::File(fd) => *fd,
        _ => return 0,
    };
    let mut st: StatBuf = unsafe { core::mem::zeroed() };
    let r = unsafe { libc_fstat(fd, &mut st as *mut _) };
    if r < 0 {
        return 0;
    }
    if !size_out.is_null() {
        unsafe {
            *size_out = st.st_size;
        }
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn SetFilePointer(handle: usize, low: i32, high: *mut i32, method: u32) -> u32 {
    let high_val = if !high.is_null() {
        unsafe { *high as i64 }
    } else {
        0
    };
    let dist = (high_val << 32) | (low as u32 as i64);
    let whence = match method {
        0 => 0, // FILE_BEGIN -> SEEK_SET
        1 => 1, // FILE_CURRENT -> SEEK_CUR
        2 => 2, // FILE_END -> SEEK_END
        _ => return 0xFFFF_FFFF,
    };
    let obj = match handles::get(handle) {
        Some(o) => o,
        None => return 0xFFFF_FFFF,
    };
    let fd = match &*obj {
        KernelObject::File(fd) => *fd,
        _ => return 0xFFFF_FFFF,
    };
    let new_off = unsafe { libc_lseek(fd, dist, whence) };
    if new_off < 0 {
        return 0xFFFF_FFFF;
    }
    if !high.is_null() {
        unsafe {
            *high = (new_off >> 32) as i32;
        }
    }
    new_off as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn SetFilePointerEx(
    handle: usize,
    dist: i64,
    new_pos: *mut i64,
    method: u32,
) -> i32 {
    let whence = match method {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => return 0,
    };
    let obj = match handles::get(handle) {
        Some(o) => o,
        None => return 0,
    };
    let fd = match &*obj {
        KernelObject::File(fd) => *fd,
        _ => return 0,
    };
    let new_off = unsafe { libc_lseek(fd, dist, whence) };
    if new_off < 0 {
        return 0;
    }
    if !new_pos.is_null() {
        unsafe {
            *new_pos = new_off;
        }
    }
    1
}

/// Hook the kernel32 resolver so the real CreateFile/ReadFile/WriteFile/
/// SetFilePointer/GetFileSize land here instead of in stubs.rs.
pub fn resolve(function: &str) -> Option<u64> {
    let p: *const () = match function {
        "CreateFileA" => CreateFileA as *const (),
        "CreateFileW" => CreateFileW as *const (),
        "ReadFile" => ReadFile as *const (),
        "WriteFile" => WriteFile as *const (),
        "GetFileSize" => GetFileSize as *const (),
        "GetFileSizeEx" => GetFileSizeEx as *const (),
        "SetFilePointer" => SetFilePointer as *const (),
        "SetFilePointerEx" => SetFilePointerEx as *const (),
        _ => return None,
    };
    Some(p as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translate_path_strips_drive_and_swaps_slashes() {
        assert_eq!(
            translate_path("C:\\Users\\foo\\bar.txt"),
            "/Users/foo/bar.txt"
        );
        assert_eq!(translate_path("data\\file.bin"), "data/file.bin");
        assert_eq!(translate_path("foo"), "foo");
    }
}

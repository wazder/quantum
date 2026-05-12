//! Raw Darwin / Mach FFI declarations. Hand-written so we don't pull in
//! `libc` or `mach2`. Only the symbols we actually use go here.

#![allow(non_camel_case_types, non_snake_case)]

use core::ffi::{c_char, c_int, c_void};

pub type kern_return_t = c_int;
pub type mach_port_t = u32;
pub type vm_prot_t = c_int;
pub type mach_vm_address_t = u64;
pub type mach_vm_size_t = u64;
pub type off_t = i64;
pub type size_t = usize;
pub type ssize_t = isize;
pub type mode_t = u16;

pub const KERN_SUCCESS: kern_return_t = 0;

pub const VM_PROT_NONE: vm_prot_t = 0x00;
pub const VM_PROT_READ: vm_prot_t = 0x01;
pub const VM_PROT_WRITE: vm_prot_t = 0x02;
pub const VM_PROT_EXECUTE: vm_prot_t = 0x04;

pub const VM_FLAGS_FIXED: c_int = 0x0000;
pub const VM_FLAGS_ANYWHERE: c_int = 0x0001;

// mmap flags / prot — Darwin.
pub const PROT_NONE: c_int = 0x0;
pub const PROT_READ: c_int = 0x1;
pub const PROT_WRITE: c_int = 0x2;
pub const PROT_EXEC: c_int = 0x4;

pub const MAP_SHARED: c_int = 0x0001;
pub const MAP_PRIVATE: c_int = 0x0002;
pub const MAP_FIXED: c_int = 0x0010;
pub const MAP_ANON: c_int = 0x1000;
pub const MAP_JIT: c_int = 0x0800;
pub const MAP_FAILED: *mut c_void = !0usize as *mut c_void;

// open flags.
pub const O_RDONLY: c_int = 0x0000;
pub const O_WRONLY: c_int = 0x0001;
pub const O_RDWR: c_int = 0x0002;
pub const O_APPEND: c_int = 0x0008;
pub const O_CREAT: c_int = 0x0200;
pub const O_TRUNC: c_int = 0x0400;
pub const O_EXCL: c_int = 0x0800;

pub const STDIN_FILENO: c_int = 0;
pub const STDOUT_FILENO: c_int = 1;
pub const STDERR_FILENO: c_int = 2;

unsafe extern "C" {
    pub fn mach_task_self() -> mach_port_t;

    pub fn mach_vm_allocate(
        target: mach_port_t,
        address: *mut mach_vm_address_t,
        size: mach_vm_size_t,
        flags: c_int,
    ) -> kern_return_t;

    pub fn mach_vm_deallocate(
        target: mach_port_t,
        address: mach_vm_address_t,
        size: mach_vm_size_t,
    ) -> kern_return_t;

    pub fn mach_vm_protect(
        target: mach_port_t,
        address: mach_vm_address_t,
        size: mach_vm_size_t,
        set_maximum: c_int,
        new_protection: vm_prot_t,
    ) -> kern_return_t;

    pub fn mmap(
        addr: *mut c_void,
        len: size_t,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: off_t,
    ) -> *mut c_void;

    pub fn munmap(addr: *mut c_void, len: size_t) -> c_int;
    pub fn mprotect(addr: *mut c_void, len: size_t, prot: c_int) -> c_int;

    pub fn open(path: *const c_char, oflag: c_int, mode: mode_t) -> c_int;
    pub fn close(fd: c_int) -> c_int;
    pub fn read(fd: c_int, buf: *mut c_void, count: size_t) -> ssize_t;
    pub fn write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t;
    pub fn lseek(fd: c_int, offset: off_t, whence: c_int) -> off_t;

    pub fn pthread_jit_write_protect_np(enabled: c_int);
    pub fn sys_icache_invalidate(start: *mut c_void, len: size_t);

    pub fn __error() -> *mut c_int;
}

#[inline]
pub fn errno() -> i32 {
    unsafe { *__error() }
}

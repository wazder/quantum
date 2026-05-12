//! Shared Win32 / NT ABI types. Layouts must match the Microsoft definitions
//! exactly — these are written to memory the guest will read directly.

#![allow(non_camel_case_types, non_snake_case)]

pub type BOOL = i32;
pub type BYTE = u8;
pub type WORD = u16;
pub type DWORD = u32;
pub type QWORD = u64;
pub type LONG = i32;
pub type ULONG = u32;
pub type ULONGLONG = u64;

pub const FALSE: BOOL = 0;
pub const TRUE: BOOL = 1;

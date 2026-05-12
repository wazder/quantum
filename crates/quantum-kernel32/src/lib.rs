//! Win32 base API surface (kernel32 equivalent). Thin layer on top of
//! `quantum-ntdll`. Concrete API stubs (ExitProcess, WriteFile, …) land in
//! task #5.

#![no_std]

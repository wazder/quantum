//! Portable Executable (PE/COFF) loader.
//!
//! Stage 1 (this file): parse-only. We map raw bytes into typed views of
//! the PE structures without copying or modifying anything. Image mapping,
//! relocation, and import resolution live in sibling modules added later.

#![no_std]

extern crate alloc;

pub mod pe;

pub use pe::{PeFile, PeKind};

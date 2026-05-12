//! Portable Executable (PE/COFF) loader.
//!
//! Modules are added as they land:
//!   - `pe`       : parse-only header views (done)
//!   - `image`    : map a parsed PE into guest memory
//!   - `reloc`    : apply the base relocation table
//!   - `imports`  : walk the import descriptor table
//!   - `delay_imports`, `tls`, `exception`, `load_config`, `exports`,
//!     `debug`, `resources`, `peb` — directory parsers
//!
//! Today everything except `pe` is being written.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod pe;

pub use pe::{PeFile, PeKind};

//! Portable Executable (PE/COFF) loader. End-to-end: parse → map →
//! relocate → import-resolve.
//!
//! Submodules:
//!   * `pe`            : raw header parsers (DOS, COFF, optional, sections, directories)
//!   * `image`         : map a PE into guest memory; protect; index by RVA
//!   * `reloc`         : apply base relocations
//!   * `imports`       : walk the import directory
//!   * `delay_imports` : walk the delay-load directory
//!   * `exports`       : walk the export directory (incl. forwarded exports)
//!   * `tls`           : TLS directory + callback list
//!   * `exception`     : RUNTIME_FUNCTION array
//!   * `load_config`   : load-configuration directory (parse, don't enforce)
//!   * `debug`         : debug directory + CODEVIEW/RSDS PDB info
//!   * `resources`     : resource directory tree
//!   * `peb`           : guest PEB/TEB structures

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod debug;
pub mod delay_imports;
pub mod exception;
pub mod exports;
pub mod image;
pub mod imports;
pub mod load_config;
pub mod pe;
pub mod peb;
pub mod reloc;
pub mod resources;
pub mod tls;

pub use exports::{Export, ExportTable, ExportTarget, NamedExport};
pub use image::{LoadedImage, MappedSection, load};
pub use imports::{DllImports, ImportEntry, ImportTable};
pub use pe::{PeFile, PeKind};
pub use reloc::{RelocStats, apply as apply_relocations};

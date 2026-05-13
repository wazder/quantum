# Quantum Loader

`quantum-loader` is a from-scratch PE/COFF parser + image mapper. No
`goblin`, no `pe-parser`, no third-party crates.

## Crate layout

```
quantum-loader/
  src/pe.rs              DOS, COFF, optional, sections, data directories
  src/image.rs           Map PE into guest VM; per-section protection
  src/reloc.rs           ABSOLUTE/HIGHLOW/DIR64 base relocations
  src/imports.rs         IMPORT_DESCRIPTOR walk + wire_iat
  src/delay_imports.rs   Delay-load directory walk
  src/exports.rs         EXPORT_DIRECTORY incl. forwarded exports
  src/exception.rs       RUNTIME_FUNCTION array (parsed for SEH later)
  src/tls.rs             TLS_DIRECTORY64 + callback list
  src/load_config.rs     LOAD_CONFIG_DIRECTORY64 (parse, don't enforce)
  src/debug.rs           DEBUG_DIRECTORY + CODEVIEW/RSDS PDB info
  src/resources.rs       Type/Name/Lang tree walk
  src/peb.rs             Guest PEB/TEB/LDR_DATA_TABLE_ENTRY layouts
```

## Parsing model

`PeFile::parse(&[u8])` returns a borrowed view over PE/COFF headers.
Failures are explicit `Error::Malformed { what, at }` — no panics on
hostile input.

PE32 (32-bit) and PE32+ (64-bit) optional headers are recognised; the
loader doesn't yet relocate PE32 because Quantum's guest model is
Win64-only.

## Image mapping

`load(&PeFile, &dyn MemoryManager)` returns a `LoadedImage`:

* Allocate `size_of_image` at the PE's preferred base, fall back to
  any free location on conflict.
* Copy headers (first `size_of_headers` bytes).
* Copy each section's raw bytes to its `virtual_address` RVA;
  zero-fill the gap if `virtual_size > size_of_raw_data`.
* Per-section protection (`IMAGE_SCN_MEM_R/W/X`) is applied later by
  `finalize_protections` — after relocations and IAT wiring need
  write access.

The `LoadedImage` exposes `rva_to_slice` / `rva_to_slice_mut` /
`rva_to_ptr` for everyone else to navigate the image without
knowing about VM internals.

## Base relocations

`reloc::apply` walks `.reloc` blocks and applies
`IMAGE_REL_BASED_ABSOLUTE` (no-op padding), `_HIGHLOW` (PE32 32-bit),
and `_DIR64` (PE32+ 64-bit). Unknown types fail loudly.

## Imports

`imports::parse` walks the `IMAGE_IMPORT_DESCRIPTOR` array, follows
the ILT (when present) or the IAT (otherwise), and produces an
`ImportTable` with per-DLL `ImportEntry` records (named or by ordinal).
Each entry records the byte offset of its IAT slot, so the runtime can
stamp the resolved address later.

`imports::wire_iat` takes a closure that maps `(dll, name)` to a host
pointer and writes the pointer to each IAT slot. The default closure
in production is `quantum_kernel32::resolve`.

## What's still pure parsing

`exports`, `delay_imports`, `tls`, `exception`, `load_config`,
`debug`, `resources`: parsed but not interpreted. They're ready when
the runtime needs them.

## What's missing (see `docs/future-work.md`)

* `PEB` / `TEB` / `LDR_DATA_TABLE_ENTRY` construction in guest memory
  (the *types* exist; nothing builds them yet).
* SEH unwind info interpretation.
* Bound imports.
* Resource blob extraction (icons, version info, manifests).
* DLL dependency walking + recursive loading.

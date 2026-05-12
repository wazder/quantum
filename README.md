# quantum

A from-scratch Windows compatibility layer for macOS on Apple Silicon.

Think Proton — but rewritten end-to-end for Darwin / ARM64, with no
upstream Wine, no GPTK, no MoltenVK in the dependency tree.

## Status

Pre-alpha skeleton. Today the workspace compiles and the CLI can dump a PE
file's layout. Nothing executes yet.

## Layout

```
crates/
  quantum-core/       shared types (Error, Handle, NT primitives)
  quantum-loader/     PE/COFF parser + (soon) image mapper
  quantum-jit/        x86_64 -> AArch64 dynamic binary translator
  quantum-ntdll/      NT subsystem (Nt*, Rtl*)
  quantum-kernel32/   Win32 base API surface
  quantum-cli/        `quantum` binary
```

## Roadmap

1. PE parsing + image mapping + relocation
2. x86_64 decoder + AArch64 emitter — translate enough to reach `ExitProcess`
3. Minimal kernel32 (`ExitProcess`, `GetStdHandle`, `WriteFile`) to run a
   "Hello World" Win32 console app
4. user32 / gdi32 + Cocoa-backed window subsystem
5. D3D11 -> Metal translation
6. Audio (CoreAudio), input (IOKit HID), COM, registry, networking

## Build

```
cargo build
cargo test -p quantum-loader
```

## License

Dual-licensed under MIT or Apache-2.0.

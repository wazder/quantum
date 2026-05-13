# quantum

A from-scratch Windows compatibility layer for macOS on Apple Silicon.

Think Proton — but rewritten end-to-end for Darwin / ARM64, with no
upstream Wine, no GPTK, no MoltenVK, and no third-party Rust crates in
the dependency tree.

## What works today

The end-to-end pipeline is alive. `cargo test -p quantum-cli --test
e2e_exit_process` hand-assembles a real Win64 PE — DOS header, COFF,
PE32+ optional header, two sections (`.text`, `.idata`), an
`IMAGE_IMPORT_DESCRIPTOR` table, an Import Lookup Table, a
`hint+name` blob and a DLL name — whose `.text` is exactly:

```
mov ecx, 42                       ; B9 2A 00 00 00
call qword ptr [rip + 0xFF5]      ; FF 15 F5 0F 00 00   ; IAT for KERNEL32!ExitProcess
ud2                               ; 0F 0B
```

and runs it through the entire stack:

| Step | Crate | What happens |
|------|-------|--------------|
| 1 | `quantum-loader::pe` | Parse PE/COFF headers, sections, every data directory |
| 2 | `quantum-loader::image` | `mach_vm_allocate` at the preferred image base; copy sections; per-section protection |
| 3 | `quantum-loader::reloc` | Apply `IMAGE_REL_BASED_DIR64` base relocations |
| 4 | `quantum-loader::imports` | Walk `IMAGE_IMPORT_DESCRIPTOR` → `(DLL, name)` pairs |
| 5 | `quantum-loader::imports::wire_iat` + `quantum-kernel32::resolve` | Stamp the host thunk address into each IAT slot |
| 6 | `quantum-jit::decoder` | Decode x86_64 from the entry RVA |
| 7 | `quantum-jit::lifter` | Lift to AArch64 with direct register pinning |
| 8 | `quantum-jit::emitter` | Emit real AArch64 bytes (golden-tested against `clang -c`) |
| 9 | `quantum-runtime::codecache` | Install into a `MAP_JIT` region; flip W^X; invalidate i-cache |
| 10 | host CPU | Execute the JIT'd code for real |
| 11 | JIT call site | Load IAT slot, marshal Win64 RCX → AAPCS64 X0, `BLR` |
| 12 | `quantum-kernel32::ExitProcess` | Write 42 to `EXIT_CODE`; `longjmp` to the trap |
| 13 | test | Reads `42` |

79 tests passing across the workspace. `cargo clippy -- -D warnings`
clean. No third-party Rust crates in `[dependencies]`.

## Layout

```
crates/
  quantum-core/       shared types (Error, Handle, NT primitives)
  quantum-runtime/    Darwin / Mach FFI, MachVmManager, CodeCache (MAP_JIT)
  quantum-loader/     PE/COFF parser + image mapper + all directory parsers
  quantum-jit/        x86_64 decoder, AArch64 emitter, lifter
  quantum-ntdll/      NT subsystem (scaffolded)
  quantum-kernel32/   Win32 thunks + IAT resolver + ExitProcess trap
  quantum-cli/        `quantum` binary + e2e test
```

## Build

```
cargo build
cargo test --workspace
```

Tests automatically codesign each test binary with the JIT entitlement
via `scripts/test-runner.sh` (configured in `.cargo/config.toml`).
The default identity is `Apple Development: tatarhasan09@gmail.com
(FD43D54MNN)` — override via `QUANTUM_SIGN_IDENTITY` env var. Falls
back to ad-hoc signing if that identity is unavailable.

## Roadmap

What's done is documented in `docs/architecture.md` and `docs/jit.md`.
What's still ahead — Wow64, AVX, DirectX, audio, threading, real PE
import resolution — is documented in `docs/future-work.md`.

## License

Dual-licensed under MIT or Apache-2.0.

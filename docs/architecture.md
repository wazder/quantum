# Quantum Architecture

The project's high-level shape, focused on the parts that exist today
and the boundaries we expect future code to respect.

## Big picture

A guest Win64 process is a `LoadedImage` (mapped via `mach_vm_allocate`
into the host address space at the PE's preferred base where possible)
plus a `CodeCache` (a `MAP_JIT` region the translator fills with
AArch64 code as it lifts guest basic blocks).

Three independent layers, each with a sharp interface:

```
+-----------------------------+      +-----------------------------+
|   quantum-loader            |      |   quantum-jit               |
|   PE bytes -> LoadedImage   |      |   x86_64 -> AArch64         |
+--------------+--------------+      +---------+---------+---------+
               |                               |
               |              +----------------+         |
               v              v                          v
        +------------------------+         +-----------------------+
        |   quantum-runtime      |         |   quantum-kernel32    |
        |   mach_vm + MAP_JIT    |<------->|   thunks + IAT        |
        +------------------------+ resolve +-----------------------+
```

`quantum-loader` is pure parsing + layout; it borrows the bytes you
give it. It never JITs, never calls Mach. It produces `LoadedImage`
and the various directory views (`ImportTable`, `ExportTable`,
`TlsInfo`, …).

`quantum-runtime` owns host VM and the host FFI. Every Mach syscall
goes through `sys.rs`; no other crate calls `mmap`/`mach_vm_*`
directly. `CodeCache` is the only thing that toggles W^X via
`pthread_jit_write_protect_np`.

`quantum-jit` is a self-contained translator. It depends only on
`quantum-core` for shared types. Decoder → IR (`iform::Inst`) →
Lifter → Emitter → bytes. Each stage is independently testable.

`quantum-kernel32` exposes the guest-visible Win32 surface. Every
function is `extern "C"` (or `extern "C-unwind"` where unwinding is
allowed) so the JIT can call into it via plain `BLR`. The resolver
turns `(dll, name)` into a host function pointer; the loader's IAT
wirer stamps those pointers into guest memory.

## Memory model

* Each guest process has one `MachVmManager` (`mach_task_self()`).
* `LoadedImage::region` is a `Region` allocated at the PE's image
  base when available, anywhere otherwise. Per-section protection
  (`R`, `RW`, `RX`, `RWX`) is applied after relocations and IAT
  wiring finish.
* The JIT code cache is a separate `MAP_JIT` region. On Apple
  Silicon the per-thread W^X bit (`pthread_jit_write_protect_np`)
  toggles the same pages between writable and executable; the cache
  flips it around each `install`.

## Calling convention bridge

Pinning (current):

| guest reg | host reg | notes |
|-----------|----------|-------|
| RAX..R15  | X0..X15  | direct |
| RSP       | X19      | callee-saved on host; keeps guest stack separate |
| RBP       | X5       | not aliased to host frame pointer (X29) |
| RIP       | implicit | the dispatcher (planned) holds the next-block address |
| FLAGS     | NZCV     | partial: PF/AF are deferred |

Calls into kernel32 thunks marshal Win64 RCX → AAPCS64 X0 inline at the
call site and save the host frame across the call with `stp x29, x30,
[sp, #-16]!` / `ldp x29, x30, [sp], #16`. Multi-argument thunks need a
richer trampoline; see `docs/future-work.md`.

## ExitProcess escape

The JIT'd frame between the guest CALL and `ExitProcess` has no DWARF
unwind metadata, so Rust panic can't escape through it (libunwind
returns `_URC_END_OF_STACK` and the panic runtime aborts). We bypass
unwinding entirely: `ExitProcess` writes its argument to a global and
`longjmp`s back to the trap that `run_with_exit_trap` armed before
calling into JIT'd code. `setjmp`/`longjmp` are declared as raw FFI in
`quantum-kernel32::process` — no `libc` crate dependency.

## Codesigning

`MAP_JIT` plus `pthread_jit_write_protect_np` on Apple Silicon
requires `com.apple.security.cs.allow-jit`. Tests get it through:

* `build/jit.entitlements` (committed; the entitlement plist itself)
* `scripts/test-runner.sh` (re-signs every test binary on the fly)
* `.cargo/config.toml` (registers the runner for
  `aarch64-apple-darwin`)

Default identity is `Apple Development: tatarhasan09@gmail.com
(FD43D54MNN)`. Override via `QUANTUM_SIGN_IDENTITY`. Falls back to
ad-hoc when that identity isn't in the keychain.

## What's not in scope tonight

`docs/future-work.md`. Everything from real dispatcher/code-chaining
through Wow64, AVX, DirectX → Metal, audio, threading, COM, and SEH
unwinding lives there.

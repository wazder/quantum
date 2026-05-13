# Quantum — Full Roadmap to Better-Than-Windows Gaming

## Scope locked 2026-05-13

The project's ambition, decided with the user:

- **Multiple Windows games run on macOS** (target list TBD)
- **Anti-cheat compatible** (EAC, BattlEye, etc.)
- **Outperform Windows native** where possible (Apple Silicon
  advantages: cheaper W^X, unified memory, lower-overhead Metal)
- **Strictly from-scratch** — no Wine, no GPTK, no MoltenVK, no DXVK,
  no VKD3D-Proton, no third-party Rust runtime crates

## Realistic timeline (consistent overnight + occasional interactive sessions)

| Phase | What | Months |
|-------|------|--------|
| 1 | JIT/runtime foundation + first real CLI .exe | 1-3 |
| 2 | kernel32 + ntdll surface + threading + heap | 2-3 |
| 3 | user32 + gdi32 + Cocoa/Metal window bridge | 3-6 |
| 4 | DirectX 11 → Metal (the big one) | 6-12 |
| 5 | DirectX 12, XAudio2, XInput, Winsock | 4-8 |
| 6 | Anti-cheat compatibility | 3-6 |
| **Total** | | **18-30** |

Phases overlap where possible (audio/input can land while D3D bring-up
is ongoing, etc.).

---

## Phase 1 — JIT/runtime foundation (1-3 months)

Goal: real mingw-compiled `hello.exe` runs from a real file on disk.

### Deliverables

- **Dispatcher** — single function that owns the main translation
  loop. On block exit, the lifted code writes the guest target RIP to
  a known register and returns to the dispatcher. The dispatcher
  looks up the target in a `BlockMap` (guest RIP → host code
  pointer); if cached, jumps in; if not, translates and chains.
- **Block chaining** — direct branches between cached blocks patched
  in place (replaces the dispatcher return with a `B` to the next
  block once both are cached).
- **Win64 ABI bridge — full rewrite of register pinning.** Move guest
  callee-saved registers (RBX, RBP, RDI, RSI, R12-R15) to AArch64
  callee-saved registers (X19-X28) so they survive thunk calls
  without manual save/restore. Update lifter pinning. Update tests.
- **Shadow space + 16B alignment** before every guest CALL.
- **Real guest stack management**: PUSH/POP set RSP correctly,
  enter/leave/calls respect alignment.
- **PEB / TEB / LDR list** constructed in guest memory at startup.
  Guest code that reads `gs:[0x60]` finds a real PEB.
- **Real DLL loading** — but the "DLL" is an in-process module
  whose exports are quantum-kernel32 thunks. When the guest's PE
  references KERNEL32.DLL, we synthesize a `LDR_DATA_TABLE_ENTRY`
  for it with the in-process export table.
- **Heap** — `HeapCreate`, `HeapAlloc`, `HeapFree`. Backed by a
  per-heap arena from `MachVmManager`.
- **Threading** — `CreateThread`, `WaitForSingleObject`,
  `CreateMutex`, `ReleaseMutex`. Backed by pthreads. TLS callbacks
  invoked on thread start.
- **Lifter coverage** — every common opcode pattern. Target: enough
  to translate every basic block in a mingw `hello.exe` without
  `Unsupported`. SSE2 scalar moves (movsd/movss) included.
- **Real PE input** — load mingw's actual `hello.exe` binary, not a
  hand-assembled one. Resolve real `printf`/`malloc`/`puts` against
  our msvcrt stub.

### Acceptance test

```sh
quantum hello.exe
# stdout: "Hello, World!"
# exit code: 0
```

---

## Phase 2 — kernel32 + ntdll surface buildout (2-3 months)

Goal: a non-trivial CLI tool (e.g. 7-zip CLI) runs.

### Major surface

Roughly 150-300 functions across:

- **Process**: `GetCurrentProcess`, `OpenProcess`, `TerminateProcess`,
  `GetCommandLineW`, `GetEnvironmentVariableW`, `SetEnvironmentVariableW`,
  `GetModuleFileNameW`, `GetSystemTimeAsFileTime`,
  `QueryPerformanceCounter`, ...
- **Heap / VM**: `VirtualAlloc`, `VirtualFree`, `VirtualProtect`,
  `GetProcessHeap`, `HeapReAlloc`, `LocalAlloc/Free`, ...
- **File I/O**: `CreateFileW`, `ReadFile`, `WriteFile`, `CloseHandle`,
  `GetFileSize`, `SetFilePointerEx`, `FindFirstFileW`,
  `FindNextFileW`, `GetFileAttributesW`, `MoveFileW`, `DeleteFileW`,
  `CreateDirectoryW`, ...
- **Sync**: `CreateMutexW`, `CreateEventW`, `CreateSemaphoreW`,
  `WaitForSingleObject`, `WaitForMultipleObjects`,
  `EnterCriticalSection`, `LeaveCriticalSection`, ...
- **Path / String**: `GetCurrentDirectoryW`, `GetTempPathW`,
  `MultiByteToWideChar`, `WideCharToMultiByte`, ...
- **Console**: `GetStdHandle`, `WriteConsoleW`, `ReadConsoleW`,
  `SetConsoleMode`, `GetConsoleScreenBufferInfo`, ...

### msvcrt / vcruntime / ucrtbase

Roughly: `printf`, `scanf`, `malloc`, `free`, `memcpy`, `memset`,
`strlen`, `strcpy`, `strcmp`, `fopen`, `fread`, `fwrite`, `fclose`,
`_setargv`, `__getmainargs`, `exit`, `atexit`, `_dllonexit`,
`_amsg_exit`, ...

Hundreds of CRT functions. Most are thin POSIX wrappers.

### Filesystem semantics shim

- Case-insensitive path matching on case-sensitive APFS volumes
- Drive letter to mount point mapping (`C:\` → some configurable
  prefix in the user's home dir, e.g. `~/Library/Application
  Support/Quantum/c_drive/`)
- Backslash → forward slash translation
- Reserved name handling (CON, PRN, AUX, NUL, ...)

---

## Phase 3 — GUI subsystem (3-6 months)

Goal: a basic Win32 GUI app (notepad-class) runs and renders.

### user32

- `RegisterClassExW`, `CreateWindowExW`, `DefWindowProcW`
- Message pump: `GetMessageW`, `TranslateMessage`, `DispatchMessageW`,
  `PostMessageW`, `SendMessageW`
- Input: WM_KEYDOWN/UP, WM_MOUSEMOVE, WM_LBUTTONDOWN/UP, ...
- Painting: WM_PAINT, BeginPaint/EndPaint
- Windowing: ShowWindow, UpdateWindow, MoveWindow, SetWindowTextW

Backed by NSWindow + a Quartz/Metal-backed view that translates the
guest's painting into a `CGContext` or Metal command buffer.

### gdi32

- DCs (device contexts)
- Pen/Brush/Font selection
- Drawing primitives: `LineTo`, `Rectangle`, `Ellipse`, `Polygon`,
  `BitBlt`, `StretchBlt`
- Text: `TextOutW`, `DrawTextW`
- Fonts: `CreateFontW`, font metrics, `GetGlyphIndicesW`

Backed by `CoreGraphics` (Quartz 2D) or Metal if we want to GPU
all of it.

### comdlg32 / shell32 / comctl32

Pick & open dialogs, common controls (buttons, edit boxes, listviews).
Mostly mapped to AppKit equivalents via a translation layer.

---

## Phase 4 — DirectX 11 → Metal (6-12 months, the heart of the project)

Goal: a real DX11 indie game (suggest: *Hades*, *Hollow Knight*,
*Stardew Valley*) renders correctly.

### Crate structure

```
quantum-d3d/
  src/d3d11/        ID3D11Device, ID3D11DeviceContext, ID3D11Buffer,
                    ID3D11Texture2D, ID3D11ShaderResourceView, ...
  src/dxgi/         IDXGISwapChain, IDXGIFactory, IDXGIAdapter
  src/d3dcompiler/  D3DCompile (HLSL -> DXBC) — for runtime shader
                    compilation
  src/dxbc/         DXBC bytecode parser
  src/metal/        Metal binding (CAMetalLayer, MTLDevice,
                    MTLCommandQueue, MTLRenderPipelineState, ...)
  src/translate/    DXBC -> MSL shader transpilation; resource
                    binding model translation
```

### Major subsystems

- **DXGI swap chain → CAMetalLayer**. Window backing layer, present.
- **Resource model**: D3D11 buffers/textures → Metal buffers/textures.
  D3D11 resource binding (`PSSetShaderResources`, `OMSetRenderTargets`)
  → Metal argument buffers.
- **Pipeline state**: D3D11 input layout + shaders + render state
  bundle → MTLRenderPipelineState. Cached by hash.
- **Shader transpilation**: DXBC → MSL. The hardest piece. Need a
  DXBC disassembler + a code generator that emits MSL. Existing
  open-source projects (SPIRV-Cross, DXIL-to-MSL) are off-limits per
  from-scratch rule; we write our own DXBC parser and MSL emitter.
- **Constant buffers**: D3D11 binding semantics → MSL `[[buffer(n)]]`.
- **Texture filtering / sampling**: D3D11 sampler state → MTLSamplerDescriptor.
- **Pipeline state caching**: hot games rebind pipelines per draw;
  must hash and cache.

### Performance expectations

D3DMetal (Apple's official translator) reportedly hits 60-80% of
Windows native on Apple Silicon for typical games. With our
co-designed JIT + Metal bridge, we aim for parity or better on the
games we target.

---

## Phase 5 — DirectX 12, Audio, Input, Networking (4-8 months, partly parallel)

### DirectX 12

Resource binding via descriptor heaps, explicit command lists,
explicit synchronization. Maps to Metal's argument buffers and
explicit command encoders well, but the API surface is much larger
than D3D11.

### XAudio2 → CoreAudio

`IXAudio2`, `IXAudio2MasteringVoice`, `IXAudio2SourceVoice`. Stream
samples to AudioUnit / AVAudioEngine.

### XInput / DirectInput → IOKit HID

Gamepad polling. Translate XInput button/axis enums to HID gamepad
elements.

### Winsock → BSD sockets

`socket`, `connect`, `send`, `recv`, `WSAAsyncSelect`. Most direct
mapping in the project — Winsock was built on BSD sockets to begin
with.

---

## Phase 6 — Anti-cheat compatibility (3-6 months)

Real anti-cheat (EAC, BattlEye, Vanguard, Hyperion) runs a kernel
driver on Windows that:

- Reads kernel structures (EPROCESS, KTHREAD) for "is this debugger
  attached?", "are there suspicious modules?"
- Walks the loaded module list
- Hooks system calls
- Checks PE signature integrity
- Talks to a userland agent that talks to a remote anti-cheat server

To run anti-cheat-protected games on quantum, we need to:

- **Emulate the kernel-level structures** the driver reads. EPROCESS,
  KTHREAD, _LDR_DATA_TABLE_ENTRY chain, PsActiveProcessHead, all of
  the well-known structures that anti-cheat walks.
- **Emulate or stub the kernel driver loading**. Anti-cheat installs
  a driver; we synthesize a fake "loaded driver" entry that satisfies
  the userland integrity checks.
- **Emulate the agent IPC**. Anti-cheat userland talks to its kernel
  side via IOCTL / DeviceIoControl; we satisfy those requests with
  plausible kernel-side data.
- **Be faithful enough** that the anti-cheat doesn't flag the system.
  This is genuinely hard — anti-cheat companies actively detect VMs
  and translators.

This phase is the most legally and technically sensitive. The
correct framing: we're building a faithful Windows-environment
emulator that the user runs on their own machine to play games
they own. Not bypassing anti-cheat — running it in a
sufficiently-Windows-like environment that it works as designed.

### Targets

- Probably start with **EasyAntiCheat** (has Linux/Proton support;
  the ecosystem has documented how it works in non-Windows envs)
- Then **BattlEye** (similar)
- **Vanguard / Hyperion** (Valorant, latest CoD) are hardest —
  they're explicitly hostile to non-Windows environments and may
  never be made to run

---

## How we work

- Overnight `/loop` sessions, autonomous. Each session targets one
  concrete sub-deliverable from the current phase.
- Interactive sessions for design decisions, picking targets,
  reviewing direction.
- Every commit gates on `cargo clippy -- -D warnings` clean and all
  tests passing.
- Every milestone has at least one e2e test that proves it.

## What makes "better than Windows" plausible

- macOS skips the Windows legacy bring-up (DOS, 16-bit, 30-year API
  timeline).
- Apple Silicon's per-thread W^X is much cheaper than Windows'
  per-page mprotect for JIT workloads.
- Unified memory on Apple Silicon (CPU/GPU share RAM) skips
  PCIe-resident-memory round-trips that DirectX gaming pays on
  discrete-GPU Windows machines.
- We get to co-design the translator and the ABI bridge; no shim
  in the middle.
- Metal's argument-buffer model is closer to D3D12's descriptor heap
  than DirectX 11's per-stage binding, so our D3D11 → Metal layer can
  amortize bind-state churn that D3D11 incurs natively.

Whether all of this actually wins on real workloads is a benchmark
question we'll answer when the first game launches. We aim for it
explicitly.

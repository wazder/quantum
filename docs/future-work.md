# Future Work

What's tracked but not in tonight's scope. Roughly ordered by how
close each item is to the current pipeline.

## Near term (days)

* **Intra-block control flow** in the JIT: `JMP rel` and `Jcc rel`
  with label fixups within a basic block. `BlockBuilder` that
  allocates one `Label` per guest RIP in the block, binds as we hit
  each instruction, and patches forward branches when bound.

* **Out-of-block dispatcher.** Today `RET` lifts to a host `RET`,
  which only works because the test transmutes the JIT'd code as a
  function. For a real guest with multi-block control flow we need
  a dispatcher: on block exit, write the guest target RIP to a known
  reg, return to the dispatcher, which either runs the next cached
  block or translates a new one.

* **Multi-arg Win64 thunks.** `WriteFile`'s 5 args need RCX/RDX/R8/R9
  → X0/X1/X2/X3 with overlap-correct shuffling and a 5th slot read
  from the guest stack. Write a `marshal_win64_to_aapcs64` helper.

* **Partial-register writes** preserving upper bits (CL ← AL, AX ← imm
  while RAX[63:16] stays put). Needs `BFI`/`BFXIL` in the emitter.

* **PF/AF flag emulation.** Compute lazily into a virtual register
  when consumed. Decoder already emits the consuming Jcc/SETcc; the
  lifter currently returns `None` from `cond_x86_to_a64` for them.

* **PEB / TEB construction.** `quantum-loader::peb` defines the
  types; nobody builds an instance yet. Needed before guest code can
  read `gs:[0x60]`.

* **DLL resolution beyond kernel32.** `resolve()` only knows
  `kernel32.dll`. Stub `user32.dll`, `msvcrt.dll`, `vcruntime140.dll`
  with minimal entries to keep simple guests happy.

## Medium term (weeks)

* **Real basic-block translation pipeline.** Today `lift_all` in the
  test crate is a stand-in for what should be a `Translator` in
  `quantum-runtime` that owns the `CodeCache`, the `block_map`
  (guest RIP → host code pointer), and the dispatcher.

* **Stack model.** Guest RSP is pinned to X19 but we don't actually
  allocate a guest stack region. CALL/RET don't push/pop a guest
  return address; today everything works because we lift only leaf-
  ish patterns. A real guest stack needs `quantum-runtime::guest_stack`
  with mach-allocated VM and proper push/pop semantics in the lifter.

* **Win64 SEH.** `RUNTIME_FUNCTION` is parsed; the unwind interpreter
  is not. Required for any guest using `__try`/`__except` or C++
  exceptions.

* **TLS callback invocation.** TLS directory and callback array are
  parsed; the runtime needs to call them after image map and before
  entry.

* **`Heap*` family.** `RtlAllocateHeap` / `HeapAlloc` backed by a
  simple bump-arena out of an `mach_vm_allocate` region.

## Long term (months)

* **Wow64 (32-bit guest).** Decode PE32, lift 32-bit x86. Most
  modern Windows apps are 64-bit; 32-bit is mostly old installers.

* **AVX / AVX2 / AVX-512.** AArch64 SVE is closest but lane counts
  don't match cleanly. SSE2 scalar moves are decoded but not lifted.

* **DirectX → Metal.** A new crate `quantum-d3d` that bridges D3D9/
  10/11/12 to Metal. Equivalent to DXVK+VKD3D-Proton on Linux.
  Independent of everything above except a working JIT.

* **Audio.** XAudio2 / DirectSound → CoreAudio.

* **Input.** XInput / DirectInput → IOKit HID.

* **COM / OLE.** Object dispatch through the registry.

* **Networking.** Winsock → BSD sockets.

* **Anti-cheat compatibility.** EasyAntiCheat, BattlEye etc. via
  kernel-driver emulation. Notoriously hostile; out of scope unless
  the upstream vendor cooperates.

## Why "more optimised than Windows" is plausible

* macOS gets to skip the legacy bring-up Win32 carries: no DOS
  subsystem, no 16-bit code, no half-decade-old API timelines.
* We control the entire dynamic translator and can co-design the
  guest ABI bridges with our host ABI (no shim layer in between).
* Apple Silicon has hardware support for short backward branches
  patched in place (we use this in the emitter already) and per-
  thread W^X (`pthread_jit_write_protect_np`) that's much cheaper
  than `mprotect` round trips.
* The IAT bridge in our model is direct: load → marshal → BLR. No
  trampoline in shared memory, no syscall, no cross-process IPC.

Whether all of that actually wins on real workloads is a benchmark
question; we'll come back to it once a real game launches.

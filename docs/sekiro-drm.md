# Sekiro Steam DRM — Findings

## Status

Sekiro's executable embeds Steam's standard DRM stub at the entry
point. The JIT translates the stub's hundreds of basic blocks
cleanly; the first hard wall is a deliberate anti-debug trap that
expects Steam's runtime exception filter to patch the post-trap state.
Without that filter we crash on a NULL indirect CALL after the trap.

This document records what we've observed so a future session can
pick up from here without re-deriving the analysis.

## The trap pattern

At guest RVA `0x42a1e37` the stub does:

```
cc        int3
eb fd     jmp -3   ; loops back to int3
```

Three bytes total. On real Windows the int3 raises an exception that
Steam's installed unhandled-exception-filter receives. The filter:

1. Decodes the surrounding instructions to identify *which* trap it
   is (Steam DRM has many of these as control-flow checkpoints).
2. Patches a small region of guest memory — at least
   `[rsp+0x640]`, which the post-trap instructions immediately use
   as an indirect CALL target.
3. Bumps `CONTEXT.Rip` past the 3-byte trap pair.
4. Returns `EXCEPTION_CONTINUE_EXECUTION`.

Without the filter, `[rsp+0x640]` is whatever sits there. The
preceding block at `0x42a1e04` is a memset-style zeroing loop that
explicitly clears the surrounding stack region to 0, so the CALL
through `[rsp+0x640]` dispatches to NULL → SIGSEGV.

The crash handler in `quantum-kernel32::process` confirms this with:

```
[trace] FATAL signal 11: fault_addr=0x0, host_pc=0x..., last_guest_rip=0x1442a1e3a
```

`0x1442a1e3a` is exactly `trap_rip + 3` — the first instruction past
the trap — and that block's terminating instruction is
`ff 94 24 40 06 00 00` (call qword ptr [rsp+0x640]).

## Why the int3-skip peephole isn't enough

`quantum-jit::block::detect_drm_int3_trap` replaces the trap pair
with a no-op block that jumps to `int3_rip + 3`. That's mechanically
correct for "skip past the trap" but it does **not** reproduce the
state mutation Steam's filter performs. The trap is structurally a
co-routine yield: control enters Steam's runtime, returns to the
guest with side effects already applied. Skipping just the
instruction pointer leaves those side effects undone.

## Paths forward

1. **Full Windows SEH / SetUnhandledExceptionFilter emulation.**
   The right long-term answer. Requires:
   - Building the TEB.NtTib.ExceptionList chain on guest threads.
   - Honoring `RtlAddVectoredExceptionHandler` /
     `SetUnhandledExceptionFilter` (today's stubs are no-ops).
   - Translating host SIGSEGV/SIGTRAP → guest `EXCEPTION_RECORD` +
     dispatching to whatever filter the guest installed.
   - **Plus** running Steam's filter code through the JIT, which
     requires Steam's filter to be findable (it lives in the same
     `.text` as the stub, somewhere reachable from
     `SetUnhandledExceptionFilter`'s argument).

2. **Steam DRM stub recognition and emulation.** Pattern-match the
   stub's prologue, identify its control-flow checkpoints, and
   replicate the state mutations directly. Less general but
   tractable if the stub format is stable across Steam-wrapped
   titles.

3. **Goldberg / Steamless-style un-wrapping.** A common community
   approach is to strip the Steam stub at load time so the JIT runs
   the original game code directly. That sidesteps DRM emulation
   entirely.

4. **Different test game.** Anything not Steam-wrapped (or
   un-wrapped) lets us validate the rest of the platform without
   blocking on DRM.

## Translation coverage as of this session

Sekiro's DRM stub exercises the following x86_64 ops, all currently
lifted correctly by the JIT:

- MOV in all four operand-shape variants (reg/reg, reg/imm, reg/mem,
  mem/reg, mem/imm).
- CMP in (reg, reg), (reg, imm), (reg, mem), (mem, reg), (mem, imm).
- MOVZX / MOVSX from memory (B1 and B2 source widths).
- Single-operand DIV / IDIV / MUL / IMUL — 64-bit forms (assume
  RDX==0 for DIV/IDIV), 32-bit forms with proper EDX:EAX combine.
- NEG / NOT.
- LEA, ADD, SUB, AND, OR, XOR, TEST, INC, DEC, SHL, SHR, PUSH, POP,
  CALL, RET, JMP, Jcc, CMOVcc, SETcc, NOP, INT3, UD2.

The remaining lifter gaps in the stub bytes we've seen are
zero — every block translated up to the SIGSEGV point.

## Diagnostic helpers shipped this session

- `quantum-jit::block::BlockError::LiftAt` carries the failing
  instruction's RIP + raw bytes so dispatcher traces pinpoint which
  opcode lacks lift coverage (previously they only showed the block
  start).
- `quantum-kernel32::process::install_crash_handler` registers a
  SA_SIGINFO handler for SIGSEGV/SIGBUS/SIGTRAP/SIGILL that longjmps
  back to the exit trap with `CrashInfo { sig, fault_addr, host_pc }`
  captured for the caller to print.
- `quantum-cli::process::LAST_ENTERED_RIP` records each guest RIP
  immediately before dispatcher entry so post-crash trace lines
  include the failing block address.

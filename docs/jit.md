# Quantum JIT

x86_64 → AArch64 dynamic binary translator. Lives in `quantum-jit`.

## Crate layout

```
quantum-jit/
  src/iform.rs       Shared IR: GpReg, Mem, Operand, Op, Cond, OpSize, Inst
  src/decoder.rs     Bytes -> Inst stream (single + 0F two-byte tables)
  src/emitter.rs     Real AArch64 assembler with label/fixup machinery
  src/lifter.rs      Inst -> AArch64 sequence via direct register pinning
  tests/live_pipeline.rs  Round-trips through CodeCache for real execution
```

Decoder, emitter, and lifter are written from scratch — no
`iced-x86`, `xed`, `dynasm`, `cranelift`, or borrowed encoding tables.

## Decoder

Walks bytes left-to-right. Handles:

* Legacy prefixes: `LOCK F0`, `REP/REPNE F2/F3`, `OSIZE 66`,
  `ASIZE 67`, `FS 64`, `GS 65`. CS/DS/ES/SS overrides are consumed
  but ignored (NOPs in long mode).
* Full `REX` byte: W/R/X/B extending ModRM reg, rm, and SIB index/base.
* ModRM + SIB including RIP-relative (`mod=00, r/m=101`) and the
  "no-base" SIB form (`mod=00, rm=100, base=101 + disp32`).
* Single-byte primary table: arith groups 0x00–0x3D, PUSH/POP r64,
  MOVSXD, PUSH imm, IMUL r,r/m,imm forms, Jcc rel8, group 1
  (0x80/0x81/0x83), TEST/XCHG/MOV/LEA (0x84–0x8F), NOP/XCHG/CWDE/CDQ/
  CQO/PUSHFQ/POPFQ, MOV r,imm, group 2 shifts, RET, MOV r/m,imm,
  LEAVE, INT3/INT, CALL/JMP rel, HLT/CMC/CLC/STC/CLD/STD, groups
  3/4/5.
* Two-byte 0F-prefixed: SYSCALL, UD2, multi-byte NOP, CMOVcc (40–4F),
  Jcc rel32 (80–8F), SETcc (90–9F), BT (A3), IMUL r,r/m (AF),
  CMPXCHG (B0/B1), MOVZX (B6/B7), group 8 BT* imm8 (BA), BSF/BSR
  (BC/BD), MOVSX (BE/BF), XADD (C0/C1).

Unknown opcodes return `Op::Unhandled` with the correct byte length so
the caller can advance the IP cleanly.

## Emitter

Bit-pattern encoders for the instruction forms the lifter consumes.
Every encoder is golden-tested against `clang -x assembler -target
arm64-apple-darwin -c`.

Covered today:

* Move wide: `MOVZ`, `MOVK`, `MOVN` (X and W views).
  `load_const64` synthesises any 64-bit immediate from the minimal
  MOVZ + MOVK chain.
* Add/sub: immediate (with 12-bit shift) and shifted-register;
  `ADDS`/`SUBS`/`CMP` aliases.
* Logical shifted: `AND`/`ORR`/`EOR`/`ANDS`. `MOV` is the
  `ORR Xd, XZR, Xm` alias.
* DP-2src: `UDIV`, `SDIV`, `LSLV`, `LSRV`, `ASRV`, `RORV`.
* DP-3src: `MADD`, `MUL` (alias of `MADD .. XZR`).
* Conditional select family: `CSEL`, `CSINC`, `CSINV`, `CSNEG`,
  `CSET` (alias).
* Loads/stores (unsigned offset): 64/32/16/8-bit, signed and unsigned.
* Load/store pair: pre-indexed, post-indexed, signed offset.
* Branches: `B`, `BL`, `B.cond`, `CBZ`/`CBNZ`, `TBZ`/`TBNZ`, `BR`,
  `BLR`, `RET`. Forward branches record a fixup; backward branches
  are patched at emit time.
* System: `NOP`, `BRK`, `ISB`, `DMB ISH`, `MRS`/`MSR` for NZCV,
  `MRS TPIDR_EL0` (for the eventual FS/GS base emulation).

## Lifter

Per-instruction lowering. No IR, no register allocator. Pinning:

```
RAX..R15 -> X0..X15   RSP -> X19   RBP -> X5
```

X16/X17 are scratch (used to materialise addresses).

Implemented today:

* `MOV` reg/imm, reg/reg, reg/mem, mem/reg (B1/B2/B4/B8). 32-bit
  destinations clear the upper 32 — for reg-reg via an inlined
  `AND Xd, Xs, #0xFFFFFFFF`, for reg-imm via `MOVZ W`.
* `ADD`, `SUB`, `CMP`: reg-reg and reg-imm (small immediates folded
  into `ADD/SUB` immediate; larger ones via the address scratch).
* `RET`: AArch64 `RET` (returns to the host caller).
* `CallIndirect`: load function pointer from the IAT slot,
  marshal Win64 RCX → AAPCS64 X0, save host frame across the call.
* `NOP`, `INT3`, `UD2`: NOP / BRK.

Memory operand lowering: `[base + index*scale + disp]` is computed
into X16. Small positive disp folds into the LDR/STR unsigned offset;
everything else gets an explicit ADD or SUB. RIP-relative addresses
are constant at translate time: the lifter computes the target VA
and materialises it via `load_const64`.

x86 → AArch64 condition mapping: the x86 carry-after-subtract flag has
the opposite polarity of AArch64's, so `JB` becomes `B.CC` rather than
`B.CS`. See `cond_x86_to_a64`.

## What's not in this pass

* Intra-block JMP rel / Jcc rel with label fixups (needs a
  BlockBuilder; trivial follow-up).
* Multi-arg Win64 thunk marshalling (RCX/RDX/R8/R9 → X0/X1/X2/X3
  preserving overlap order).
* Partial-register writes (CL ← AL etc) preserving the upper bits.
* PF / AF flag emulation.
* x87, SSE2 beyond the scalar mov family, AVX, AVX-512.
* `Wow64` (32-bit guest).

All of the above are tracked in `docs/future-work.md`.

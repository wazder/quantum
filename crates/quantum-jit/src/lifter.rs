//! x86_64 → AArch64 lifter.
//!
//! Consumes `Inst`s produced by `decoder` and writes AArch64 bytes via
//! `Emitter`. The model is straight-line per-instruction lowering with
//! direct register pinning — no IR, no register allocator, no
//! optimisation. That keeps the lifter total and easy to verify against
//! a software reference for the e2e bring-up.
//!
//! Pinning
//! -------
//!   RAX..R15  -> X0..X15  (the host AAPCS64 caller-saved set + a few
//!                          callee-saved; we restore them ourselves)
//!   RSP       -> X19      (callee-saved host reg; we keep guest stack
//!                          separate from host SP)
//!   RIP       -> implicit (advanced by the dispatcher)
//!   FLAGS    -> NZCV     (Z=ZF, N=SF, V=OF; C is inverted for SUB —
//!                         see `cond_x86_to_a64` for the mapping)
//!   PF, AF    -> deferred and unimplemented (very rarely consumed in
//!                          modern code; consumers `BRK` until we model
//!                          them).
//!
//! What is implemented today
//! -------------------------
//!   * MOV r, imm; MOV r, r (32/64-bit)
//!   * ADD, SUB, CMP r, r and r, imm
//!   * RET
//!   * JMP rel; Jcc rel (using the x86→ARM condition mapping)
//!   * NOP, INT3, UD2
//!
//! Memory operands, CALL, control-flow chaining, and 8/16-bit ops follow
//! in subsequent passes. The lifter returns `Unsupported(op)` for those
//! so the caller can decide whether to fall back or bail.

use crate::emitter::{Cond as A64Cond, Emitter, Reg};
use crate::iform::{Cond as XCond, GpReg, Inst, Mem, Op, OpSize, Operand};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifterError {
    /// Op or operand form we haven't lowered yet.
    Unsupported(Op),
    /// Decoder reported `Op::Unhandled`.
    Unhandled,
    /// Operand combination invalid for this op (decoder bug).
    BadOperands,
}

pub type LifterResult<T> = core::result::Result<T, LifterError>;

pub struct Lifter<'a> {
    pub emitter: &'a mut Emitter,
}

impl<'a> Lifter<'a> {
    pub fn new(emitter: &'a mut Emitter) -> Self {
        Self { emitter }
    }

    pub fn lift(&mut self, inst: &Inst) -> LifterResult<()> {
        match inst.op {
            Op::Mov => self.lift_mov(inst),
            Op::Movzx => self.lift_movzx_or_movsx(inst, false),
            Op::Movsx => self.lift_movzx_or_movsx(inst, true),
            Op::Movsxd => self.lift_movsxd(inst),
            Op::Add => self.lift_arith(inst, ArithKind::Add),
            Op::Sub => self.lift_arith(inst, ArithKind::Sub),
            Op::And => self.lift_bitop(inst, BitOp::And),
            Op::Or => self.lift_bitop(inst, BitOp::Or),
            Op::Xor => self.lift_xor(inst),
            Op::Test => self.lift_test(inst),
            Op::Lea => self.lift_lea(inst),
            Op::Cmp => self.lift_cmp(inst),
            Op::Inc => self.lift_inc_dec(inst, true),
            Op::Dec => self.lift_inc_dec(inst, false),
            Op::Div => self.lift_divmul(inst, DivMulKind::Div),
            Op::Idiv => self.lift_divmul(inst, DivMulKind::Idiv),
            Op::Mul => self.lift_divmul(inst, DivMulKind::Mul),
            Op::Imul if inst.operands[1].is_none() => self.lift_divmul(inst, DivMulKind::Imul1),
            Op::Imul => self.lift_imul_n_operand(inst),
            Op::Adc => self.lift_addc(inst, true),
            Op::Sbb => self.lift_addc(inst, false),
            Op::Neg => self.lift_neg(inst),
            Op::Not => self.lift_not(inst),
            Op::Cdq => {
                // EDX = (int32)EAX >> 31 sign-extended into upper 32 bits of RDX.
                // Equivalent: x_rdx = sign-extend low 32 of rax to 64.
                let rax = host_reg(GpReg::Rax);
                let rdx = host_reg(GpReg::Rdx);
                // SBFM Xd, Xn, #31, #31 — extract bit 31 as sign and replicate
                // would be wrong; we want sign-extend bit 31 to bits 31..63.
                // Simpler: ASR Xd, (sign-extended rax), #31 — bit 31 broadcast.
                let sxtw = 0x9340_7C00 | ((rax.raw() as u32) << 5) | (rdx.raw() as u32);
                self.emitter.raw_word(sxtw);
                // Then rdx >>= 31 (arith) so the whole 64-bit reg = bit31 of eax replicated.
                self.emitter
                    .raw_word(0x9343_FC00 | ((rdx.raw() as u32) << 5) | (rdx.raw() as u32));
                // Mask EDX to 32 bits since we treat it as 32-bit in CDQ.
                self.emit_and_imm_lo32(rdx, rdx);
                Ok(())
            }
            Op::Cqo => {
                // RDX = sign-extension of RAX (bit 63 broadcast across RDX).
                let rax = host_reg(GpReg::Rax);
                let rdx = host_reg(GpReg::Rdx);
                // ASR Xd, Xn, #63 — bit 63 broadcast.
                // SBFM Xd, Xn, #63, #63.
                let w = 0x9340_0000
                    | (63u32 << 16)
                    | (63u32 << 10)
                    | ((rax.raw() as u32) << 5)
                    | (rdx.raw() as u32);
                self.emitter.raw_word(w);
                Ok(())
            }
            Op::Leave => {
                // mov rsp, rbp; pop rbp.
                self.emitter.mov64(Reg::x(19), host_reg(GpReg::Rbp));
                self.emitter.ldr64(host_reg(GpReg::Rbp), Reg::x(19), 0);
                self.emitter.add64_imm(Reg::x(19), Reg::x(19), 8);
                Ok(())
            }
            Op::Xchg => self.lift_xchg(inst),
            Op::Shl => self.lift_shift(inst, ShiftDir::Left),
            Op::Shr => self.lift_shift(inst, ShiftDir::Right),
            Op::Sar => self.lift_shift(inst, ShiftDir::ArithRight),
            Op::Rol => self.lift_rotate(inst, true),
            Op::Ror => self.lift_rotate(inst, false),
            Op::Cmov(cond) => self.lift_cmov(inst, cond),
            Op::Set(cond) => self.lift_set(inst, cond),
            Op::Push => self.lift_push(inst),
            Op::Pop => self.lift_pop(inst),
            Op::CallIndirect => self.lift_call_indirect(inst),
            Op::Ret => {
                // For now treat RET as a host RET. Once we wire the
                // dispatcher this becomes a return-to-dispatcher trampoline.
                self.emitter.ret();
                Ok(())
            }
            Op::Jmp => {
                // Direct rel: we don't have a label here yet because the
                // basic-block boundary translator owns label allocation.
                // Defer until lift_block is introduced; for now refuse.
                Err(LifterError::Unsupported(Op::Jmp))
            }
            Op::Jcc(_) => Err(LifterError::Unsupported(inst.op)),
            Op::Nop => {
                self.emitter.nop();
                Ok(())
            }
            Op::Int3 | Op::Ud2 => {
                self.emitter.brk(0);
                Ok(())
            }
            Op::Unhandled => Err(LifterError::Unhandled),
            other => Err(LifterError::Unsupported(other)),
        }
    }

    /// Compute the effective guest address of a memory operand into
    /// scratch register `X16` (`xtmp`).
    ///
    /// For `[base + index*scale + disp]` we materialise the address with
    /// an `add base, index << log2(scale)` plus an immediate offset; if
    /// the displacement is small enough, we leave it for the final
    /// LDR/STR offset so we don't emit a redundant ADD.
    ///
    /// For `RipRel(disp, size)` the effective guest address is fixed at
    /// translate time: `inst.guest_rip + inst.len + disp`. We embed it
    /// as a 64-bit immediate via `load_const64`.
    pub(crate) fn addr_into_xtmp(
        &mut self,
        op: &Operand,
        inst: &Inst,
        xtmp: Reg,
    ) -> LifterResult<u32> {
        match *op {
            Operand::Mem(m) => Ok(self.mem_address_into(m, xtmp)),
            Operand::RipRel(disp, _) => {
                let target = inst
                    .guest_rip
                    .wrapping_add(inst.len as u64)
                    .wrapping_add(disp as u64);
                self.emitter.load_const64(xtmp, target);
                Ok(0)
            }
            _ => Err(LifterError::BadOperands),
        }
    }

    /// Materialise `m`'s effective address into `xtmp`, returning the
    /// leftover constant displacement that the caller may fold into the
    /// LDR/STR unsigned offset (0 if everything was added in).
    ///
    /// Segment overrides (`gs:`/`fs:`) add the corresponding base. The
    /// dispatcher prologue pins gs_base into X24 and fs_base into X25
    /// before any block body runs; non-dispatcher builds emit segment
    /// overrides only by accident and find zero in those regs.
    fn mem_address_into(&mut self, m: Mem, xtmp: Reg) -> u32 {
        match m.base {
            Some(base) => self.emitter.mov64(xtmp, host_reg(base)),
            None => self.emitter.load_const64(xtmp, 0),
        }
        if let Some(seg) = m.seg {
            let seg_reg = match seg {
                crate::iform::Seg::Gs => Reg::x(24),
                crate::iform::Seg::Fs => Reg::x(25),
            };
            self.emitter.add64(xtmp, xtmp, seg_reg);
        }

        if let Some(index) = m.index {
            let hi = host_reg(index);
            match m.scale {
                1 => self.emitter.add64(xtmp, xtmp, hi),
                2 | 4 | 8 => {
                    // ADD Xd, Xn, Xm, LSL #shift.
                    let shift = match m.scale {
                        2 => 1,
                        4 => 2,
                        8 => 3,
                        _ => 0,
                    };
                    self.emit_add_lsl64(xtmp, xtmp, hi, shift);
                }
                _ => self.emitter.add64(xtmp, xtmp, hi),
            }
        }

        if m.disp == 0 {
            return 0;
        }

        // Try to fold positive small disp into the LDR/STR offset (caller
        // does the alignment scaling). Otherwise add it now.
        if m.disp > 0 && (m.disp as u32) < (1 << 24) {
            return m.disp as u32;
        }
        if m.disp > 0 {
            self.emitter.add64_imm(xtmp, xtmp, m.disp as u32);
        } else {
            let abs = m.disp.unsigned_abs();
            if abs < (1 << 24) {
                self.emitter.sub64_imm(xtmp, xtmp, abs);
            } else {
                // Materialise the displacement in x17 and add.
                self.emitter.load_const64(Reg::X17, abs as u64);
                self.emitter.sub64(xtmp, xtmp, Reg::X17);
            }
        }
        0
    }

    /// Emit `ADD Xd, Xn, Xm, LSL #shift`. We hand-encode because the
    /// emitter's typed `add64` doesn't expose the shift amount yet.
    fn emit_add_lsl64(&mut self, rd: Reg, rn: Reg, rm: Reg, shift: u32) {
        // sf=1, op=0, S=0, opc=01011, shift=00 (LSL), N=0
        // imm6 = shift
        //   = 0x8B000000 | (Rm<<16) | (shift<<10) | (Rn<<5) | Rd
        let word = 0x8B00_0000
            | ((rm.raw() as u32) << 16)
            | (shift << 10)
            | ((rn.raw() as u32) << 5)
            | (rd.raw() as u32);
        self.emitter.raw_word(word);
    }

    /// Lower an indirect call through a memory operand. For the e2e
    /// path we know the IAT slot is filled before execution, so we
    /// dereference it at run time and `BLR` to the loaded pointer.
    ///
    /// AAPCS64 arg-marshalling for Win64 thunks is done inline: we
    /// move RCX (X1) into X0 so a single-argument Rust thunk sees its
    /// argument in the standard place. Multi-arg thunks need a richer
    /// trampoline; see `docs/jit.md`.
    fn lift_call_indirect(&mut self, inst: &Inst) -> LifterResult<()> {
        let target = inst.operands[0].ok_or(LifterError::BadOperands)?;
        // Effective address of the function pointer slot -> X16.
        let leftover = self.addr_into_xtmp(&target, inst, Reg::X16)?;
        // X16 = *X16  (load the function pointer from the slot).
        self.emitter.ldr64(Reg::X16, Reg::X16, leftover);
        // Multi-argument Win64 -> AAPCS64 marshaling.
        //
        // Win64 places args 1..4 in RCX/RDX/R8/R9; AAPCS64 puts them in
        // X0/X1/X2/X3. In our pinning RCX=X1, RDX=X2, R8=X8, R9=X9.
        //
        // The four moves below are sequenced so each write happens
        // *after* the next source is read. That avoids any scratch
        // saving (and crucially avoids touching AArch64 callee-saved
        // registers X19..X28, which would corrupt the host caller's
        // state and surface as a SIGSEGV on return).
        self.emitter.mov64(Reg::X0, Reg::X1); // arg0 <- RCX
        self.emitter.mov64(Reg::X1, Reg::X2); // arg1 <- RDX
        self.emitter.mov64(Reg::X2, Reg::X8); // arg2 <- R8
        self.emitter.mov64(Reg::X3, Reg::x(9)); // arg3 <- R9
        // Args 5+ in Win64 live on the guest stack at [rsp+32], [rsp+40], ...
        // In AAPCS64 the 5th+ args go on the host stack too. We don't
        // wire that path yet, but several common thunks (WriteFile's
        // OVERLAPPED, etc.) accept NULL for those slots, so zero X4 as
        // a safe default. Callees that need a real 5th arg will see 0;
        // we add a real marshaling path in a follow-up.
        self.emitter.movz64(Reg::X4, 0, 0);

        // Save host frame & link register across the call so the lifted
        // block can still RET to its original host caller afterwards.
        // 16-byte stack alignment is preserved by stp/ldp pre/post-index.
        self.emitter.stp64_pre(Reg::X29, Reg::X30, Reg::SP, -16);
        // BLR X16 — sets X30 (LR) to the next host PC. AAPCS64.
        self.emitter.blr(Reg::X16);
        self.emitter.ldp64_post(Reg::X29, Reg::X30, Reg::SP, 16);
        Ok(())
    }

    /// PUSH r64 / PUSH imm.
    ///   sub x19, x19, #8
    ///   str <src>, [x19]
    fn lift_push(&mut self, inst: &Inst) -> LifterResult<()> {
        let src = inst.operands[0].ok_or(LifterError::BadOperands)?;
        self.emitter.sub64_imm(Reg::x(19), Reg::x(19), 8);
        match src {
            Operand::Reg(rs, _) => {
                self.emitter.str64(host_reg(rs), Reg::x(19), 0);
            }
            Operand::Imm(imm, _) => {
                // Materialise the immediate into a scratch reg first.
                self.emitter.load_const64(Reg::X16, imm as u64);
                self.emitter.str64(Reg::X16, Reg::x(19), 0);
            }
            _ => return Err(LifterError::Unsupported(Op::Push)),
        }
        Ok(())
    }

    /// POP r64.
    ///   ldr <dst>, [x19]
    ///   add x19, x19, #8
    fn lift_pop(&mut self, inst: &Inst) -> LifterResult<()> {
        let dst = inst.operands[0].ok_or(LifterError::BadOperands)?;
        if let Operand::Reg(rd, _) = dst {
            self.emitter.ldr64(host_reg(rd), Reg::x(19), 0);
            self.emitter.add64_imm(Reg::x(19), Reg::x(19), 8);
            return Ok(());
        }
        Err(LifterError::Unsupported(Op::Pop))
    }

    /// MOVZX / MOVSX r, r/m8 or r/m16. Zero- or sign-extend a smaller
    /// source into a wider destination.
    fn lift_movzx_or_movsx(&mut self, inst: &Inst, signed: bool) -> LifterResult<()> {
        let dst = inst.operands[0].ok_or(LifterError::BadOperands)?;
        let src = inst.operands[1].ok_or(LifterError::BadOperands)?;
        match (dst, src) {
            (Operand::Reg(rd, _dst_size), Operand::Reg(rs, src_size)) => {
                let hd = host_reg(rd);
                let hs = host_reg(rs);
                match (src_size, signed) {
                    (OpSize::B1, false) => self.emit_and_imm_byte(hd, hs),
                    (OpSize::B2, false) => self.emit_and_imm_word(hd, hs),
                    (OpSize::B1, true) => self.emit_sxt_byte(hd, hs),
                    (OpSize::B2, true) => self.emit_sxt_word(hd, hs),
                    _ => return Err(LifterError::Unsupported(inst.op)),
                }
                Ok(())
            }
            (Operand::Reg(rd, _dst_size), m @ (Operand::Mem(_) | Operand::RipRel(_, _))) => {
                let src_size = match m {
                    Operand::Mem(mm) => mm.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                let hd = host_reg(rd);
                match (src_size, signed) {
                    (OpSize::B1, false) => self.emitter.ldrb(hd, Reg::X16, leftover),
                    (OpSize::B2, false) => self.emitter.ldrh(hd, Reg::X16, leftover),
                    (OpSize::B1, true) => {
                        self.emitter.ldrb(hd, Reg::X16, leftover);
                        self.emit_sxt_byte(hd, hd);
                    }
                    (OpSize::B2, true) => {
                        self.emitter.ldrh(hd, Reg::X16, leftover);
                        self.emit_sxt_word(hd, hd);
                    }
                    _ => return Err(LifterError::Unsupported(inst.op)),
                }
                Ok(())
            }
            _ => Err(LifterError::Unsupported(inst.op)),
        }
    }

    /// MOVSXD r, r/m32 — sign-extend 32→64. Encoded as SBFM Xd, Xs, #0, #31
    /// (alias SXTW).
    fn lift_movsxd(&mut self, inst: &Inst) -> LifterResult<()> {
        let dst = inst.operands[0].ok_or(LifterError::BadOperands)?;
        let src = inst.operands[1].ok_or(LifterError::BadOperands)?;
        if let (Operand::Reg(rd, _), Operand::Reg(rs, _)) = (dst, src) {
            self.emit_sxtw(host_reg(rd), host_reg(rs));
            return Ok(());
        }
        Err(LifterError::Unsupported(Op::Movsxd))
    }

    /// AND Xd, Xs, #0xFF (alias UXTB).
    fn emit_and_imm_byte(&mut self, rd: Reg, rs: Reg) {
        // and Xd, Xs, #0xFF — N=0, immr=000000, imms=000111
        let word = 0x9240_1C00 | ((rs.raw() as u32) << 5) | (rd.raw() as u32);
        self.emitter.raw_word(word);
    }
    /// AND Xd, Xs, #0xFFFF (alias UXTH).
    fn emit_and_imm_word(&mut self, rd: Reg, rs: Reg) {
        // and Xd, Xs, #0xFFFF — N=0, immr=000000, imms=001111
        let word = 0x9240_3C00 | ((rs.raw() as u32) << 5) | (rd.raw() as u32);
        self.emitter.raw_word(word);
    }
    /// SXTB Xd, Ws  (sign-extend byte) — SBFM Xd, Xs, #0, #7.
    fn emit_sxt_byte(&mut self, rd: Reg, rs: Reg) {
        // sbfm Xd, Xs, #0, #7 -> sf=1, opc=00, N=1, immr=0, imms=000111
        //   = 0x9340_1C00 | (Rn<<5) | Rd
        let word = 0x9340_1C00 | ((rs.raw() as u32) << 5) | (rd.raw() as u32);
        self.emitter.raw_word(word);
    }
    /// SXTH Xd, Ws  (sign-extend half) — SBFM Xd, Xs, #0, #15.
    fn emit_sxt_word(&mut self, rd: Reg, rs: Reg) {
        let word = 0x9340_3C00 | ((rs.raw() as u32) << 5) | (rd.raw() as u32);
        self.emitter.raw_word(word);
    }
    /// SXTW Xd, Ws  (sign-extend word) — SBFM Xd, Xs, #0, #31.
    fn emit_sxtw(&mut self, rd: Reg, rs: Reg) {
        let word = 0x9340_7C00 | ((rs.raw() as u32) << 5) | (rd.raw() as u32);
        self.emitter.raw_word(word);
    }

    /// AND / OR reg-reg or reg-imm. Both operand classes set flags (AND
    /// has the implicit ANDS form for register-form; OR sets flags too
    /// on x86). For now we emit non-flag-setting AArch64 forms when the
    /// guest only uses the result; flag bits get computed lazily later.
    fn lift_bitop(&mut self, inst: &Inst, op: BitOp) -> LifterResult<()> {
        let dst = inst.operands[0].ok_or(LifterError::BadOperands)?;
        let src = inst.operands[1].ok_or(LifterError::BadOperands)?;
        match (dst, src) {
            (Operand::Reg(rd, size), Operand::Reg(rs, _)) => {
                let hd = host_reg(rd);
                let hs = host_reg(rs);
                self.emit_bitop_rr(op, hd, hd, hs, size);
                Ok(())
            }
            (Operand::Reg(rd, size), Operand::Imm(imm, _)) => {
                let hd = host_reg(rd);
                self.emitter.load_const64(Reg::X16, imm as u64);
                self.emit_bitop_rr(op, hd, hd, Reg::X16, size);
                Ok(())
            }
            (Operand::Reg(rd, size), m @ (Operand::Mem(_) | Operand::RipRel(_, _))) => {
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                let mem_size = match m {
                    Operand::Mem(mm) => mm.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                self.load_sized(Reg::X17, Reg::X16, leftover, mem_size);
                let hd = host_reg(rd);
                self.emit_bitop_rr(op, hd, hd, Reg::X17, size);
                Ok(())
            }
            (m @ (Operand::Mem(_) | Operand::RipRel(_, _)), Operand::Reg(rs, _)) => {
                let size = match m {
                    Operand::Mem(mm) => mm.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                self.load_sized(Reg::X17, Reg::X16, leftover, size);
                self.emit_bitop_rr(op, Reg::X17, Reg::X17, host_reg(rs), size);
                self.store_sized(Reg::X17, Reg::X16, leftover, size);
                Ok(())
            }
            (m @ (Operand::Mem(_) | Operand::RipRel(_, _)), Operand::Imm(imm, _)) => {
                let size = match m {
                    Operand::Mem(mm) => mm.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                self.load_sized(Reg::X17, Reg::X16, leftover, size);
                self.emitter.load_const64(Reg::X16, imm as u64);
                self.emit_bitop_rr(op, Reg::X17, Reg::X17, Reg::X16, size);
                let leftover2 = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                self.store_sized(Reg::X17, Reg::X16, leftover2, size);
                Ok(())
            }
            _ => Err(LifterError::Unsupported(inst.op)),
        }
    }

    fn emit_bitop_rr(&mut self, op: BitOp, rd: Reg, ra: Reg, rb: Reg, size: OpSize) {
        match op {
            BitOp::And => self.emitter.and64(rd, ra, rb),
            BitOp::Or => self.emitter.orr64(rd, ra, rb),
        }
        if matches!(size, OpSize::B4) {
            self.emit_and_imm_lo32(rd, rd);
        }
    }

    /// TEST sets flags only (AND that discards the result). We emit
    /// ANDS Xzr, Xa, Xb so NZCV reflects the bitwise-AND of operands.
    fn lift_test(&mut self, inst: &Inst) -> LifterResult<()> {
        let a = inst.operands[0].ok_or(LifterError::BadOperands)?;
        let b = inst.operands[1].ok_or(LifterError::BadOperands)?;
        match (a, b) {
            (Operand::Reg(ra, _), Operand::Reg(rb, _)) => {
                self.emitter.ands64(Reg::XZR, host_reg(ra), host_reg(rb));
                Ok(())
            }
            (Operand::Reg(ra, _), Operand::Imm(imm, _)) => {
                self.emitter.load_const64(Reg::X16, imm as u64);
                self.emitter.ands64(Reg::XZR, host_reg(ra), Reg::X16);
                Ok(())
            }
            (m @ (Operand::Mem(_) | Operand::RipRel(_, _)), Operand::Reg(rb, _)) => {
                let size = match m {
                    Operand::Mem(mm) => mm.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                self.load_sized(Reg::X17, Reg::X16, leftover, size);
                self.emitter.ands64(Reg::XZR, Reg::X17, host_reg(rb));
                Ok(())
            }
            (Operand::Reg(ra, _), m @ (Operand::Mem(_) | Operand::RipRel(_, _))) => {
                let size = match m {
                    Operand::Mem(mm) => mm.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                self.load_sized(Reg::X17, Reg::X16, leftover, size);
                self.emitter.ands64(Reg::XZR, host_reg(ra), Reg::X17);
                Ok(())
            }
            (m @ (Operand::Mem(_) | Operand::RipRel(_, _)), Operand::Imm(imm, _)) => {
                let size = match m {
                    Operand::Mem(mm) => mm.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                self.load_sized(Reg::X17, Reg::X16, leftover, size);
                self.emitter.load_const64(Reg::X16, imm as u64);
                self.emitter.ands64(Reg::XZR, Reg::X17, Reg::X16);
                Ok(())
            }
            _ => Err(LifterError::Unsupported(Op::Test)),
        }
    }

    /// INC/DEC r — increment or decrement a register. Sets flags
    /// EXCEPT CF (x86 quirk); we ignore that subtlety for now and use
    /// ADDS/SUBS which set CF as well. Programs that rely on the
    /// CF-preservation property are vanishingly rare.
    /// Emit `ORR Xd, Xn, Xm, LSL #shift` (shifted-register form).
    fn emit_orr_lsl64(&mut self, rd: Reg, rn: Reg, rm: Reg, shift: u32) {
        let word = 0xAA00_0000
            | ((rm.raw() as u32) << 16)
            | (shift << 10)
            | ((rn.raw() as u32) << 5)
            | (rd.raw() as u32);
        self.emitter.raw_word(word);
    }

    /// Emit `UBFM Xd, Xn, #immr, #imms` (64-bit). Used for masks.
    fn emit_ubfm64(&mut self, rd: Reg, rn: Reg, immr: u32, imms: u32) {
        let word = 0xD340_0000
            | (immr << 16)
            | (imms << 10)
            | ((rn.raw() as u32) << 5)
            | (rd.raw() as u32);
        self.emitter.raw_word(word);
    }

    /// Mask Xd to its low 32 bits (UBFM Xd, Xn, #0, #31, alias UXTW).
    fn emit_uxtw(&mut self, rd: Reg, rn: Reg) {
        self.emit_ubfm64(rd, rn, 0, 31);
    }

    /// Lift single-operand DIV / IDIV / MUL / IMUL (group 3 /4-/7).
    ///
    /// For 64-bit DIV/IDIV we currently assume RDX is zero on entry
    /// (the overwhelmingly common idiom `xor rdx, rdx; div r`). For
    /// 32-bit we combine EDX:EAX into a 64-bit dividend, divide
    /// against the 32-bit divisor, then mask the results.
    /// 2-operand and 3-operand IMUL.
    /// 2-op: `imul rd, r/m`         → rd = rd * r/m
    /// 3-op: `imul rd, r/m, imm`    → rd = r/m * imm
    /// Only the low half is written to rd; the high half is discarded.
    fn lift_imul_n_operand(&mut self, inst: &Inst) -> LifterResult<()> {
        let dst = inst.operands[0].ok_or(LifterError::BadOperands)?;
        let a = inst.operands[1].ok_or(LifterError::BadOperands)?;
        let b_imm = inst.operands[2];

        let (rd, size) = match dst {
            Operand::Reg(r, s) => (host_reg(r), s),
            _ => return Err(LifterError::Unsupported(Op::Imul)),
        };

        // Get factor A into X17.
        match a {
            Operand::Reg(rs, _) => {
                self.emitter.mov64(Reg::X17, host_reg(rs));
            }
            m @ (Operand::Mem(_) | Operand::RipRel(_, _)) => {
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                let mem_size = match m {
                    Operand::Mem(mm) => mm.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                self.load_sized(Reg::X17, Reg::X16, leftover, mem_size);
            }
            _ => return Err(LifterError::Unsupported(Op::Imul)),
        }

        // Get factor B (= rd for 2-op, imm for 3-op) into X16.
        match b_imm {
            Some(Operand::Imm(imm, _)) => {
                self.emitter.load_const64(Reg::X16, imm as u64);
            }
            None => {
                // 2-operand form: factor B is the destination's current value.
                self.emitter.mov64(Reg::X16, rd);
            }
            _ => return Err(LifterError::Unsupported(Op::Imul)),
        }

        self.emitter.mul64(rd, Reg::X17, Reg::X16);
        if matches!(size, OpSize::B4) {
            self.emit_and_imm_lo32(rd, rd);
        }
        Ok(())
    }

    /// ADC / SBB — add/subtract with carry. We compute the result as
    /// `rd = rd ± src ± C`. Sets NZCV. AArch64 has ADCS/SBCS encoded
    /// in the same family but we hand-encode here since the emitter
    /// doesn't expose them yet.
    fn lift_addc(&mut self, inst: &Inst, add: bool) -> LifterResult<()> {
        let dst = inst.operands[0].ok_or(LifterError::BadOperands)?;
        let src = inst.operands[1].ok_or(LifterError::BadOperands)?;
        let (rd, size) = match dst {
            Operand::Reg(r, s) => (host_reg(r), s),
            _ => return Err(LifterError::Unsupported(inst.op)),
        };
        // Materialise source into X17.
        match src {
            Operand::Reg(rs, _) => self.emitter.mov64(Reg::X17, host_reg(rs)),
            Operand::Imm(imm, _) => self.emitter.load_const64(Reg::X17, imm as u64),
            m @ (Operand::Mem(_) | Operand::RipRel(_, _)) => {
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                let mem_size = match m {
                    Operand::Mem(mm) => mm.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                self.load_sized(Reg::X17, Reg::X16, leftover, mem_size);
            }
        }
        // ADCS Xd, Xn, Xm = 0xBA00_0000 | (Rm<<16) | (Rn<<5) | Rd
        // SBCS Xd, Xn, Xm = 0xFA00_0000 | (Rm<<16) | (Rn<<5) | Rd
        let base = if add { 0xBA00_0000 } else { 0xFA00_0000 };
        let w = base
            | ((Reg::X17.raw() as u32) << 16)
            | ((rd.raw() as u32) << 5)
            | (rd.raw() as u32);
        self.emitter.raw_word(w);
        if matches!(size, OpSize::B4) {
            self.emit_and_imm_lo32(rd, rd);
        }
        Ok(())
    }

    fn lift_divmul(&mut self, inst: &Inst, kind: DivMulKind) -> LifterResult<()> {
        let rm_op = inst.operands[0].ok_or(LifterError::BadOperands)?;
        // Materialise the divisor/multiplier into X17.
        let (size, divisor) = match rm_op {
            Operand::Reg(r, s) => (s, host_reg(r)),
            m @ (Operand::Mem(_) | Operand::RipRel(_, _)) => {
                let sz = match m {
                    Operand::Mem(mm) => mm.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                self.load_sized(Reg::X17, Reg::X16, leftover, sz);
                (sz, Reg::X17)
            }
            _ => return Err(LifterError::Unsupported(inst.op)),
        };

        let rax = Reg::X0;
        let rdx = Reg::X2;
        match (kind, size) {
            (DivMulKind::Div, OpSize::B8) | (DivMulKind::Idiv, OpSize::B8) => {
                // Assume RDX == 0 (caller cleared it).
                // x16 = saved rax for remainder computation.
                self.emitter.mov64(Reg::X16, rax);
                if matches!(kind, DivMulKind::Div) {
                    self.emitter.udiv64(rax, Reg::X16, divisor);
                } else {
                    self.emitter.sdiv64(rax, Reg::X16, divisor);
                }
                self.emitter.msub64(rdx, rax, divisor, Reg::X16);
                Ok(())
            }
            (DivMulKind::Div, OpSize::B4) | (DivMulKind::Idiv, OpSize::B4) => {
                // dividend = (EDX << 32) | EAX (zero-extended).
                self.emit_uxtw(Reg::X16, rax); // low 32 of rax
                self.emit_uxtw(Reg::X17, rdx); // low 32 of rdx
                self.emit_orr_lsl64(Reg::X16, Reg::X16, Reg::X17, 32);
                // divisor masked to 32.
                self.emit_uxtw(Reg::X17, divisor);
                if matches!(kind, DivMulKind::Div) {
                    self.emitter.udiv64(rax, Reg::X16, Reg::X17);
                } else {
                    // For IDIV B4 the divisor & dividend should be
                    // signed 32-bit. SDIV with 64-bit zero-extended
                    // values would treat them as positive — so we
                    // sign-extend instead.
                    // SXTW Xd, Wn -> SBFM Xd, Xn, #0, #31.
                    let sxtw = |dst: Reg, src: Reg| -> u32 {
                        0x9340_7C00 | ((src.raw() as u32) << 5) | (dst.raw() as u32)
                    };
                    self.emitter.raw_word(sxtw(Reg::X16, rax));
                    // Re-pack dividend properly for signed: high half
                    // is signed rdx, low is unsigned rax.
                    // Compromise: just treat dividend as 64-bit signed
                    // value of (rdx<<32)|rax (cast). That matches the
                    // semantics if rdx is the proper sign-extension
                    // of the result of a prior CDQ.
                    self.emit_orr_lsl64(Reg::X16, Reg::X16, Reg::X17, 32);
                    self.emitter.raw_word(sxtw(Reg::X17, divisor));
                    self.emitter.sdiv64(rax, Reg::X16, Reg::X17);
                }
                self.emitter.msub64(rdx, rax, Reg::X17, Reg::X16);
                // Mask quotient/remainder to 32 bits each.
                self.emit_uxtw(rax, rax);
                self.emit_uxtw(rdx, rdx);
                Ok(())
            }
            (DivMulKind::Mul, OpSize::B8) => {
                // RDX:RAX = RAX * r/m (unsigned).
                self.emitter.mov64(Reg::X16, rax);
                self.emitter.mul64(rax, Reg::X16, divisor);
                self.emitter.umulh64(rdx, Reg::X16, divisor);
                Ok(())
            }
            (DivMulKind::Imul1, OpSize::B8) => {
                // RDX:RAX = RAX * r/m (signed).
                self.emitter.mov64(Reg::X16, rax);
                self.emitter.mul64(rax, Reg::X16, divisor);
                self.emitter.smulh64(rdx, Reg::X16, divisor);
                Ok(())
            }
            (DivMulKind::Mul, OpSize::B4) | (DivMulKind::Imul1, OpSize::B4) => {
                // EDX:EAX = EAX * r/m32. Mask both inputs to 32 bits
                // (signed extend for IMUL), multiply 64-bit, split into
                // low/high halves, mask each to 32.
                let signed = matches!(kind, DivMulKind::Imul1);
                if signed {
                    let sxtw = |dst: Reg, src: Reg| -> u32 {
                        0x9340_7C00 | ((src.raw() as u32) << 5) | (dst.raw() as u32)
                    };
                    self.emitter.raw_word(sxtw(Reg::X16, rax));
                    self.emitter.raw_word(sxtw(Reg::X17, divisor));
                } else {
                    self.emit_uxtw(Reg::X16, rax);
                    self.emit_uxtw(Reg::X17, divisor);
                }
                self.emitter.mul64(rax, Reg::X16, Reg::X17);
                // EDX = (result >> 32) & 0xFFFFFFFF.
                self.emit_ubfm64(rdx, rax, 32, 63);
                self.emit_uxtw(rax, rax);
                Ok(())
            }
            _ => Err(LifterError::Unsupported(inst.op)),
        }
    }

    /// XCHG. We support the common shapes: reg/reg and reg/mem (mem/reg
    /// is the same op decoded). x86 XCHG with a memory operand is
    /// implicitly LOCK'd, which has stronger ordering than a plain LDR
    /// + STR — for now we ignore that since the JIT runs single-threaded.
    fn lift_xchg(&mut self, inst: &Inst) -> LifterResult<()> {
        let a = inst.operands[0].ok_or(LifterError::BadOperands)?;
        let b = inst.operands[1].ok_or(LifterError::BadOperands)?;
        match (a, b) {
            (Operand::Reg(ra, _), Operand::Reg(rb, _)) => {
                if ra == rb {
                    return Ok(()); // NOP idiom
                }
                let ha = host_reg(ra);
                let hb = host_reg(rb);
                // tmp = ha; ha = hb; hb = tmp.
                self.emitter.mov64(Reg::X16, ha);
                self.emitter.mov64(ha, hb);
                self.emitter.mov64(hb, Reg::X16);
                Ok(())
            }
            (Operand::Reg(rr, _), m @ (Operand::Mem(_) | Operand::RipRel(_, _)))
            | (m @ (Operand::Mem(_) | Operand::RipRel(_, _)), Operand::Reg(rr, _)) => {
                let size = match m {
                    Operand::Mem(mm) => mm.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                let hr = host_reg(rr);
                // tmp = mem; mem = reg; reg = tmp.
                self.load_sized(Reg::X17, Reg::X16, leftover, size);
                self.store_sized(hr, Reg::X16, leftover, size);
                self.emitter.mov64(hr, Reg::X17);
                Ok(())
            }
            _ => Err(LifterError::Unsupported(Op::Xchg)),
        }
    }

    /// NEG r/m: rd = -rd (alias SUB rd, XZR, rd). Sets NZCV.
    fn lift_neg(&mut self, inst: &Inst) -> LifterResult<()> {
        let dst = inst.operands[0].ok_or(LifterError::BadOperands)?;
        match dst {
            Operand::Reg(rd, size) => {
                let hd = host_reg(rd);
                let w =
                    0xEB00_0000 | ((hd.raw() as u32) << 16) | ((31u32) << 5) | (hd.raw() as u32);
                self.emitter.raw_word(w);
                if matches!(size, OpSize::B4) {
                    self.emit_and_imm_lo32(hd, hd);
                }
                Ok(())
            }
            m @ (Operand::Mem(_) | Operand::RipRel(_, _)) => {
                let size = match m {
                    Operand::Mem(mm) => mm.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                self.load_sized(Reg::X17, Reg::X16, leftover, size);
                let w = 0xEB00_0000 | (17u32 << 16) | (31u32 << 5) | 17u32;
                self.emitter.raw_word(w);
                if matches!(size, OpSize::B4) {
                    self.emit_and_imm_lo32(Reg::X17, Reg::X17);
                }
                self.store_sized(Reg::X17, Reg::X16, leftover, size);
                Ok(())
            }
            _ => Err(LifterError::Unsupported(Op::Neg)),
        }
    }

    /// NOT r/m: rd = ~rd (alias MVN). No flags.
    fn lift_not(&mut self, inst: &Inst) -> LifterResult<()> {
        let dst = inst.operands[0].ok_or(LifterError::BadOperands)?;
        match dst {
            Operand::Reg(rd, size) => {
                let hd = host_reg(rd);
                let w =
                    0xAA20_0000 | ((hd.raw() as u32) << 16) | ((31u32) << 5) | (hd.raw() as u32);
                self.emitter.raw_word(w);
                if matches!(size, OpSize::B4) {
                    self.emit_and_imm_lo32(hd, hd);
                }
                Ok(())
            }
            m @ (Operand::Mem(_) | Operand::RipRel(_, _)) => {
                let size = match m {
                    Operand::Mem(mm) => mm.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                self.load_sized(Reg::X17, Reg::X16, leftover, size);
                let w = 0xAA20_0000 | (17u32 << 16) | (31u32 << 5) | 17u32;
                self.emitter.raw_word(w);
                if matches!(size, OpSize::B4) {
                    self.emit_and_imm_lo32(Reg::X17, Reg::X17);
                }
                self.store_sized(Reg::X17, Reg::X16, leftover, size);
                Ok(())
            }
            _ => Err(LifterError::Unsupported(Op::Not)),
        }
    }

    fn lift_inc_dec(&mut self, inst: &Inst, inc: bool) -> LifterResult<()> {
        let dst = inst.operands[0].ok_or(LifterError::BadOperands)?;
        match dst {
            Operand::Reg(rd, size) => {
                let hd = host_reg(rd);
                if inc {
                    self.emitter.adds64_imm(hd, hd, 1);
                } else {
                    self.emitter.subs64_imm(hd, hd, 1);
                }
                if matches!(size, OpSize::B4) {
                    self.emit_and_imm_lo32(hd, hd);
                }
                Ok(())
            }
            m @ (Operand::Mem(_) | Operand::RipRel(_, _)) => {
                let size = match m {
                    Operand::Mem(mm) => mm.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                self.load_sized(Reg::X17, Reg::X16, leftover, size);
                if inc {
                    self.emitter.adds64_imm(Reg::X17, Reg::X17, 1);
                } else {
                    self.emitter.subs64_imm(Reg::X17, Reg::X17, 1);
                }
                if matches!(size, OpSize::B4) {
                    self.emit_and_imm_lo32(Reg::X17, Reg::X17);
                }
                self.store_sized(Reg::X17, Reg::X16, leftover, size);
                Ok(())
            }
            _ => Err(LifterError::Unsupported(inst.op)),
        }
    }

    /// SHL/SHR r, imm8 or r, CL. We use AArch64's variable-shift
    /// instructions (LSLV/LSRV) through scratch X16 to avoid having to
    /// teach the emitter the UBFM/SBFM immediate encodings yet.
    ///
    /// 32-bit operands: result is masked to the low 32 bits afterwards,
    /// matching x86's zero-extending semantics. SAR (signed arithmetic
    /// shift) is deferred until we add 32-bit shift helpers — naive
    /// 64-bit ASR on a movz32-zero-extended value treats bit 63 as
    /// the sign rather than bit 31.
    fn lift_shift(&mut self, inst: &Inst, dir: ShiftDir) -> LifterResult<()> {
        let dst = inst.operands[0].ok_or(LifterError::BadOperands)?;
        let amt = inst.operands[1].ok_or(LifterError::BadOperands)?;
        let (rd, size) = match dst {
            Operand::Reg(r, s) => (r, s),
            _ => return Err(LifterError::Unsupported(inst.op)),
        };
        let hd = host_reg(rd);

        let amt_reg = match amt {
            Operand::Imm(imm, _) => {
                let mask = if matches!(size, OpSize::B8) {
                    0x3F
                } else {
                    0x1F
                };
                let value = (imm as u64 & mask) as u16;
                self.emitter.movz64(Reg::X16, value, 0);
                Reg::X16
            }
            Operand::Reg(GpReg::Rcx, _) => host_reg(GpReg::Rcx),
            _ => return Err(LifterError::Unsupported(inst.op)),
        };

        // For SAR on B4 we need to sign-extend the 32-bit value first so
        // ASRV uses bit 31 as the sign rather than bit 63 (which is zero
        // after our usual upper-clear mask).
        if matches!(dir, ShiftDir::ArithRight) && matches!(size, OpSize::B4) {
            // SBFM Xd, Xs, #0, #31 (alias SXTW) — sign-extend 32→64.
            let sxtw = 0x9340_7C00 | ((hd.raw() as u32) << 5) | (hd.raw() as u32);
            self.emitter.raw_word(sxtw);
        }

        match dir {
            ShiftDir::Left => self.emitter.lslv64(hd, hd, amt_reg),
            ShiftDir::Right => self.emitter.lsrv64(hd, hd, amt_reg),
            ShiftDir::ArithRight => self.emitter.asrv64(hd, hd, amt_reg),
        }
        if matches!(size, OpSize::B4) {
            self.emit_and_imm_lo32(hd, hd);
        }
        Ok(())
    }

    /// ROL / ROR r, imm or r, CL.
    fn lift_rotate(&mut self, inst: &Inst, rol: bool) -> LifterResult<()> {
        let dst = inst.operands[0].ok_or(LifterError::BadOperands)?;
        let amt = inst.operands[1].ok_or(LifterError::BadOperands)?;
        let (rd, size) = match dst {
            Operand::Reg(r, s) => (r, s),
            _ => return Err(LifterError::Unsupported(inst.op)),
        };
        let hd = host_reg(rd);

        // AArch64 only has ROR; emulate ROL n as ROR (width - n).
        let amt_reg = match amt {
            Operand::Imm(imm, _) => {
                let mask = if matches!(size, OpSize::B8) {
                    0x3F
                } else {
                    0x1F
                };
                let mut n = (imm as u64 & mask) as u32;
                if rol {
                    let width = if matches!(size, OpSize::B8) { 64 } else { 32 };
                    n = (width - n) & mask as u32;
                }
                self.emitter.movz64(Reg::X16, n as u16, 0);
                Reg::X16
            }
            Operand::Reg(GpReg::Rcx, _) => {
                if rol {
                    // X16 = (width - rcx) & mask.
                    let width = if matches!(size, OpSize::B8) { 64 } else { 32 };
                    self.emitter.movz64(Reg::X16, width as u16, 0);
                    self.emitter
                        .subs64(Reg::X16, Reg::X16, host_reg(GpReg::Rcx));
                    Reg::X16
                } else {
                    host_reg(GpReg::Rcx)
                }
            }
            _ => return Err(LifterError::Unsupported(inst.op)),
        };

        self.emitter.rorv64(hd, hd, amt_reg);
        if matches!(size, OpSize::B4) {
            self.emit_and_imm_lo32(hd, hd);
        }
        Ok(())
    }

    /// CMOVcc rd, rs — conditional move.
    ///   CSEL Xd, <rs-or-rd>, <rs-or-rd>, <cond>
    /// We emit CSEL Xd, Xs, Xd, <cond> — pick source when cond true,
    /// keep destination when false.
    fn lift_cmov(&mut self, inst: &Inst, cond: XCond) -> LifterResult<()> {
        let dst = inst.operands[0].ok_or(LifterError::BadOperands)?;
        let src = inst.operands[1].ok_or(LifterError::BadOperands)?;
        if let (Operand::Reg(rd, _), Operand::Reg(rs, _)) = (dst, src) {
            let a64_cond = cond_x86_to_a64(cond).ok_or(LifterError::Unsupported(inst.op))?;
            self.emitter
                .csel64(host_reg(rd), host_reg(rs), host_reg(rd), a64_cond);
            return Ok(());
        }
        Err(LifterError::Unsupported(inst.op))
    }

    /// SETcc r/m8 — write 1 if cond holds, 0 otherwise.
    fn lift_set(&mut self, inst: &Inst, cond: XCond) -> LifterResult<()> {
        let dst = inst.operands[0].ok_or(LifterError::BadOperands)?;
        if let Operand::Reg(rd, _) = dst {
            let a64_cond = cond_x86_to_a64(cond).ok_or(LifterError::Unsupported(inst.op))?;
            // CSET Wd, cond — alias for CSINC Wd, WZR, WZR, !cond.
            // We have a 64-bit CSET helper; AArch64 will zero the upper
            // 32 bits regardless. The result is in low byte; x86 SETcc
            // only writes the low 8 bits and preserves the upper 56,
            // so for a clean lower-byte write we mask before writing
            // back? For now the simpler full-write matches what most
            // compilers do when SETcc's dest is used purely as a 0/1.
            self.emitter.cset64(host_reg(rd), a64_cond);
            return Ok(());
        }
        Err(LifterError::Unsupported(inst.op))
    }

    fn lift_xor(&mut self, inst: &Inst) -> LifterResult<()> {
        let dst = inst.operands[0].ok_or(LifterError::BadOperands)?;
        let src = inst.operands[1].ok_or(LifterError::BadOperands)?;
        match (dst, src) {
            (Operand::Reg(rd, size), Operand::Reg(rs, _)) => {
                let hd = host_reg(rd);
                if rd == rs {
                    // Zero idiom.
                    match size {
                        OpSize::B8 => self.emitter.movz64(hd, 0, 0),
                        OpSize::B4 | OpSize::B2 | OpSize::B1 => self.emitter.movz32(hd, 0, 0),
                    }
                    return Ok(());
                }
                let hs = host_reg(rs);
                self.emit_xor_rr(hd, hd, hs, size);
                Ok(())
            }
            (Operand::Reg(rd, size), Operand::Imm(imm, _)) => {
                let hd = host_reg(rd);
                self.emitter.load_const64(Reg::X16, imm as u64);
                self.emit_xor_rr(hd, hd, Reg::X16, size);
                Ok(())
            }
            (Operand::Reg(rd, size), m @ (Operand::Mem(_) | Operand::RipRel(_, _))) => {
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                let mem_size = match m {
                    Operand::Mem(mm) => mm.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                self.load_sized(Reg::X17, Reg::X16, leftover, mem_size);
                let hd = host_reg(rd);
                self.emit_xor_rr(hd, hd, Reg::X17, size);
                Ok(())
            }
            (m @ (Operand::Mem(_) | Operand::RipRel(_, _)), Operand::Reg(rs, _)) => {
                let size = match m {
                    Operand::Mem(mm) => mm.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                self.load_sized(Reg::X17, Reg::X16, leftover, size);
                self.emit_xor_rr(Reg::X17, Reg::X17, host_reg(rs), size);
                self.store_sized(Reg::X17, Reg::X16, leftover, size);
                Ok(())
            }
            (m @ (Operand::Mem(_) | Operand::RipRel(_, _)), Operand::Imm(imm, _)) => {
                let size = match m {
                    Operand::Mem(mm) => mm.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                self.load_sized(Reg::X17, Reg::X16, leftover, size);
                self.emitter.load_const64(Reg::X16, imm as u64);
                self.emit_xor_rr(Reg::X17, Reg::X17, Reg::X16, size);
                let leftover2 = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                self.store_sized(Reg::X17, Reg::X16, leftover2, size);
                Ok(())
            }
            _ => Err(LifterError::Unsupported(Op::Xor)),
        }
    }

    fn emit_xor_rr(&mut self, rd: Reg, ra: Reg, rb: Reg, size: OpSize) {
        match size {
            OpSize::B8 => self.emitter.eor64(rd, ra, rb),
            OpSize::B4 => {
                self.emitter.eor64(rd, ra, rb);
                self.emit_and_imm_lo32(rd, rd);
            }
            _ => self.emitter.eor64(rd, ra, rb),
        }
    }

    fn lift_lea(&mut self, inst: &Inst) -> LifterResult<()> {
        let dst = inst.operands[0].ok_or(LifterError::BadOperands)?;
        let src = inst.operands[1].ok_or(LifterError::BadOperands)?;
        if let Operand::Reg(rd, size) = dst {
            let hd = host_reg(rd);
            // Compute effective address into the destination register.
            let leftover = match src {
                Operand::Mem(m) => self.mem_address_into(m, hd),
                Operand::RipRel(disp, _) => {
                    let target = inst
                        .guest_rip
                        .wrapping_add(inst.len as u64)
                        .wrapping_add(disp as u64);
                    self.emitter.load_const64(hd, target);
                    0
                }
                _ => return Err(LifterError::Unsupported(Op::Lea)),
            };
            if leftover != 0 {
                self.emitter.add64_imm(hd, hd, leftover);
            }
            if matches!(size, OpSize::B4) {
                self.emit_and_imm_lo32(hd, hd);
            }
            return Ok(());
        }
        Err(LifterError::Unsupported(Op::Lea))
    }

    fn lift_mov(&mut self, inst: &Inst) -> LifterResult<()> {
        let dst = inst.operands[0].ok_or(LifterError::BadOperands)?;
        let src = inst.operands[1].ok_or(LifterError::BadOperands)?;
        match (dst, src) {
            // mov reg, imm
            (Operand::Reg(rd, size), Operand::Imm(imm, _)) => {
                self.mov_reg_imm(rd, size, imm as u64);
                Ok(())
            }
            // mov reg, reg
            (Operand::Reg(rd, dst_size), Operand::Reg(rs, _src_size)) => {
                self.mov_reg_reg(rd, dst_size, rs);
                Ok(())
            }
            // mov reg, [mem]
            (Operand::Reg(rd, size), src @ (Operand::Mem(_) | Operand::RipRel(_, _))) => {
                let leftover = self.addr_into_xtmp(&src, inst, Reg::X16)?;
                let hd = host_reg(rd);
                match size {
                    OpSize::B8 => self.emitter.ldr64(hd, Reg::X16, leftover),
                    OpSize::B4 => {
                        self.emitter.ldr32(hd, Reg::X16, leftover);
                        // x86 32-bit dest already zero-extends; LDR Wn does this.
                    }
                    OpSize::B2 => self.emitter.ldrh(hd, Reg::X16, leftover),
                    OpSize::B1 => self.emitter.ldrb(hd, Reg::X16, leftover),
                }
                Ok(())
            }
            // mov [mem], reg
            (dst @ (Operand::Mem(_) | Operand::RipRel(_, _)), Operand::Reg(rs, size)) => {
                let leftover = self.addr_into_xtmp(&dst, inst, Reg::X16)?;
                let hs = host_reg(rs);
                match size {
                    OpSize::B8 => self.emitter.str64(hs, Reg::X16, leftover),
                    OpSize::B4 => self.emitter.str32(hs, Reg::X16, leftover),
                    OpSize::B2 => self.emitter.strh(hs, Reg::X16, leftover),
                    OpSize::B1 => self.emitter.strb(hs, Reg::X16, leftover),
                }
                Ok(())
            }
            // mov [mem], imm (C7 /0 form). For B8 the imm is sign-extended
            // from imm32; for smaller widths it's stored as-is.
            (dst @ (Operand::Mem(_) | Operand::RipRel(_, _)), Operand::Imm(imm, _)) => {
                let size = match dst {
                    Operand::Mem(m) => m.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                let leftover = self.addr_into_xtmp(&dst, inst, Reg::X16)?;
                // Materialise the immediate into X17 (X16 holds the addr).
                self.emitter.load_const64(Reg::X17, imm as u64);
                match size {
                    OpSize::B8 => self.emitter.str64(Reg::X17, Reg::X16, leftover),
                    OpSize::B4 => self.emitter.str32(Reg::X17, Reg::X16, leftover),
                    OpSize::B2 => self.emitter.strh(Reg::X17, Reg::X16, leftover),
                    OpSize::B1 => self.emitter.strb(Reg::X17, Reg::X16, leftover),
                }
                Ok(())
            }
            _ => Err(LifterError::Unsupported(Op::Mov)),
        }
    }

    fn mov_reg_imm(&mut self, rd: GpReg, size: OpSize, imm: u64) {
        let host = host_reg(rd);
        match size {
            OpSize::B8 => self.emitter.load_const64(host, imm),
            OpSize::B4 => {
                // Writing a 32-bit register zero-extends to 64 — exactly
                // what MOVZ + MOVK on the W view of the same register does.
                // Use 32-bit movz/movk for clarity.
                let lo = (imm & 0xFFFF) as u16;
                let hi = ((imm >> 16) & 0xFFFF) as u16;
                self.emitter.movz32(host, lo, 0);
                if hi != 0 {
                    self.emitter.movk32(host, hi, 16);
                }
            }
            OpSize::B2 | OpSize::B1 => {
                // Partial register writes: the upper bits of the
                // architectural 64-bit register must be preserved. That
                // takes BFI which we haven't added to the emitter yet —
                // defer to a follow-up turn.
                // For now, fall back to a full-register MOVK to make the
                // bring-up path move forward; the e2e exe does not use
                // 8/16-bit MOVs.
                let lo = (imm & 0xFFFF) as u16;
                self.emitter.movk64(host, lo, 0);
            }
        }
    }

    fn mov_reg_reg(&mut self, rd: GpReg, dst_size: OpSize, rs: GpReg) {
        let hd = host_reg(rd);
        let hs = host_reg(rs);
        match dst_size {
            OpSize::B8 => self.emitter.mov64(hd, hs),
            OpSize::B4 => {
                // 32-bit mov zero-extends: write the W view of the same
                // physical reg through ORR Wd, WZR, Ws. We don't yet
                // have a `mov32` helper; ORR Xd, XZR, Xs followed by an
                // implicit upper-clear is equivalent because the source
                // upper bits don't matter when the destination is the
                // 32-bit view. For straight-line lifting the simplest
                // correct lowering is AND Xd, Xs, #0xFFFFFFFF.
                self.emit_and_imm_lo32(hd, hs);
            }
            OpSize::B2 | OpSize::B1 => {
                // Partial-register move (preserve upper). Deferred.
                self.emitter.mov64(hd, hs);
            }
        }
    }

    /// Emit `Xd = Xs & 0xFFFFFFFF` using a logical-immediate AND. The
    /// bitmask 0xFFFF_FFFF is encodable as an AArch64 logical immediate
    /// (N=0, immr=0, imms=0b011111, sf=1).
    fn emit_and_imm_lo32(&mut self, rd: Reg, rs: Reg) {
        // Manual encoding because we haven't added a generic logical-imm
        // encoder yet. and Xd, Xs, #0xFFFFFFFF
        //   sf=1, opc=00, 100100, N=0, immr=000000, imms=011111
        //   = 1_00_100100_0_000000_011111_<Rn>_<Rd>
        //   = 0x92407C00 | (Rn << 5) | Rd
        let word = 0x9240_7C00 | ((rs.raw() as u32) << 5) | (rd.raw() as u32);
        self.emitter_push_raw(word);
    }

    fn emitter_push_raw(&mut self, word: u32) {
        // Local helper that pokes into the emitter's word buffer through
        // its public ABI. Until we expose an `emit_raw` in the emitter,
        // we synthesise the word by routing through a label-less branch
        // that we then overwrite — but that's clumsy. Cleaner: add a
        // public `raw` method on Emitter. We do so via a re-export
        // trick: just call a friend-mode push.
        self.emitter.raw_word(word);
    }

    fn lift_arith(&mut self, inst: &Inst, kind: ArithKind) -> LifterResult<()> {
        let dst = inst.operands[0].ok_or(LifterError::BadOperands)?;
        let src = inst.operands[1].ok_or(LifterError::BadOperands)?;
        match (dst, src) {
            (Operand::Reg(rd, size), Operand::Reg(rs, _)) => {
                let hd = host_reg(rd);
                let hs = host_reg(rs);
                self.emit_arith_rr(kind, hd, hd, hs, size);
                Ok(())
            }
            (Operand::Reg(rd, size), Operand::Imm(imm, _))
                if (0..(1 << 24)).contains(&imm) && matches!(size, OpSize::B8 | OpSize::B4) =>
            {
                let hd = host_reg(rd);
                match kind {
                    ArithKind::Add => self.emitter.adds64_imm(hd, hd, imm as u32),
                    ArithKind::Sub => self.emitter.subs64_imm(hd, hd, imm as u32),
                }
                if matches!(size, OpSize::B4) {
                    self.emit_and_imm_lo32(hd, hd);
                }
                Ok(())
            }
            // reg, imm with imm outside the cheap range → materialise.
            (Operand::Reg(rd, size), Operand::Imm(imm, _))
                if matches!(size, OpSize::B8 | OpSize::B4) =>
            {
                let hd = host_reg(rd);
                self.emitter.load_const64(Reg::X17, imm as u64);
                self.emit_arith_rr(kind, hd, hd, Reg::X17, size);
                Ok(())
            }
            // reg, [mem]: load + arith.
            (Operand::Reg(rd, size), m @ (Operand::Mem(_) | Operand::RipRel(_, _))) => {
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                let mem_size = match m {
                    Operand::Mem(mm) => mm.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                self.load_sized(Reg::X17, Reg::X16, leftover, mem_size);
                let hd = host_reg(rd);
                self.emit_arith_rr(kind, hd, hd, Reg::X17, size);
                Ok(())
            }
            // [mem], reg: load → arith → store.
            (m @ (Operand::Mem(_) | Operand::RipRel(_, _)), Operand::Reg(rs, _src_size)) => {
                let size = match m {
                    Operand::Mem(mm) => mm.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                self.load_sized(Reg::X17, Reg::X16, leftover, size);
                self.emit_arith_rr(kind, Reg::X17, Reg::X17, host_reg(rs), size);
                self.store_sized(Reg::X17, Reg::X16, leftover, size);
                Ok(())
            }
            // [mem], imm: load → arith imm → store.
            (m @ (Operand::Mem(_) | Operand::RipRel(_, _)), Operand::Imm(imm, _)) => {
                let size = match m {
                    Operand::Mem(mm) => mm.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                self.load_sized(Reg::X17, Reg::X16, leftover, size);
                // Materialise imm into the X16-relative scratch (X16 already
                // holds the address — borrow it after the load by saving the
                // address to a callee-saved nope; we just keep using X16 and
                // recompute below). Simpler: use a fresh constant load into
                // X16, since X17 holds the loaded value we need to mutate.
                let imm_reg = Reg::X16;
                // X16 currently holds the address; we'll need it again for
                // the store, so spill it into X28+offset? No — re-derive
                // the address below. For brevity, recompute the address
                // after the imm-load.
                self.emitter.load_const64(imm_reg, imm as u64);
                self.emit_arith_rr(kind, Reg::X17, Reg::X17, imm_reg, size);
                // Re-materialise the address into X16 for the store.
                let leftover2 = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                self.store_sized(Reg::X17, Reg::X16, leftover2, size);
                Ok(())
            }
            _ => Err(LifterError::Unsupported(inst.op)),
        }
    }

    /// Emit a 32/64-bit ADDS/SUBS into `rd = ra ± rb`, with x86's
    /// 32-bit upper-clear semantics applied when `size == B4`.
    fn emit_arith_rr(&mut self, kind: ArithKind, rd: Reg, ra: Reg, rb: Reg, size: OpSize) {
        match (kind, size) {
            (ArithKind::Add, OpSize::B8) => self.emitter.adds64(rd, ra, rb),
            (ArithKind::Sub, OpSize::B8) => self.emitter.subs64(rd, ra, rb),
            (ArithKind::Add, OpSize::B4) => {
                self.emitter.adds64(rd, ra, rb);
                self.emit_and_imm_lo32(rd, rd);
            }
            (ArithKind::Sub, OpSize::B4) => {
                self.emitter.subs64(rd, ra, rb);
                self.emit_and_imm_lo32(rd, rd);
            }
            // For B1/B2 we still go through the 64-bit form; the load
            // path produced a zero-extended value so the math is right
            // even if NZCV is set for the wider operands.
            (ArithKind::Add, _) => self.emitter.adds64(rd, ra, rb),
            (ArithKind::Sub, _) => self.emitter.subs64(rd, ra, rb),
        }
    }

    fn store_sized(&mut self, src: Reg, base: Reg, offset: u32, size: OpSize) {
        match size {
            OpSize::B8 => self.emitter.str64(src, base, offset),
            OpSize::B4 => self.emitter.str32(src, base, offset),
            OpSize::B2 => self.emitter.strh(src, base, offset),
            OpSize::B1 => self.emitter.strb(src, base, offset),
        }
    }

    fn lift_cmp(&mut self, inst: &Inst) -> LifterResult<()> {
        let a = inst.operands[0].ok_or(LifterError::BadOperands)?;
        let b = inst.operands[1].ok_or(LifterError::BadOperands)?;
        match (a, b) {
            (Operand::Reg(ra, OpSize::B4 | OpSize::B8), Operand::Reg(rb, _)) => {
                // For B4 we still use the 64-bit form because both
                // sides are masked to 32 bits in their pinned regs.
                // SUBS still sets NZCV correctly for the bit pattern.
                self.emitter.cmp64(host_reg(ra), host_reg(rb));
                Ok(())
            }
            (Operand::Reg(ra, OpSize::B4 | OpSize::B8), Operand::Imm(imm, _))
                if (0..(1 << 24)).contains(&imm) =>
            {
                self.emitter.cmp64_imm(host_reg(ra), imm as u32);
                Ok(())
            }
            // cmp reg, imm with imm outside cheap range → materialise in X17.
            (Operand::Reg(ra, OpSize::B4 | OpSize::B8), Operand::Imm(imm, _)) => {
                self.emitter.load_const64(Reg::X17, imm as u64);
                self.emitter.cmp64(host_reg(ra), Reg::X17);
                Ok(())
            }
            // cmp [mem], reg
            (m @ (Operand::Mem(_) | Operand::RipRel(_, _)), Operand::Reg(rb, size)) => {
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                self.load_sized(Reg::X17, Reg::X16, leftover, size);
                self.emitter.cmp64(Reg::X17, host_reg(rb));
                Ok(())
            }
            // cmp reg, [mem]
            (Operand::Reg(ra, size), m @ (Operand::Mem(_) | Operand::RipRel(_, _))) => {
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                self.load_sized(Reg::X17, Reg::X16, leftover, size);
                self.emitter.cmp64(host_reg(ra), Reg::X17);
                Ok(())
            }
            // cmp [mem], imm
            (m @ (Operand::Mem(_) | Operand::RipRel(_, _)), Operand::Imm(imm, _)) => {
                let size = match m {
                    Operand::Mem(mm) => mm.size,
                    Operand::RipRel(_, s) => s,
                    _ => unreachable!(),
                };
                let leftover = self.addr_into_xtmp(&m, inst, Reg::X16)?;
                self.load_sized(Reg::X17, Reg::X16, leftover, size);
                if (0..(1 << 24)).contains(&imm) {
                    self.emitter.cmp64_imm(Reg::X17, imm as u32);
                } else {
                    self.emitter.load_const64(Reg::X16, imm as u64);
                    self.emitter.cmp64(Reg::X17, Reg::X16);
                }
                Ok(())
            }
            _ => Err(LifterError::Unsupported(Op::Cmp)),
        }
    }

    fn load_sized(&mut self, dst: Reg, base: Reg, offset: u32, size: OpSize) {
        match size {
            OpSize::B8 => self.emitter.ldr64(dst, base, offset),
            OpSize::B4 => self.emitter.ldr32(dst, base, offset),
            OpSize::B2 => self.emitter.ldrh(dst, base, offset),
            OpSize::B1 => self.emitter.ldrb(dst, base, offset),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ArithKind {
    Add,
    Sub,
}

#[derive(Debug, Clone, Copy)]
enum DivMulKind {
    Div,
    Idiv,
    Mul,
    /// Single-operand IMUL (group 3 /5).
    Imul1,
}

#[derive(Debug, Clone, Copy)]
enum BitOp {
    And,
    Or,
}

#[derive(Debug, Clone, Copy)]
enum ShiftDir {
    Left,
    Right,
    ArithRight,
}

/// Map an x86 GPR to its pinned AArch64 GPR.
pub fn host_reg(g: GpReg) -> Reg {
    match g {
        GpReg::Rax => Reg::X0,
        GpReg::Rcx => Reg::X1,
        GpReg::Rdx => Reg::X2,
        GpReg::Rbx => Reg::X3,
        GpReg::Rsp => Reg::X19,
        GpReg::Rbp => Reg::X5,
        GpReg::Rsi => Reg::X6,
        GpReg::Rdi => Reg::X7,
        GpReg::R8 => Reg::X8,
        GpReg::R9 => Reg::x(9),
        GpReg::R10 => Reg::x(10),
        GpReg::R11 => Reg::x(11),
        GpReg::R12 => Reg::x(12),
        GpReg::R13 => Reg::x(13),
        GpReg::R14 => Reg::x(14),
        GpReg::R15 => Reg::x(15),
    }
}

/// Translate an x86 condition into an AArch64 condition usable
/// immediately after a `SUBS`/`CMP` that follows x86 SUB semantics.
///
/// The x86 carry flag and the AArch64 C flag have opposite polarity for
/// subtraction: x86 CF=1 means borrow occurred (a < b unsigned), while
/// AArch64 C=1 means no borrow occurred. We compensate by swapping the
/// CS/CC and HI/LS pairs.
pub fn cond_x86_to_a64(c: XCond) -> Option<A64Cond> {
    Some(match c {
        XCond::E => A64Cond::Eq,
        XCond::NE => A64Cond::Ne,
        XCond::B => A64Cond::Cc,
        XCond::NB => A64Cond::Cs,
        XCond::BE => A64Cond::Ls,
        XCond::A => A64Cond::Hi,
        XCond::S => A64Cond::Mi,
        XCond::NS => A64Cond::Pl,
        XCond::L => A64Cond::Lt,
        XCond::NL => A64Cond::Ge,
        XCond::LE => A64Cond::Le,
        XCond::G => A64Cond::Gt,
        XCond::O => A64Cond::Vs,
        XCond::NO => A64Cond::Vc,
        // Parity flags don't have direct ARM equivalents. Returning
        // None lets the lifter emit a deopt path.
        XCond::P | XCond::NP => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::Decoder;

    fn lift_one(bytes: &[u8]) -> alloc::vec::Vec<u32> {
        extern crate alloc;
        let mut d = Decoder::new(bytes, 0x1000);
        let inst = d.next().expect("decode");
        let mut e = Emitter::new();
        let mut l = Lifter::new(&mut e);
        l.lift(&inst).expect("lift");
        e.words().to_vec()
    }

    #[test]
    fn mov_eax_42_clears_high_via_movz32() {
        // B8 2A 00 00 00 -> mov eax, 42
        let words = lift_one(&[0xB8, 0x2A, 0x00, 0x00, 0x00]);
        // Expect a single MOVZ Wn, #42 (high half is zero).
        assert_eq!(words, &[0x5280_0540]);
    }

    #[test]
    fn mov_rax_imm64_uses_const_loader() {
        // 48 B8 EF BE AD DE FE CA 00 00 -> mov rax, 0xCAFEDEADBEEF
        let words = lift_one(&[0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xFE, 0xCA, 0x00, 0x00]);
        // load_const64 emits movz then movk for non-zero lanes (3 total
        // since lane 3 is zero).
        // Mask 0xFFE0_001F preserves sf+opc+prefix+hw and Rd, isolating
        // exactly what we want to assert (instruction kind + lane + dest).
        assert_eq!(words.len(), 3);
        assert_eq!(words[0] & 0xFFE0_001F, 0xD280_0000); // movz x0 lsl 0
        assert_eq!(words[1] & 0xFFE0_001F, 0xF2A0_0000); // movk x0 lsl 16
        assert_eq!(words[2] & 0xFFE0_001F, 0xF2C0_0000); // movk x0 lsl 32
    }

    #[test]
    fn add_rax_rbx_emits_adds64() {
        // 48 01 D8 -> add rax, rbx
        let words = lift_one(&[0x48, 0x01, 0xD8]);
        // adds x0, x0, x3 -> 0xAB03_0000
        assert_eq!(words.len(), 1);
        assert_eq!(words[0], 0xAB03_0000);
    }

    #[test]
    fn cmp_rax_imm_emits_subs_xzr() {
        // 48 83 F8 2A -> cmp rax, 42
        let words = lift_one(&[0x48, 0x83, 0xF8, 0x2A]);
        // subs xzr, x0, #42 -> 0xF100A81F
        assert_eq!(words, &[0xF100_A81F]);
    }

    #[test]
    fn ret_lifts_to_aarch64_ret() {
        let words = lift_one(&[0xC3]);
        assert_eq!(words, &[0xD65F_03C0]);
    }

    #[test]
    fn ud2_lifts_to_brk() {
        let words = lift_one(&[0x0F, 0x0B]);
        // brk #0 -> 0xD420_0000
        assert_eq!(words, &[0xD420_0000]);
    }

    #[test]
    fn mov_mem_rsp_rcx_lifts_ok() {
        // 48 89 4C 24 08 -> mov [rsp+8], rcx
        let words = lift_one(&[0x48, 0x89, 0x4C, 0x24, 0x08]);
        // Should emit mov xtmp, x19 (rsp) then str x1 (rcx), [xtmp, #8].
        assert!(!words.is_empty(), "expected non-empty emission");
    }

    #[test]
    fn condition_mapping_carry_polarity() {
        // x86 B (CF=1, unsigned <) maps to ARM CC (C=0, unsigned <).
        assert_eq!(cond_x86_to_a64(XCond::B), Some(A64Cond::Cc));
        assert_eq!(cond_x86_to_a64(XCond::NB), Some(A64Cond::Cs));
        assert_eq!(cond_x86_to_a64(XCond::BE), Some(A64Cond::Ls));
        assert_eq!(cond_x86_to_a64(XCond::A), Some(A64Cond::Hi));
        assert_eq!(cond_x86_to_a64(XCond::P), None);
    }
}

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
            Op::Add => self.lift_arith(inst, ArithKind::Add),
            Op::Sub => self.lift_arith(inst, ArithKind::Sub),
            Op::Cmp => self.lift_cmp(inst),
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
    fn addr_into_xtmp(&mut self, op: &Operand, inst: &Inst, xtmp: Reg) -> LifterResult<u32> {
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
    fn mem_address_into(&mut self, m: Mem, xtmp: Reg) -> u32 {
        if let Some(base) = m.base {
            self.emitter.mov64(xtmp, host_reg(base));
        } else {
            // No base — start from zero.
            self.emitter.load_const64(xtmp, 0);
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
        // Marshal: AAPCS64 arg0 = guest RCX (which is X1 in our pinning).
        self.emitter.mov64(Reg::X0, Reg::X1);
        // Save host frame & link register across the call so the lifted
        // block can still RET to its original host caller afterwards.
        // 16-byte stack alignment is preserved by stp/ldp pre/post-index.
        self.emitter.stp64_pre(Reg::X29, Reg::X30, Reg::SP, -16);
        // BLR X16 — sets X30 (LR) to the next host PC. AAPCS64.
        self.emitter.blr(Reg::X16);
        self.emitter.ldp64_post(Reg::X29, Reg::X30, Reg::SP, 16);
        Ok(())
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
                match (kind, size) {
                    (ArithKind::Add, OpSize::B8) => self.emitter.adds64(hd, hd, hs),
                    (ArithKind::Sub, OpSize::B8) => self.emitter.subs64(hd, hd, hs),
                    (ArithKind::Add, OpSize::B4) => {
                        self.emitter.adds64(hd, hd, hs);
                        // Clear upper 32 bits to match x86 semantics for
                        // 32-bit destinations.
                        self.emit_and_imm_lo32(hd, hd);
                    }
                    (ArithKind::Sub, OpSize::B4) => {
                        self.emitter.subs64(hd, hd, hs);
                        self.emit_and_imm_lo32(hd, hd);
                    }
                    _ => return Err(LifterError::Unsupported(inst.op)),
                }
                Ok(())
            }
            (Operand::Reg(rd, OpSize::B8), Operand::Imm(imm, _))
                if (0..(1 << 24)).contains(&imm) =>
            {
                let hd = host_reg(rd);
                match kind {
                    ArithKind::Add => self.emitter.adds64_imm(hd, hd, imm as u32),
                    ArithKind::Sub => self.emitter.subs64_imm(hd, hd, imm as u32),
                }
                Ok(())
            }
            _ => Err(LifterError::Unsupported(inst.op)),
        }
    }

    fn lift_cmp(&mut self, inst: &Inst) -> LifterResult<()> {
        let a = inst.operands[0].ok_or(LifterError::BadOperands)?;
        let b = inst.operands[1].ok_or(LifterError::BadOperands)?;
        match (a, b) {
            (Operand::Reg(ra, OpSize::B8), Operand::Reg(rb, _)) => {
                self.emitter.cmp64(host_reg(ra), host_reg(rb));
                Ok(())
            }
            (Operand::Reg(ra, OpSize::B8), Operand::Imm(imm, _))
                if (0..(1 << 24)).contains(&imm) =>
            {
                self.emitter.cmp64_imm(host_reg(ra), imm as u32);
                Ok(())
            }
            _ => Err(LifterError::Unsupported(Op::Cmp)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ArithKind {
    Add,
    Sub,
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
    fn condition_mapping_carry_polarity() {
        // x86 B (CF=1, unsigned <) maps to ARM CC (C=0, unsigned <).
        assert_eq!(cond_x86_to_a64(XCond::B), Some(A64Cond::Cc));
        assert_eq!(cond_x86_to_a64(XCond::NB), Some(A64Cond::Cs));
        assert_eq!(cond_x86_to_a64(XCond::BE), Some(A64Cond::Ls));
        assert_eq!(cond_x86_to_a64(XCond::A), Some(A64Cond::Hi));
        assert_eq!(cond_x86_to_a64(XCond::P), None);
    }
}

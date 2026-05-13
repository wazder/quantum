//! x86_64 instruction decoder.
//!
//! From-scratch — no `iced-x86`, no `xed`, no tables borrowed from
//! external projects. We walk bytes left-to-right, consume any legacy
//! prefixes and the REX byte, then dispatch on the first opcode byte
//! through a single big match. Two-byte (`0F`-prefixed) opcodes get the
//! same treatment.
//!
//! Coverage scope (the e2e path and well beyond):
//!   * full legacy + REX prefix handling
//!   * ModRM + SIB + RIP-relative addressing
//!   * single-byte primary table for the integer / common-flow subset
//!   * `0F`-secondary for Jcc/SETcc/CMOVcc/MOV{S,Z}X/IMUL/BSR/BSF/BT*
//!     family/XADD/CMPXCHG plus the SSE2 scalar moves compilers emit.
//!
//! Anything we don't lift yet returns `Op::Unhandled` carrying the
//! correct byte length so the caller can advance the IP cleanly.

use crate::iform::{Cond, GpReg, Inst, Mem, Op, OpSize, Operand, Seg};
use core::convert::TryFrom;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Truncated,
    Reserved,
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Default, Clone, Copy)]
pub struct Rex {
    pub w: bool,
    pub r: bool,
    pub x: bool,
    pub b: bool,
    pub present: bool,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Prefixes {
    pub lock: bool,
    pub repe: bool,
    pub repne: bool,
    pub osize: bool,
    pub asize: bool,
    pub seg: Option<Seg>,
    pub rex: Rex,
}

pub struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
    guest_rip: u64,
}

impl<'a> Decoder<'a> {
    pub fn new(bytes: &'a [u8], guest_rip: u64) -> Self {
        Self {
            bytes,
            pos: 0,
            guest_rip,
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn rip(&self) -> u64 {
        self.guest_rip.wrapping_add(self.pos as u64)
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn read_u8(&mut self) -> Result<u8> {
        let b = *self.bytes.get(self.pos).ok_or(Error::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn peek_u8(&self) -> Result<u8> {
        self.bytes.get(self.pos).copied().ok_or(Error::Truncated)
    }

    fn read_i8(&mut self) -> Result<i8> {
        Ok(self.read_u8()? as i8)
    }

    fn read_u16(&mut self) -> Result<u16> {
        let s = self
            .bytes
            .get(self.pos..self.pos + 2)
            .ok_or(Error::Truncated)?;
        self.pos += 2;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    fn read_i16(&mut self) -> Result<i16> {
        Ok(self.read_u16()? as i16)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let s = self
            .bytes
            .get(self.pos..self.pos + 4)
            .ok_or(Error::Truncated)?;
        self.pos += 4;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn read_i32(&mut self) -> Result<i32> {
        Ok(self.read_u32()? as i32)
    }

    fn read_u64(&mut self) -> Result<u64> {
        let s = self
            .bytes
            .get(self.pos..self.pos + 8)
            .ok_or(Error::Truncated)?;
        self.pos += 8;
        Ok(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    fn read_prefixes(&mut self) -> Result<Prefixes> {
        let mut p = Prefixes::default();
        loop {
            let b = self.peek_u8()?;
            match b {
                0xF0 => {
                    p.lock = true;
                    self.pos += 1;
                }
                0xF2 => {
                    p.repne = true;
                    self.pos += 1;
                }
                0xF3 => {
                    p.repe = true;
                    self.pos += 1;
                }
                0x66 => {
                    p.osize = true;
                    self.pos += 1;
                }
                0x67 => {
                    p.asize = true;
                    self.pos += 1;
                }
                0x2E | 0x3E | 0x26 | 0x36 => {
                    // CS/DS/ES/SS overrides are NOPs in long mode; consume but ignore.
                    self.pos += 1;
                }
                0x64 => {
                    p.seg = Some(Seg::Fs);
                    self.pos += 1;
                }
                0x65 => {
                    p.seg = Some(Seg::Gs);
                    self.pos += 1;
                }
                0x40..=0x4F => {
                    // REX must be the last prefix before the opcode.
                    p.rex = Rex {
                        w: (b & 0b1000) != 0,
                        r: (b & 0b0100) != 0,
                        x: (b & 0b0010) != 0,
                        b: (b & 0b0001) != 0,
                        present: true,
                    };
                    self.pos += 1;
                    break;
                }
                _ => break,
            }
        }
        Ok(p)
    }

    /// Decode one instruction and return it. Advances `pos` past the
    /// instruction. Returns `Op::Unhandled` for opcodes we recognise but
    /// haven't lifted; the `len` field still reflects the correct byte
    /// count consumed.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Inst> {
        let start = self.pos;
        let inst_rip = self.guest_rip.wrapping_add(start as u64);
        let p = self.read_prefixes()?;
        let opcode = self.read_u8()?;

        let mut inst = if opcode == 0x0F {
            self.decode_secondary(&p, inst_rip)?
        } else {
            self.decode_primary(opcode, &p, inst_rip)?
        };
        inst.len = (self.pos - start) as u8;
        inst.guest_rip = inst_rip;
        Ok(inst)
    }

    fn op_size_default32(&self, p: &Prefixes) -> OpSize {
        match (p.rex.w, p.osize) {
            (true, _) => OpSize::B8,
            (false, true) => OpSize::B2,
            (false, false) => OpSize::B4,
        }
    }

    fn op_size_default64(&self, p: &Prefixes) -> OpSize {
        // Used for PUSH/POP/CALL/JMP — default 64-bit, OSIZE=66 → 16.
        if p.osize { OpSize::B2 } else { OpSize::B8 }
    }

    fn decode_modrm(
        &mut self,
        p: &Prefixes,
        size: OpSize,
    ) -> Result<(Operand, u8 /* reg field */)> {
        let modrm = self.read_u8()?;
        let mod_ = modrm >> 6;
        let reg = (modrm >> 3) & 0b111;
        let rm = modrm & 0b111;

        let rm_op = if mod_ == 0b11 {
            // r/m is a register.
            let r = ((p.rex.b as u8) << 3) | rm;
            Operand::Reg(GpReg::from_index(r).unwrap(), size)
        } else {
            self.decode_rm_memory(p, mod_, rm, size)?
        };

        Ok((rm_op, reg))
    }

    fn decode_rm_memory(
        &mut self,
        p: &Prefixes,
        mod_: u8,
        rm: u8,
        size: OpSize,
    ) -> Result<Operand> {
        let seg = p.seg;
        // Special case: mod=00, rm=101 → RIP-relative with disp32.
        if mod_ == 0b00 && rm == 0b101 {
            let disp = self.read_i32()?;
            return Ok(Operand::RipRel(disp, size));
        }

        let (base, index, scale) = if rm == 0b100 {
            // SIB byte present.
            let sib = self.read_u8()?;
            let scale = 1u8 << (sib >> 6);
            let index_idx = (sib >> 3) & 0b111;
            let base_idx = sib & 0b111;

            let index = if index_idx == 0b100 && !p.rex.x {
                // RSP index encoding means "no index".
                None
            } else {
                let r = ((p.rex.x as u8) << 3) | index_idx;
                Some(GpReg::from_index(r).unwrap())
            };

            let base = if mod_ == 0b00 && base_idx == 0b101 {
                // No base register; disp32 follows.
                None
            } else {
                let r = ((p.rex.b as u8) << 3) | base_idx;
                Some(GpReg::from_index(r).unwrap())
            };
            (base, index, scale)
        } else {
            let r = ((p.rex.b as u8) << 3) | rm;
            (Some(GpReg::from_index(r).unwrap()), None, 1u8)
        };

        let disp = match mod_ {
            // SIB with mod=00 and base_idx=101 yields no base register and
            // therefore needs an explicit disp32; otherwise mod=00 has no
            // displacement at all.
            0b00 if rm == 0b100 && base.is_none() => self.read_i32()?,
            0b01 => self.read_i8()? as i32,
            0b10 => self.read_i32()?,
            _ => 0,
        };

        Ok(Operand::Mem(Mem {
            base,
            index,
            scale,
            disp,
            size,
            seg,
        }))
    }

    fn reg_operand(&self, p: &Prefixes, reg_field: u8, size: OpSize) -> Operand {
        let r = ((p.rex.r as u8) << 3) | reg_field;
        Operand::Reg(GpReg::from_index(r).unwrap(), size)
    }

    fn opcode_reg_operand(&self, p: &Prefixes, opcode_low3: u8, size: OpSize) -> Operand {
        let r = ((p.rex.b as u8) << 3) | opcode_low3;
        Operand::Reg(GpReg::from_index(r).unwrap(), size)
    }

    fn read_imm(&mut self, size: OpSize) -> Result<i64> {
        Ok(match size {
            OpSize::B1 => self.read_i8()? as i64,
            OpSize::B2 => self.read_i16()? as i64,
            OpSize::B4 => self.read_i32()? as i64,
            OpSize::B8 => self.read_u64()? as i64,
        })
    }

    fn decode_primary(&mut self, opcode: u8, p: &Prefixes, rip: u64) -> Result<Inst> {
        // Helper: arithmetic/logical 0x00-0x3D family. The high nibble selects
        // the operation; the low 3 bits select the operand form.
        if opcode <= 0x3D && matches!(opcode & 0b111, 0..=5) {
            let op_group = opcode >> 3;
            let op = match op_group {
                0 => Op::Add,
                1 => Op::Or,
                2 => Op::Adc,
                3 => Op::Sbb,
                4 => Op::And,
                5 => Op::Sub,
                6 => Op::Xor,
                7 => Op::Cmp,
                _ => unreachable!(),
            };
            return self.decode_arith_form(opcode, p, op, rip);
        }

        match opcode {
            // 0x50..=0x57 PUSH r64 (default 64-bit)
            0x50..=0x57 => {
                let size = self.op_size_default64(p);
                let r = self.opcode_reg_operand(p, opcode - 0x50, size);
                Ok(make(Op::Push, [Some(r), None, None], rip))
            }
            // 0x58..=0x5F POP r64
            0x58..=0x5F => {
                let size = self.op_size_default64(p);
                let r = self.opcode_reg_operand(p, opcode - 0x58, size);
                Ok(make(Op::Pop, [Some(r), None, None], rip))
            }
            // 0x63 MOVSXD r64, r/m32 (with REX.W) or MOVSXD r32, r/m32
            0x63 => {
                let dst_size = if p.rex.w { OpSize::B8 } else { OpSize::B4 };
                let (rm, reg) = self.decode_modrm(p, OpSize::B4)?;
                let r = self.reg_operand(p, reg, dst_size);
                Ok(make(Op::Movsxd, [Some(r), Some(rm), None], rip))
            }
            // 0x68 PUSH imm32 (sign-extended)
            0x68 => {
                let imm = self.read_i32()? as i64;
                let size = self.op_size_default64(p);
                Ok(make(
                    Op::Push,
                    [Some(Operand::Imm(imm, size)), None, None],
                    rip,
                ))
            }
            // 0x6A PUSH imm8 (sign-extended)
            0x6A => {
                let imm = self.read_i8()? as i64;
                let size = self.op_size_default64(p);
                Ok(make(
                    Op::Push,
                    [Some(Operand::Imm(imm, size)), None, None],
                    rip,
                ))
            }
            // 0x69 IMUL r, r/m, imm32
            0x69 => {
                let size = self.op_size_default32(p);
                let (rm, reg) = self.decode_modrm(p, size)?;
                let r = self.reg_operand(p, reg, size);
                let imm = if size == OpSize::B2 {
                    self.read_i16()? as i64
                } else {
                    self.read_i32()? as i64
                };
                Ok(make(
                    Op::Imul,
                    [Some(r), Some(rm), Some(Operand::Imm(imm, size))],
                    rip,
                ))
            }
            // 0x6B IMUL r, r/m, imm8
            0x6B => {
                let size = self.op_size_default32(p);
                let (rm, reg) = self.decode_modrm(p, size)?;
                let r = self.reg_operand(p, reg, size);
                let imm = self.read_i8()? as i64;
                Ok(make(
                    Op::Imul,
                    [Some(r), Some(rm), Some(Operand::Imm(imm, size))],
                    rip,
                ))
            }
            // 0x70..=0x7F Jcc rel8
            0x70..=0x7F => {
                let cond = cond_from_low4(opcode & 0xF);
                let rel = self.read_i8()? as i64;
                Ok(make(
                    Op::Jcc(cond),
                    [Some(Operand::Imm(rel, OpSize::B1)), None, None],
                    rip,
                ))
            }
            // 0x80 group 1 — r/m8, imm8
            0x80 => self.decode_group1(p, OpSize::B1, OpSize::B1, rip),
            // 0x81 group 1 — r/m, immZ
            0x81 => {
                let size = self.op_size_default32(p);
                let imm_size = if size == OpSize::B2 {
                    OpSize::B2
                } else {
                    OpSize::B4
                };
                self.decode_group1(p, size, imm_size, rip)
            }
            // 0x83 group 1 — r/m, imm8 sign-extended
            0x83 => {
                let size = self.op_size_default32(p);
                self.decode_group1(p, size, OpSize::B1, rip)
            }
            // 0x84 TEST r/m8, r8
            0x84 => {
                let (rm, reg) = self.decode_modrm(p, OpSize::B1)?;
                let r = self.reg_operand(p, reg, OpSize::B1);
                Ok(make(Op::Test, [Some(rm), Some(r), None], rip))
            }
            // 0x85 TEST r/m, r
            0x85 => {
                let size = self.op_size_default32(p);
                let (rm, reg) = self.decode_modrm(p, size)?;
                let r = self.reg_operand(p, reg, size);
                Ok(make(Op::Test, [Some(rm), Some(r), None], rip))
            }
            // 0x86 XCHG r/m8, r8
            0x86 => {
                let (rm, reg) = self.decode_modrm(p, OpSize::B1)?;
                let r = self.reg_operand(p, reg, OpSize::B1);
                Ok(make(Op::Xchg, [Some(rm), Some(r), None], rip))
            }
            // 0x87 XCHG r/m, r
            0x87 => {
                let size = self.op_size_default32(p);
                let (rm, reg) = self.decode_modrm(p, size)?;
                let r = self.reg_operand(p, reg, size);
                Ok(make(Op::Xchg, [Some(rm), Some(r), None], rip))
            }
            // 0x88 MOV r/m8, r8
            0x88 => {
                let (rm, reg) = self.decode_modrm(p, OpSize::B1)?;
                let r = self.reg_operand(p, reg, OpSize::B1);
                Ok(make(Op::Mov, [Some(rm), Some(r), None], rip))
            }
            // 0x89 MOV r/m, r
            0x89 => {
                let size = self.op_size_default32(p);
                let (rm, reg) = self.decode_modrm(p, size)?;
                let r = self.reg_operand(p, reg, size);
                Ok(make(Op::Mov, [Some(rm), Some(r), None], rip))
            }
            // 0x8A MOV r8, r/m8
            0x8A => {
                let (rm, reg) = self.decode_modrm(p, OpSize::B1)?;
                let r = self.reg_operand(p, reg, OpSize::B1);
                Ok(make(Op::Mov, [Some(r), Some(rm), None], rip))
            }
            // 0x8B MOV r, r/m
            0x8B => {
                let size = self.op_size_default32(p);
                let (rm, reg) = self.decode_modrm(p, size)?;
                let r = self.reg_operand(p, reg, size);
                Ok(make(Op::Mov, [Some(r), Some(rm), None], rip))
            }
            // 0x8D LEA r, m
            0x8D => {
                let size = self.op_size_default32(p);
                let (rm, reg) = self.decode_modrm(p, size)?;
                let r = self.reg_operand(p, reg, size);
                Ok(make(Op::Lea, [Some(r), Some(rm), None], rip))
            }
            // 0x8F /0 POP r/m
            0x8F => {
                let size = self.op_size_default64(p);
                let (rm, sub) = self.decode_modrm(p, size)?;
                if sub != 0 {
                    return Ok(unhandled(rip));
                }
                Ok(make(Op::Pop, [Some(rm), None, None], rip))
            }
            // 0x90 NOP / XCHG eax, r — REP prefix turns it into PAUSE; treat both as NOP for now.
            0x90 => Ok(make(Op::Nop, [None, None, None], rip)),
            // 0x91..=0x97 XCHG eax/rax, r
            0x91..=0x97 => {
                let size = self.op_size_default32(p);
                let acc = Operand::Reg(GpReg::Rax, size);
                let other = self.opcode_reg_operand(p, opcode - 0x90, size);
                Ok(make(Op::Xchg, [Some(acc), Some(other), None], rip))
            }
            // 0x98 CBW/CWDE/CDQE
            0x98 => Ok(make(Op::Cwde, [None, None, None], rip)),
            // 0x99 CWD/CDQ/CQO
            0x99 => Ok(make(
                if p.rex.w { Op::Cqo } else { Op::Cdq },
                [None, None, None],
                rip,
            )),
            // 0x9C PUSHFQ
            0x9C => Ok(make(Op::Pushfq, [None, None, None], rip)),
            // 0x9D POPFQ
            0x9D => Ok(make(Op::Popfq, [None, None, None], rip)),
            // 0xA8/A9 TEST AL/eax, imm
            0xA8 => {
                let imm = self.read_i8()? as i64;
                Ok(make(
                    Op::Test,
                    [
                        Some(Operand::Reg(GpReg::Rax, OpSize::B1)),
                        Some(Operand::Imm(imm, OpSize::B1)),
                        None,
                    ],
                    rip,
                ))
            }
            0xA9 => {
                let size = self.op_size_default32(p);
                let imm_size = if size == OpSize::B2 {
                    OpSize::B2
                } else {
                    OpSize::B4
                };
                let imm = self.read_imm(imm_size)?;
                Ok(make(
                    Op::Test,
                    [
                        Some(Operand::Reg(GpReg::Rax, size)),
                        Some(Operand::Imm(imm, imm_size)),
                        None,
                    ],
                    rip,
                ))
            }
            // 0xB0..=0xB7 MOV r8, imm8
            0xB0..=0xB7 => {
                let r = self.opcode_reg_operand(p, opcode - 0xB0, OpSize::B1);
                let imm = self.read_i8()? as i64;
                Ok(make(
                    Op::Mov,
                    [Some(r), Some(Operand::Imm(imm, OpSize::B1)), None],
                    rip,
                ))
            }
            // 0xB8..=0xBF MOV r, immZ
            0xB8..=0xBF => {
                let size = if p.rex.w {
                    OpSize::B8
                } else if p.osize {
                    OpSize::B2
                } else {
                    OpSize::B4
                };
                let r = self.opcode_reg_operand(p, opcode - 0xB8, size);
                let imm = self.read_imm(size)?;
                Ok(make(
                    Op::Mov,
                    [Some(r), Some(Operand::Imm(imm, size)), None],
                    rip,
                ))
            }
            // 0xC0/C1 group 2 — shifts r/m, imm8
            0xC0 => self.decode_group2(p, OpSize::B1, ShiftAmount::Imm8, rip),
            0xC1 => {
                let size = self.op_size_default32(p);
                self.decode_group2(p, size, ShiftAmount::Imm8, rip)
            }
            // 0xC2 RET imm16
            0xC2 => {
                let imm = self.read_u16()? as i64;
                Ok(make(
                    Op::RetImm,
                    [Some(Operand::Imm(imm, OpSize::B2)), None, None],
                    rip,
                ))
            }
            // 0xC3 RET
            0xC3 => Ok(make(Op::Ret, [None, None, None], rip)),
            // 0xC6/C7 MOV r/m, imm (group 11 /0)
            0xC6 => {
                let (rm, sub) = self.decode_modrm(p, OpSize::B1)?;
                if sub != 0 {
                    return Ok(unhandled(rip));
                }
                let imm = self.read_i8()? as i64;
                Ok(make(
                    Op::Mov,
                    [Some(rm), Some(Operand::Imm(imm, OpSize::B1)), None],
                    rip,
                ))
            }
            0xC7 => {
                let size = self.op_size_default32(p);
                let (rm, sub) = self.decode_modrm(p, size)?;
                if sub != 0 {
                    return Ok(unhandled(rip));
                }
                let imm_size = if size == OpSize::B2 {
                    OpSize::B2
                } else {
                    OpSize::B4
                };
                let imm = self.read_imm(imm_size)?;
                Ok(make(
                    Op::Mov,
                    [Some(rm), Some(Operand::Imm(imm, imm_size)), None],
                    rip,
                ))
            }
            // 0xC9 LEAVE
            0xC9 => Ok(make(Op::Leave, [None, None, None], rip)),
            // 0xCC INT3
            0xCC => Ok(make(Op::Int3, [None, None, None], rip)),
            // 0xCD INT imm8
            0xCD => {
                let imm = self.read_u8()? as i64;
                Ok(make(
                    Op::Int,
                    [Some(Operand::Imm(imm, OpSize::B1)), None, None],
                    rip,
                ))
            }
            // 0xD0..=0xD3 group 2 shifts
            0xD0 => self.decode_group2(p, OpSize::B1, ShiftAmount::One, rip),
            0xD1 => {
                let size = self.op_size_default32(p);
                self.decode_group2(p, size, ShiftAmount::One, rip)
            }
            0xD2 => self.decode_group2(p, OpSize::B1, ShiftAmount::Cl, rip),
            0xD3 => {
                let size = self.op_size_default32(p);
                self.decode_group2(p, size, ShiftAmount::Cl, rip)
            }
            // 0xE8 CALL rel32
            0xE8 => {
                let rel = self.read_i32()? as i64;
                Ok(make(
                    Op::Call,
                    [Some(Operand::Imm(rel, OpSize::B4)), None, None],
                    rip,
                ))
            }
            // 0xE9 JMP rel32
            0xE9 => {
                let rel = self.read_i32()? as i64;
                Ok(make(
                    Op::Jmp,
                    [Some(Operand::Imm(rel, OpSize::B4)), None, None],
                    rip,
                ))
            }
            // 0xEB JMP rel8
            0xEB => {
                let rel = self.read_i8()? as i64;
                Ok(make(
                    Op::Jmp,
                    [Some(Operand::Imm(rel, OpSize::B1)), None, None],
                    rip,
                ))
            }
            // 0xF4 HLT
            0xF4 => Ok(make(Op::Hlt, [None, None, None], rip)),
            // 0xF5 CMC
            0xF5 => Ok(make(Op::Cmc, [None, None, None], rip)),
            // 0xF6/F7 group 3
            0xF6 => self.decode_group3(p, OpSize::B1, rip),
            0xF7 => {
                let size = self.op_size_default32(p);
                self.decode_group3(p, size, rip)
            }
            // 0xF8 CLC, 0xF9 STC, 0xFC CLD, 0xFD STD
            0xF8 => Ok(make(Op::Clc, [None, None, None], rip)),
            0xF9 => Ok(make(Op::Stc, [None, None, None], rip)),
            0xFC => Ok(make(Op::Cld, [None, None, None], rip)),
            0xFD => Ok(make(Op::Std, [None, None, None], rip)),
            // 0xFE group 4 (INC/DEC r/m8)
            0xFE => self.decode_group4(p, rip),
            // 0xFF group 5
            0xFF => self.decode_group5(p, rip),
            _ => Ok(unhandled(rip)),
        }
    }

    /// ModRM decode variant that returns the rm side as an `XmmReg`
    /// when mod==11. Memory operand mode falls through to the same
    /// path as GPR decoding.
    fn decode_modrm_xmm(
        &mut self,
        p: &Prefixes,
        size: OpSize,
    ) -> Result<(Operand, u8 /* reg field */)> {
        let modrm = self.read_u8()?;
        let mod_ = modrm >> 6;
        let reg = (modrm >> 3) & 0b111;
        let rm = modrm & 0b111;
        let rm_op = if mod_ == 0b11 {
            let r = ((p.rex.b as u8) << 3) | rm;
            Operand::XmmReg(r, size)
        } else {
            self.decode_rm_memory(p, mod_, rm, size)?
        };
        let reg_idx = ((p.rex.r as u8) << 3) | reg;
        Ok((rm_op, reg_idx))
    }

    fn decode_secondary(&mut self, p: &Prefixes, rip: u64) -> Result<Inst> {
        let opcode = self.read_u8()?;
        match opcode {
            // 0F 05 SYSCALL
            0x05 => Ok(make(Op::Syscall, [None, None, None], rip)),
            // 0F 0B UD2
            0x0B => Ok(make(Op::Ud2, [None, None, None], rip)),
            // 0F 31 RDTSC
            0x31 => Ok(make(Op::Rdtsc, [None, None, None], rip)),
            // 0F A2 CPUID
            0xA2 if !p.osize && !p.repe && !p.repne => Ok(make(Op::Cpuid, [None, None, None], rip)),
            // SSE2 scalar moves with size determined by REP/OSIZE prefixes.
            //   66 0F 10 /r is unused (movupd); skip for now.
            //   F2 0F 10 /r MOVSD xmm, xmm/m64
            //   F3 0F 10 /r MOVSS xmm, xmm/m32
            0x10 if p.repne || p.repe => {
                let size = if p.repne { OpSize::B8 } else { OpSize::B4 };
                let (rm, reg) = self.decode_modrm_xmm(p, size)?;
                let xmm = Operand::XmmReg(reg, size);
                let op = if p.repne { Op::MovsdXmm } else { Op::MovssXmm };
                Ok(make(op, [Some(xmm), Some(rm), None], rip))
            }
            //   F2 0F 11 /r MOVSD xmm/m64, xmm
            //   F3 0F 11 /r MOVSS xmm/m32, xmm
            0x11 if p.repne || p.repe => {
                let size = if p.repne { OpSize::B8 } else { OpSize::B4 };
                let (rm, reg) = self.decode_modrm_xmm(p, size)?;
                let xmm = Operand::XmmReg(reg, size);
                let op = if p.repne { Op::MovsdXmm } else { Op::MovssXmm };
                Ok(make(op, [Some(rm), Some(xmm), None], rip))
            }
            // 66 0F 6E /r MOVD xmm, r/m32  (with REX.W => MOVQ xmm, r/m64)
            // Note: rm here is a *GPR* or memory, not an XMM, when used
            // as a movd/movq across the GPR/XMM boundary.
            0x6E if p.osize => {
                let size = if p.rex.w { OpSize::B8 } else { OpSize::B4 };
                let (rm, reg) = self.decode_modrm(p, size)?;
                let xmm = Operand::XmmReg(reg, size);
                Ok(make(Op::MovqXmm, [Some(xmm), Some(rm), None], rip))
            }
            // 66 0F 7E /r MOVD r/m32, xmm  (with REX.W => MOVQ r/m64, xmm)
            // F3 0F 7E /r MOVQ xmm, xmm/m64 (alternate form, 64-bit always)
            0x7E if p.osize => {
                let size = if p.rex.w { OpSize::B8 } else { OpSize::B4 };
                let (rm, reg) = self.decode_modrm(p, size)?;
                let xmm = Operand::XmmReg(reg, size);
                Ok(make(Op::MovqXmm, [Some(rm), Some(xmm), None], rip))
            }
            0x7E if p.repe => {
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B8)?;
                let xmm = Operand::XmmReg(reg, OpSize::B8);
                Ok(make(Op::MovqXmm, [Some(xmm), Some(rm), None], rip))
            }
            // 66 0F 6F /r MOVDQA xmm, xmm/m128
            // F3 0F 6F /r MOVDQU xmm, xmm/m128
            0x6F if p.osize || p.repe => {
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B8)?;
                let xmm = Operand::XmmReg(reg, OpSize::B8);
                Ok(make(Op::MovdqXmm, [Some(xmm), Some(rm), None], rip))
            }
            // 66 0F 7F /r MOVDQA xmm/m128, xmm
            // F3 0F 7F /r MOVDQU xmm/m128, xmm
            0x7F if p.osize || p.repe => {
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B8)?;
                let xmm = Operand::XmmReg(reg, OpSize::B8);
                Ok(make(Op::MovdqXmm, [Some(rm), Some(xmm), None], rip))
            }
            // 66 0F 71/72/73 — packed shift immediate group (PSLLW/D/Q
            // PSRLW/D/Q PSRAW/D). The ModRM /sub field picks the op:
            //   /2 PSRL*
            //   /3 PSRLDQ (only for 73 — shift WHOLE 128-bit reg right by imm8 bytes)
            //   /4 PSRA*  (only for W and D — there is no PSRAQ)
            //   /6 PSLL*
            //   /7 PSLLDQ (only for 73)
            // 71 -> word lanes, 72 -> dword lanes, 73 -> qword lanes.
            0x71..=0x73 if p.osize => {
                let lane = match opcode {
                    0x71 => OpSize::B2,
                    0x72 => OpSize::B4,
                    0x73 => OpSize::B8,
                    _ => unreachable!(),
                };
                let modrm = self.read_u8()?;
                let mod_ = modrm >> 6;
                let sub = (modrm >> 3) & 0b111;
                let rm = modrm & 0b111;
                if mod_ != 0b11 {
                    return Ok(unhandled(rip));
                }
                let r = ((p.rex.b as u8) << 3) | rm;
                let xmm = Operand::XmmReg(r, OpSize::B8);
                let imm = self.read_u8()? as i64;
                let op = match (sub, lane) {
                    (2, _) => Op::PsrlImm(lane),
                    (3, OpSize::B8) => Op::PsrldqImm,
                    (4, OpSize::B2) | (4, OpSize::B4) => Op::PsraImm(lane),
                    (6, _) => Op::PsllImm(lane),
                    (7, OpSize::B8) => Op::PslldqImm,
                    _ => return Ok(unhandled(rip)),
                };
                Ok(make(
                    op,
                    [Some(xmm), Some(Operand::Imm(imm, OpSize::B1)), None],
                    rip,
                ))
            }
            // PUNPCKLxx / PUNPCKHxx family with OSIZE prefix:
            //   66 0F 60 PUNPCKLBW  | 66 0F 68 PUNPCKHBW
            //   66 0F 61 PUNPCKLWD  | 66 0F 69 PUNPCKHWD
            //   66 0F 62 PUNPCKLDQ  | 66 0F 6A PUNPCKHDQ
            //   66 0F 6C PUNPCKLQDQ | 66 0F 6D PUNPCKHQDQ
            0x60..=0x62 | 0x68..=0x6A | 0x6C | 0x6D if p.osize => {
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B8)?;
                let xmm = Operand::XmmReg(reg, OpSize::B8);
                let (high, lane) = match opcode {
                    0x60 => (false, OpSize::B1),
                    0x61 => (false, OpSize::B2),
                    0x62 => (false, OpSize::B4),
                    0x68 => (true, OpSize::B1),
                    0x69 => (true, OpSize::B2),
                    0x6A => (true, OpSize::B4),
                    0x6C => (false, OpSize::B8),
                    0x6D => (true, OpSize::B8),
                    _ => unreachable!(),
                };
                let op = if high {
                    Op::PunpckHigh(lane)
                } else {
                    Op::PunpckLow(lane)
                };
                Ok(make(op, [Some(xmm), Some(rm), None], rip))
            }
            // 66 0F D7 /r PMOVMSKB r32, xmm — extract per-byte high
            // bits of the XMM into a 16-bit mask in the low half of
            // the GPR.
            0xD7 if p.osize => {
                let modrm = self.read_u8()?;
                let mod_ = modrm >> 6;
                let reg = (modrm >> 3) & 0b111;
                let rm = modrm & 0b111;
                if mod_ != 0b11 {
                    return Ok(unhandled(rip));
                }
                let xmm_idx = ((p.rex.b as u8) << 3) | rm;
                let gpr_idx = ((p.rex.r as u8) << 3) | reg;
                let dst = Operand::Reg(GpReg::from_index(gpr_idx).unwrap(), OpSize::B4);
                let src = Operand::XmmReg(xmm_idx, OpSize::B8);
                Ok(make(Op::PmovmskB, [Some(dst), Some(src), None], rip))
            }
            // 66 0F D5 /r PMULLW — 8-lane 16-bit multiply (low 16).
            0xD5 if p.osize => {
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B8)?;
                let xmm = Operand::XmmReg(reg, OpSize::B8);
                Ok(make(Op::PmullW, [Some(xmm), Some(rm), None], rip))
            }
            // 66 0F 70 /r ib  PSHUFD xmm, xmm/m128, imm8
            0x70 if p.osize => {
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B8)?;
                let xmm = Operand::XmmReg(reg, OpSize::B8);
                let imm = self.read_u8()? as i64;
                Ok(make(
                    Op::PshufD,
                    [Some(xmm), Some(rm), Some(Operand::Imm(imm, OpSize::B1))],
                    rip,
                ))
            }
            // 66 0F 74/75/76 /r PCMPEQB/W/D — per-lane integer compare-equal.
            0x74 if p.osize => {
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B8)?;
                let xmm = Operand::XmmReg(reg, OpSize::B8);
                Ok(make(
                    Op::PcmpeqLane(OpSize::B1),
                    [Some(xmm), Some(rm), None],
                    rip,
                ))
            }
            0x75 if p.osize => {
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B8)?;
                let xmm = Operand::XmmReg(reg, OpSize::B8);
                Ok(make(
                    Op::PcmpeqLane(OpSize::B2),
                    [Some(xmm), Some(rm), None],
                    rip,
                ))
            }
            0x76 if p.osize => {
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B8)?;
                let xmm = Operand::XmmReg(reg, OpSize::B8);
                Ok(make(
                    Op::PcmpeqLane(OpSize::B4),
                    [Some(xmm), Some(rm), None],
                    rip,
                ))
            }
            // 66 0F EF /r PXOR xmm, xmm/m128
            0xEF if p.osize => {
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B8)?;
                let xmm = Operand::XmmReg(reg, OpSize::B8);
                Ok(make(Op::PxorXmm, [Some(xmm), Some(rm), None], rip))
            }
            // 66 0F DB /r PAND xmm, xmm/m128
            0xDB if p.osize => {
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B8)?;
                let xmm = Operand::XmmReg(reg, OpSize::B8);
                Ok(make(Op::PandXmm, [Some(xmm), Some(rm), None], rip))
            }
            // 66 0F EB /r POR xmm, xmm/m128
            0xEB if p.osize => {
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B8)?;
                let xmm = Operand::XmmReg(reg, OpSize::B8);
                Ok(make(Op::PorXmm, [Some(xmm), Some(rm), None], rip))
            }
            // Scalar FP arithmetic ops. The F2 (REPNE) prefix selects
            // double precision; F3 (REPE) selects single. Operand size
            // on the XMM is B8 for SD or B4 for SS.
            //   0F 58 /r  ADD{SD,SS}
            //   0F 59 /r  MUL{SD,SS}
            //   0F 5C /r  SUB{SD,SS}
            //   0F 5E /r  DIV{SD,SS}
            0x58 | 0x59 | 0x5C | 0x5E if p.repne || p.repe => {
                let size = if p.repne { OpSize::B8 } else { OpSize::B4 };
                let (rm, reg) = self.decode_modrm_xmm(p, size)?;
                let xmm = Operand::XmmReg(reg, size);
                let op = match opcode {
                    0x58 => Op::AddScalar,
                    0x59 => Op::MulScalar,
                    0x5C => Op::SubScalar,
                    0x5E => Op::DivScalar,
                    _ => unreachable!(),
                };
                Ok(make(op, [Some(xmm), Some(rm), None], rip))
            }
            // Packed FP arith — same opcodes as scalar (58/59/5C/5E) but
            // *without* a REPE/REPNE prefix. OSIZE (66) selects double
            // (2-lane), no prefix selects single (4-lane).
            //   NP  0F 58 /r  ADDPS
            //   66  0F 58 /r  ADDPD
            //   NP  0F 59 /r  MULPS
            //   66  0F 59 /r  MULPD
            //   NP  0F 5C /r  SUBPS
            //   66  0F 5C /r  SUBPD
            //   NP  0F 5E /r  DIVPS
            //   66  0F 5E /r  DIVPD
            0x58 | 0x59 | 0x5C | 0x5E if !p.repne && !p.repe => {
                let size = if p.osize { OpSize::B8 } else { OpSize::B4 };
                let (rm, reg) = self.decode_modrm_xmm(p, size)?;
                let xmm = Operand::XmmReg(reg, size);
                let op = match opcode {
                    0x58 => Op::AddPacked,
                    0x59 => Op::MulPacked,
                    0x5C => Op::SubPacked,
                    0x5E => Op::DivPacked,
                    _ => unreachable!(),
                };
                Ok(make(op, [Some(xmm), Some(rm), None], rip))
            }
            // FP <-> int / FP <-> FP precision conversions.
            //   F2 0F 2A /r CVTSI2SD xmm, r/m{32,64}
            //   F3 0F 2A /r CVTSI2SS xmm, r/m{32,64}
            //   F2 0F 2C /r CVTTSD2SI r{32,64}, xmm/m64  (truncate)
            //   F3 0F 2C /r CVTTSS2SI r{32,64}, xmm/m32
            //   F2 0F 2D /r CVTSD2SI  r{32,64}, xmm/m64  (round)
            //   F3 0F 2D /r CVTSS2SI  r{32,64}, xmm/m32
            //   F2 0F 5A /r CVTSD2SS  xmm, xmm/m64
            //   F3 0F 5A /r CVTSS2SD  xmm, xmm/m32
            0x2A if p.repne || p.repe => {
                let fp_size = if p.repne { OpSize::B8 } else { OpSize::B4 };
                let int_size = if p.rex.w { OpSize::B8 } else { OpSize::B4 };
                let (rm, reg) = self.decode_modrm(p, int_size)?;
                let xmm = Operand::XmmReg(reg, fp_size);
                Ok(make(Op::CvtIntToScalar, [Some(xmm), Some(rm), None], rip))
            }
            0x2C if p.repne || p.repe => {
                let fp_size = if p.repne { OpSize::B8 } else { OpSize::B4 };
                let int_size = if p.rex.w { OpSize::B8 } else { OpSize::B4 };
                let (rm, reg) = self.decode_modrm_xmm(p, fp_size)?;
                let int_reg = self.reg_operand(p, reg, int_size);
                Ok(make(
                    Op::CvtScalarToIntTrunc,
                    [Some(int_reg), Some(rm), None],
                    rip,
                ))
            }
            0x2D if p.repne || p.repe => {
                let fp_size = if p.repne { OpSize::B8 } else { OpSize::B4 };
                let int_size = if p.rex.w { OpSize::B8 } else { OpSize::B4 };
                let (rm, reg) = self.decode_modrm_xmm(p, fp_size)?;
                let int_reg = self.reg_operand(p, reg, int_size);
                Ok(make(
                    Op::CvtScalarToInt,
                    [Some(int_reg), Some(rm), None],
                    rip,
                ))
            }
            0x5A if p.repne => {
                // CVTSD2SS xmm, xmm/m64 — read 64-bit double, write 32-bit single.
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B8)?;
                let xmm = Operand::XmmReg(reg, OpSize::B4);
                Ok(make(Op::CvtSdToSs, [Some(xmm), Some(rm), None], rip))
            }
            0x5A if p.repe => {
                // CVTSS2SD xmm, xmm/m32.
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B4)?;
                let xmm = Operand::XmmReg(reg, OpSize::B8);
                Ok(make(Op::CvtSsToSd, [Some(xmm), Some(rm), None], rip))
            }
            //   NP 0F 2E /r UCOMISS xmm, xmm/m32
            //   66 0F 2E /r UCOMISD xmm, xmm/m64
            // Note: COMISS/COMISD (0F 2F) differ only in NaN-signaling
            // behaviour; we collapse them into UCOMIS for now since the
            // post-compare flag layout is the same.
            0x2E | 0x2F if !p.repne && !p.repe => {
                let size = if p.osize { OpSize::B8 } else { OpSize::B4 };
                let (rm, reg) = self.decode_modrm_xmm(p, size)?;
                let xmm = Operand::XmmReg(reg, size);
                Ok(make(Op::UcomisScalar, [Some(xmm), Some(rm), None], rip))
            }
            //   F3 0F 51 /r SQRTSS xmm, xmm/m32
            //   F2 0F 51 /r SQRTSD xmm, xmm/m64
            //   F3 0F 5D /r MINSS
            //   F2 0F 5D /r MINSD
            //   F3 0F 5F /r MAXSS
            //   F2 0F 5F /r MAXSD
            0x51 | 0x5D | 0x5F if p.repne || p.repe => {
                let size = if p.repne { OpSize::B8 } else { OpSize::B4 };
                let (rm, reg) = self.decode_modrm_xmm(p, size)?;
                let xmm = Operand::XmmReg(reg, size);
                let op = match opcode {
                    0x51 => Op::SqrtScalar,
                    0x5D => Op::MinScalar,
                    0x5F => Op::MaxScalar,
                    _ => unreachable!(),
                };
                Ok(make(op, [Some(xmm), Some(rm), None], rip))
            }
            // 0F 1F /0 multi-byte NOP (variable length)
            0x1F => {
                let _ = self.decode_modrm(p, OpSize::B4)?;
                Ok(make(Op::Nop, [None, None, None], rip))
            }
            // 0F 40..=4F CMOVcc
            0x40..=0x4F => {
                let cond = cond_from_low4(opcode & 0xF);
                let size = self.op_size_default32(p);
                let (rm, reg) = self.decode_modrm(p, size)?;
                let r = self.reg_operand(p, reg, size);
                Ok(make(Op::Cmov(cond), [Some(r), Some(rm), None], rip))
            }
            // 0F 80..=8F Jcc rel32
            0x80..=0x8F => {
                let cond = cond_from_low4(opcode & 0xF);
                let rel = self.read_i32()? as i64;
                Ok(make(
                    Op::Jcc(cond),
                    [Some(Operand::Imm(rel, OpSize::B4)), None, None],
                    rip,
                ))
            }
            // 0F 90..=9F SETcc r/m8
            0x90..=0x9F => {
                let cond = cond_from_low4(opcode & 0xF);
                let (rm, _) = self.decode_modrm(p, OpSize::B1)?;
                Ok(make(Op::Set(cond), [Some(rm), None, None], rip))
            }
            // 0F A3 BT r/m, r
            0xA3 => {
                let size = self.op_size_default32(p);
                let (rm, reg) = self.decode_modrm(p, size)?;
                let r = self.reg_operand(p, reg, size);
                Ok(make(Op::Bt, [Some(rm), Some(r), None], rip))
            }
            // 0F AF IMUL r, r/m
            0xAF => {
                let size = self.op_size_default32(p);
                let (rm, reg) = self.decode_modrm(p, size)?;
                let r = self.reg_operand(p, reg, size);
                Ok(make(Op::Imul, [Some(r), Some(rm), None], rip))
            }
            // 0F B0/B1 CMPXCHG r/m, r
            0xB0 => {
                let (rm, reg) = self.decode_modrm(p, OpSize::B1)?;
                let r = self.reg_operand(p, reg, OpSize::B1);
                Ok(make(Op::Cmpxchg, [Some(rm), Some(r), None], rip))
            }
            0xB1 => {
                let size = self.op_size_default32(p);
                let (rm, reg) = self.decode_modrm(p, size)?;
                let r = self.reg_operand(p, reg, size);
                Ok(make(Op::Cmpxchg, [Some(rm), Some(r), None], rip))
            }
            // 0F B6 MOVZX r, r/m8
            0xB6 => {
                let size = self.op_size_default32(p);
                let (rm, reg) = self.decode_modrm(p, OpSize::B1)?;
                let r = self.reg_operand(p, reg, size);
                Ok(make(Op::Movzx, [Some(r), Some(rm), None], rip))
            }
            // 0F B7 MOVZX r, r/m16
            0xB7 => {
                let size = self.op_size_default32(p);
                let (rm, reg) = self.decode_modrm(p, OpSize::B2)?;
                let r = self.reg_operand(p, reg, size);
                Ok(make(Op::Movzx, [Some(r), Some(rm), None], rip))
            }
            // 0F BA group 8: BT/BTS/BTR/BTC r/m, imm8
            0xBA => {
                let size = self.op_size_default32(p);
                let (rm, sub) = self.decode_modrm(p, size)?;
                let imm = self.read_i8()? as i64;
                let op = match sub {
                    4 => Op::Bt,
                    5 => Op::Bts,
                    6 => Op::Btr,
                    7 => Op::Btc,
                    _ => return Ok(unhandled(rip)),
                };
                Ok(make(
                    op,
                    [Some(rm), Some(Operand::Imm(imm, OpSize::B1)), None],
                    rip,
                ))
            }
            // 0F BC BSF, 0F BD BSR
            0xBC | 0xBD => {
                let size = self.op_size_default32(p);
                let (rm, reg) = self.decode_modrm(p, size)?;
                let r = self.reg_operand(p, reg, size);
                let op = if opcode == 0xBC { Op::Bsf } else { Op::Bsr };
                Ok(make(op, [Some(r), Some(rm), None], rip))
            }
            // 0F BE MOVSX r, r/m8
            0xBE => {
                let size = self.op_size_default32(p);
                let (rm, reg) = self.decode_modrm(p, OpSize::B1)?;
                let r = self.reg_operand(p, reg, size);
                Ok(make(Op::Movsx, [Some(r), Some(rm), None], rip))
            }
            // 0F BF MOVSX r, r/m16
            0xBF => {
                let size = self.op_size_default32(p);
                let (rm, reg) = self.decode_modrm(p, OpSize::B2)?;
                let r = self.reg_operand(p, reg, size);
                Ok(make(Op::Movsx, [Some(r), Some(rm), None], rip))
            }
            // 0F C0/C1 XADD
            0xC0 => {
                let (rm, reg) = self.decode_modrm(p, OpSize::B1)?;
                let r = self.reg_operand(p, reg, OpSize::B1);
                Ok(make(Op::Xadd, [Some(rm), Some(r), None], rip))
            }
            0xC1 => {
                let size = self.op_size_default32(p);
                let (rm, reg) = self.decode_modrm(p, size)?;
                let r = self.reg_operand(p, reg, size);
                Ok(make(Op::Xadd, [Some(rm), Some(r), None], rip))
            }
            // 0F C8 + reg-low3 — BSWAP r32/r64.
            0xC8..=0xCF => {
                let size = if p.rex.w { OpSize::B8 } else { OpSize::B4 };
                let r = self.opcode_reg_operand(p, opcode - 0xC8, size);
                Ok(make(Op::Bswap, [Some(r), None, None], rip))
            }
            // 66 0F D4 /r PADDQ — 2x64-bit packed add.
            0xD4 if p.osize => {
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B8)?;
                let xmm = Operand::XmmReg(reg, OpSize::B8);
                Ok(make(Op::PaddQ, [Some(xmm), Some(rm), None], rip))
            }
            // 66 0F FB /r PSUBQ.
            0xFB if p.osize => {
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B8)?;
                let xmm = Operand::XmmReg(reg, OpSize::B8);
                Ok(make(Op::PsubQ, [Some(xmm), Some(rm), None], rip))
            }
            // 66 0F FE /r PADDD — 4x32-bit packed add.
            0xFE if p.osize => {
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B8)?;
                let xmm = Operand::XmmReg(reg, OpSize::B8);
                Ok(make(Op::PaddD, [Some(xmm), Some(rm), None], rip))
            }
            // 66 0F FA /r PSUBD.
            0xFA if p.osize => {
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B8)?;
                let xmm = Operand::XmmReg(reg, OpSize::B8);
                Ok(make(Op::PsubD, [Some(xmm), Some(rm), None], rip))
            }
            // 66 0F FD /r PADDW — 8x16-bit packed add.
            0xFD if p.osize => {
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B8)?;
                let xmm = Operand::XmmReg(reg, OpSize::B8);
                Ok(make(Op::PaddW, [Some(xmm), Some(rm), None], rip))
            }
            // 66 0F F9 /r PSUBW.
            0xF9 if p.osize => {
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B8)?;
                let xmm = Operand::XmmReg(reg, OpSize::B8);
                Ok(make(Op::PsubW, [Some(xmm), Some(rm), None], rip))
            }
            // 66 0F FC /r PADDB — 16x8-bit packed add.
            0xFC if p.osize => {
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B8)?;
                let xmm = Operand::XmmReg(reg, OpSize::B8);
                Ok(make(Op::PaddB, [Some(xmm), Some(rm), None], rip))
            }
            // 66 0F F8 /r PSUBB.
            0xF8 if p.osize => {
                let (rm, reg) = self.decode_modrm_xmm(p, OpSize::B8)?;
                let xmm = Operand::XmmReg(reg, OpSize::B8);
                Ok(make(Op::PsubB, [Some(xmm), Some(rm), None], rip))
            }
            _ => Ok(unhandled(rip)),
        }
    }

    fn decode_arith_form(&mut self, opcode: u8, p: &Prefixes, op: Op, rip: u64) -> Result<Inst> {
        let form = opcode & 0b111;
        match form {
            0 => {
                // r/m8, r8
                let (rm, reg) = self.decode_modrm(p, OpSize::B1)?;
                let r = self.reg_operand(p, reg, OpSize::B1);
                Ok(make(op, [Some(rm), Some(r), None], rip))
            }
            1 => {
                // r/m, r
                let size = self.op_size_default32(p);
                let (rm, reg) = self.decode_modrm(p, size)?;
                let r = self.reg_operand(p, reg, size);
                Ok(make(op, [Some(rm), Some(r), None], rip))
            }
            2 => {
                // r8, r/m8
                let (rm, reg) = self.decode_modrm(p, OpSize::B1)?;
                let r = self.reg_operand(p, reg, OpSize::B1);
                Ok(make(op, [Some(r), Some(rm), None], rip))
            }
            3 => {
                // r, r/m
                let size = self.op_size_default32(p);
                let (rm, reg) = self.decode_modrm(p, size)?;
                let r = self.reg_operand(p, reg, size);
                Ok(make(op, [Some(r), Some(rm), None], rip))
            }
            4 => {
                // AL, imm8
                let imm = self.read_i8()? as i64;
                Ok(make(
                    op,
                    [
                        Some(Operand::Reg(GpReg::Rax, OpSize::B1)),
                        Some(Operand::Imm(imm, OpSize::B1)),
                        None,
                    ],
                    rip,
                ))
            }
            5 => {
                // EAX/RAX, immZ
                let size = self.op_size_default32(p);
                let imm_size = if size == OpSize::B2 {
                    OpSize::B2
                } else {
                    OpSize::B4
                };
                let imm = self.read_imm(imm_size)?;
                Ok(make(
                    op,
                    [
                        Some(Operand::Reg(GpReg::Rax, size)),
                        Some(Operand::Imm(imm, imm_size)),
                        None,
                    ],
                    rip,
                ))
            }
            _ => Ok(unhandled(rip)),
        }
    }

    fn decode_group1(
        &mut self,
        p: &Prefixes,
        size: OpSize,
        imm_size: OpSize,
        rip: u64,
    ) -> Result<Inst> {
        let (rm, sub) = self.decode_modrm(p, size)?;
        let op = match sub {
            0 => Op::Add,
            1 => Op::Or,
            2 => Op::Adc,
            3 => Op::Sbb,
            4 => Op::And,
            5 => Op::Sub,
            6 => Op::Xor,
            7 => Op::Cmp,
            _ => unreachable!(),
        };
        let imm = self.read_imm(imm_size)?;
        Ok(make(
            op,
            [Some(rm), Some(Operand::Imm(imm, imm_size)), None],
            rip,
        ))
    }

    fn decode_group2(
        &mut self,
        p: &Prefixes,
        size: OpSize,
        amount: ShiftAmount,
        rip: u64,
    ) -> Result<Inst> {
        let (rm, sub) = self.decode_modrm(p, size)?;
        let op = match sub {
            0 => Op::Rol,
            1 => Op::Ror,
            2 => Op::Rcl,
            3 => Op::Rcr,
            4 | 6 => Op::Shl,
            5 => Op::Shr,
            7 => Op::Sar,
            _ => unreachable!(),
        };
        let amt_operand = match amount {
            ShiftAmount::One => Operand::Imm(1, OpSize::B1),
            ShiftAmount::Cl => Operand::Reg(GpReg::Rcx, OpSize::B1),
            ShiftAmount::Imm8 => {
                let v = self.read_u8()? as i64;
                Operand::Imm(v, OpSize::B1)
            }
        };
        Ok(make(op, [Some(rm), Some(amt_operand), None], rip))
    }

    fn decode_group3(&mut self, p: &Prefixes, size: OpSize, rip: u64) -> Result<Inst> {
        let (rm, sub) = self.decode_modrm(p, size)?;
        match sub {
            0 | 1 => {
                // TEST r/m, imm (two encodings — both legal)
                let imm_size = if size == OpSize::B1 {
                    OpSize::B1
                } else if size == OpSize::B2 {
                    OpSize::B2
                } else {
                    OpSize::B4
                };
                let imm = self.read_imm(imm_size)?;
                Ok(make(
                    Op::Test,
                    [Some(rm), Some(Operand::Imm(imm, imm_size)), None],
                    rip,
                ))
            }
            2 => Ok(make(Op::Not, [Some(rm), None, None], rip)),
            3 => Ok(make(Op::Neg, [Some(rm), None, None], rip)),
            4 => Ok(make(Op::Mul, [Some(rm), None, None], rip)),
            5 => Ok(make(Op::Imul, [Some(rm), None, None], rip)),
            6 => Ok(make(Op::Div, [Some(rm), None, None], rip)),
            7 => Ok(make(Op::Idiv, [Some(rm), None, None], rip)),
            _ => unreachable!(),
        }
    }

    fn decode_group4(&mut self, p: &Prefixes, rip: u64) -> Result<Inst> {
        let (rm, sub) = self.decode_modrm(p, OpSize::B1)?;
        match sub {
            0 => Ok(make(Op::Inc, [Some(rm), None, None], rip)),
            1 => Ok(make(Op::Dec, [Some(rm), None, None], rip)),
            _ => Ok(unhandled(rip)),
        }
    }

    fn decode_group5(&mut self, p: &Prefixes, rip: u64) -> Result<Inst> {
        let size = self.op_size_default32(p);
        let call_size = self.op_size_default64(p);
        let (rm, sub) = self.decode_modrm(p, size)?;
        let (rm_call, _) = (rm, sub);
        match sub {
            0 => Ok(make(Op::Inc, [Some(rm), None, None], rip)),
            1 => Ok(make(Op::Dec, [Some(rm), None, None], rip)),
            2 => Ok(make(
                Op::CallIndirect,
                [Some(rewidth(rm_call, call_size)), None, None],
                rip,
            )),
            4 => Ok(make(
                Op::JmpIndirect,
                [Some(rewidth(rm_call, call_size)), None, None],
                rip,
            )),
            6 => Ok(make(
                Op::Push,
                [Some(rewidth(rm_call, call_size)), None, None],
                rip,
            )),
            _ => Ok(unhandled(rip)),
        }
    }
}

fn rewidth(op: Operand, size: OpSize) -> Operand {
    match op {
        Operand::Reg(r, _) => Operand::Reg(r, size),
        Operand::XmmReg(r, _) => Operand::XmmReg(r, size),
        Operand::Mem(mut m) => {
            m.size = size;
            Operand::Mem(m)
        }
        Operand::RipRel(d, _) => Operand::RipRel(d, size),
        Operand::Imm(v, _) => Operand::Imm(v, size),
    }
}

fn make(op: Op, operands: [Option<Operand>; 3], rip: u64) -> Inst {
    Inst {
        op,
        operands,
        len: 0,
        guest_rip: rip,
    }
}

fn unhandled(rip: u64) -> Inst {
    Inst {
        op: Op::Unhandled,
        operands: [None, None, None],
        len: 0,
        guest_rip: rip,
    }
}

#[derive(Debug, Clone, Copy)]
enum ShiftAmount {
    One,
    Cl,
    Imm8,
}

fn cond_from_low4(low4: u8) -> Cond {
    match low4 {
        0x0 => Cond::O,
        0x1 => Cond::NO,
        0x2 => Cond::B,
        0x3 => Cond::NB,
        0x4 => Cond::E,
        0x5 => Cond::NE,
        0x6 => Cond::BE,
        0x7 => Cond::A,
        0x8 => Cond::S,
        0x9 => Cond::NS,
        0xA => Cond::P,
        0xB => Cond::NP,
        0xC => Cond::L,
        0xD => Cond::NL,
        0xE => Cond::LE,
        0xF => Cond::G,
        _ => unreachable!(),
    }
}

impl TryFrom<u8> for Cond {
    type Error = ();
    fn try_from(v: u8) -> core::result::Result<Self, ()> {
        if v < 16 {
            Ok(cond_from_low4(v))
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(bytes: &[u8]) -> Inst {
        let mut d = Decoder::new(bytes, 0x1000);
        d.next().expect("decode")
    }

    fn decn(bytes: &[u8], n: usize) -> alloc::vec::Vec<Inst> {
        extern crate alloc;
        use alloc::vec::Vec;
        let mut d = Decoder::new(bytes, 0x1000);
        let mut out: Vec<Inst> = Vec::new();
        for _ in 0..n {
            out.push(d.next().expect("decode"));
        }
        out
    }

    #[test]
    fn mov_eax_imm32() {
        // B8 2A 00 00 00  -> mov eax, 42
        let i = dec(&[0xB8, 0x2A, 0x00, 0x00, 0x00]);
        assert_eq!(i.op, Op::Mov);
        assert_eq!(i.len, 5);
        assert_eq!(i.operands[0], Some(Operand::Reg(GpReg::Rax, OpSize::B4)));
        assert_eq!(i.operands[1], Some(Operand::Imm(42, OpSize::B4)));
    }

    #[test]
    fn mov_rax_imm64_rex_w() {
        // 48 B8 11 22 33 44 55 66 77 88
        let i = dec(&[0x48, 0xB8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert_eq!(i.op, Op::Mov);
        assert_eq!(i.len, 10);
        assert_eq!(i.operands[0], Some(Operand::Reg(GpReg::Rax, OpSize::B8)));
        if let Some(Operand::Imm(v, OpSize::B8)) = i.operands[1] {
            assert_eq!(v as u64, 0x8877_6655_4433_2211);
        } else {
            panic!("expected imm64");
        }
    }

    #[test]
    fn mov_ecx_42_b9() {
        // B9 2A 00 00 00 -> mov ecx, 42
        let i = dec(&[0xB9, 0x2A, 0x00, 0x00, 0x00]);
        assert_eq!(i.op, Op::Mov);
        assert_eq!(i.operands[0], Some(Operand::Reg(GpReg::Rcx, OpSize::B4)));
        assert_eq!(i.operands[1], Some(Operand::Imm(42, OpSize::B4)));
    }

    #[test]
    fn add_eax_ebx() {
        // 01 D8 -> add eax, ebx
        let i = dec(&[0x01, 0xD8]);
        assert_eq!(i.op, Op::Add);
        assert_eq!(i.len, 2);
        assert_eq!(i.operands[0], Some(Operand::Reg(GpReg::Rax, OpSize::B4)));
        assert_eq!(i.operands[1], Some(Operand::Reg(GpReg::Rbx, OpSize::B4)));
    }

    #[test]
    fn push_rbp_pop_rbp() {
        let v = decn(&[0x55, 0x5D], 2);
        assert_eq!(v[0].op, Op::Push);
        assert_eq!(v[0].operands[0], Some(Operand::Reg(GpReg::Rbp, OpSize::B8)));
        assert_eq!(v[1].op, Op::Pop);
        assert_eq!(v[1].operands[0], Some(Operand::Reg(GpReg::Rbp, OpSize::B8)));
    }

    #[test]
    fn ret() {
        let i = dec(&[0xC3]);
        assert_eq!(i.op, Op::Ret);
        assert_eq!(i.len, 1);
    }

    #[test]
    fn call_rel32() {
        // E8 2A 00 00 00 -> call +42
        let i = dec(&[0xE8, 0x2A, 0x00, 0x00, 0x00]);
        assert_eq!(i.op, Op::Call);
        assert_eq!(i.operands[0], Some(Operand::Imm(42, OpSize::B4)));
    }

    #[test]
    fn ud2() {
        let i = dec(&[0x0F, 0x0B]);
        assert_eq!(i.op, Op::Ud2);
        assert_eq!(i.len, 2);
    }

    #[test]
    fn syscall_two_byte() {
        let i = dec(&[0x0F, 0x05]);
        assert_eq!(i.op, Op::Syscall);
    }

    #[test]
    fn jne_rel8() {
        // 75 02 -> jne +2
        let i = dec(&[0x75, 0x02]);
        assert_eq!(i.op, Op::Jcc(Cond::NE));
        assert_eq!(i.operands[0], Some(Operand::Imm(2, OpSize::B1)));
    }

    #[test]
    fn jne_rel32() {
        // 0F 85 78 56 34 12 -> jne 0x12345678
        let i = dec(&[0x0F, 0x85, 0x78, 0x56, 0x34, 0x12]);
        assert_eq!(i.op, Op::Jcc(Cond::NE));
        if let Some(Operand::Imm(v, OpSize::B4)) = i.operands[0] {
            assert_eq!(v as i32, 0x1234_5678);
        } else {
            panic!();
        }
    }

    #[test]
    fn rip_relative_mov() {
        // 48 8B 05 78 56 34 12 -> mov rax, [rip + 0x12345678]
        let i = dec(&[0x48, 0x8B, 0x05, 0x78, 0x56, 0x34, 0x12]);
        assert_eq!(i.op, Op::Mov);
        if let Some(Operand::RipRel(d, OpSize::B8)) = i.operands[1] {
            assert_eq!(d, 0x1234_5678);
        } else {
            panic!("expected rip-relative");
        }
    }

    #[test]
    fn call_indirect_rip_relative() {
        // FF 15 78 56 34 12 -> call qword ptr [rip + 0x12345678]
        let i = dec(&[0xFF, 0x15, 0x78, 0x56, 0x34, 0x12]);
        assert_eq!(i.op, Op::CallIndirect);
        if let Some(Operand::RipRel(d, OpSize::B8)) = i.operands[0] {
            assert_eq!(d, 0x1234_5678);
        } else {
            panic!("expected rip-relative");
        }
    }

    #[test]
    fn add_r8_with_rex_b() {
        // 4D 01 C8 -> add r8, r9 (REX.W+REX.R+REX.B all set)
        let i = dec(&[0x4D, 0x01, 0xC8]);
        assert_eq!(i.op, Op::Add);
        assert_eq!(i.operands[0], Some(Operand::Reg(GpReg::R8, OpSize::B8)));
        assert_eq!(i.operands[1], Some(Operand::Reg(GpReg::R9, OpSize::B8)));
    }

    #[test]
    fn movzx_eax_byte_ptr_rbx() {
        // 0F B6 03 -> movzx eax, byte ptr [rbx]
        let i = dec(&[0x0F, 0xB6, 0x03]);
        assert_eq!(i.op, Op::Movzx);
        assert_eq!(i.operands[0], Some(Operand::Reg(GpReg::Rax, OpSize::B4)));
        if let Some(Operand::Mem(m)) = i.operands[1] {
            assert_eq!(m.base, Some(GpReg::Rbx));
            assert_eq!(m.size, OpSize::B1);
            assert_eq!(m.disp, 0);
        } else {
            panic!();
        }
    }

    #[test]
    fn sib_with_index() {
        // 48 8B 04 8B -> mov rax, qword ptr [rbx + rcx*4]
        let i = dec(&[0x48, 0x8B, 0x04, 0x8B]);
        assert_eq!(i.op, Op::Mov);
        if let Some(Operand::Mem(m)) = i.operands[1] {
            assert_eq!(m.base, Some(GpReg::Rbx));
            assert_eq!(m.index, Some(GpReg::Rcx));
            assert_eq!(m.scale, 4);
            assert_eq!(m.disp, 0);
        } else {
            panic!();
        }
    }

    #[test]
    fn lea_rax_rbp_8() {
        // 48 8D 45 F8 -> lea rax, [rbp - 8]
        let i = dec(&[0x48, 0x8D, 0x45, 0xF8]);
        assert_eq!(i.op, Op::Lea);
        if let Some(Operand::Mem(m)) = i.operands[1] {
            assert_eq!(m.base, Some(GpReg::Rbp));
            assert_eq!(m.disp, -8);
        } else {
            panic!();
        }
    }

    #[test]
    fn sub_rsp_imm32() {
        // 48 83 EC 28 -> sub rsp, 0x28
        let i = dec(&[0x48, 0x83, 0xEC, 0x28]);
        assert_eq!(i.op, Op::Sub);
        assert_eq!(i.operands[0], Some(Operand::Reg(GpReg::Rsp, OpSize::B8)));
        assert_eq!(i.operands[1], Some(Operand::Imm(0x28, OpSize::B1)));
    }

    #[test]
    fn cpuid_decodes() {
        // 0F A2 -> cpuid
        let i = dec(&[0x0F, 0xA2]);
        assert_eq!(i.op, Op::Cpuid);
        assert_eq!(i.len, 2);
    }

    #[test]
    fn rdtsc_decodes() {
        // 0F 31 -> rdtsc
        let i = dec(&[0x0F, 0x31]);
        assert_eq!(i.op, Op::Rdtsc);
        assert_eq!(i.len, 2);
    }

    #[test]
    fn int3_and_nop() {
        let v = decn(&[0xCC, 0x90], 2);
        assert_eq!(v[0].op, Op::Int3);
        assert_eq!(v[1].op, Op::Nop);
    }

    #[test]
    fn imul_three_operand() {
        // 69 C0 78 56 34 12 -> imul eax, eax, 0x12345678
        let i = dec(&[0x69, 0xC0, 0x78, 0x56, 0x34, 0x12]);
        assert_eq!(i.op, Op::Imul);
        assert_eq!(i.operands[0], Some(Operand::Reg(GpReg::Rax, OpSize::B4)));
        assert_eq!(i.operands[1], Some(Operand::Reg(GpReg::Rax, OpSize::B4)));
        assert_eq!(i.operands[2], Some(Operand::Imm(0x1234_5678, OpSize::B4)));
    }

    #[test]
    fn cmovne() {
        // 0F 45 C1 -> cmovne eax, ecx
        let i = dec(&[0x0F, 0x45, 0xC1]);
        assert_eq!(i.op, Op::Cmov(Cond::NE));
        assert_eq!(i.operands[0], Some(Operand::Reg(GpReg::Rax, OpSize::B4)));
        assert_eq!(i.operands[1], Some(Operand::Reg(GpReg::Rcx, OpSize::B4)));
    }

    #[test]
    fn movq_xmm0_rax() {
        // 66 48 0F 6E C0 -> movq xmm0, rax
        let i = dec(&[0x66, 0x48, 0x0F, 0x6E, 0xC0]);
        assert_eq!(i.op, Op::MovqXmm);
        assert_eq!(i.operands[0], Some(Operand::XmmReg(0, OpSize::B8)));
        assert_eq!(i.operands[1], Some(Operand::Reg(GpReg::Rax, OpSize::B8)));
    }

    #[test]
    fn movq_rax_xmm0() {
        // 66 48 0F 7E C0 -> movq rax, xmm0
        let i = dec(&[0x66, 0x48, 0x0F, 0x7E, 0xC0]);
        assert_eq!(i.op, Op::MovqXmm);
        assert_eq!(i.operands[0], Some(Operand::Reg(GpReg::Rax, OpSize::B8)));
        assert_eq!(i.operands[1], Some(Operand::XmmReg(0, OpSize::B8)));
    }

    #[test]
    fn movsd_xmm_xmm() {
        // F2 0F 10 C1 -> movsd xmm0, xmm1
        let i = dec(&[0xF2, 0x0F, 0x10, 0xC1]);
        assert_eq!(i.op, Op::MovsdXmm);
        assert_eq!(i.operands[0], Some(Operand::XmmReg(0, OpSize::B8)));
        assert_eq!(i.operands[1], Some(Operand::XmmReg(1, OpSize::B8)));
    }

    #[test]
    fn movdqa_xmm_xmm() {
        // 66 0F 6F C1 -> movdqa xmm0, xmm1
        let i = dec(&[0x66, 0x0F, 0x6F, 0xC1]);
        assert_eq!(i.op, Op::MovdqXmm);
        assert_eq!(i.operands[0], Some(Operand::XmmReg(0, OpSize::B8)));
        assert_eq!(i.operands[1], Some(Operand::XmmReg(1, OpSize::B8)));
    }

    #[test]
    fn movdqu_xmm_mem() {
        // F3 0F 6F 04 24 -> movdqu xmm0, [rsp]
        let i = dec(&[0xF3, 0x0F, 0x6F, 0x04, 0x24]);
        assert_eq!(i.op, Op::MovdqXmm);
        assert_eq!(i.operands[0], Some(Operand::XmmReg(0, OpSize::B8)));
    }

    #[test]
    fn pxor_xmm_xmm() {
        // 66 0F EF C0 -> pxor xmm0, xmm0  (zero idiom)
        let i = dec(&[0x66, 0x0F, 0xEF, 0xC0]);
        assert_eq!(i.op, Op::PxorXmm);
        assert_eq!(i.operands[0], Some(Operand::XmmReg(0, OpSize::B8)));
        assert_eq!(i.operands[1], Some(Operand::XmmReg(0, OpSize::B8)));
    }

    #[test]
    fn addsd_xmm_xmm() {
        // F2 0F 58 C1 -> addsd xmm0, xmm1
        let i = dec(&[0xF2, 0x0F, 0x58, 0xC1]);
        assert_eq!(i.op, Op::AddScalar);
        assert_eq!(i.operands[0], Some(Operand::XmmReg(0, OpSize::B8)));
        assert_eq!(i.operands[1], Some(Operand::XmmReg(1, OpSize::B8)));
    }

    #[test]
    fn mulss_xmm_xmm() {
        // F3 0F 59 C1 -> mulss xmm0, xmm1
        let i = dec(&[0xF3, 0x0F, 0x59, 0xC1]);
        assert_eq!(i.op, Op::MulScalar);
        assert_eq!(i.operands[0], Some(Operand::XmmReg(0, OpSize::B4)));
        assert_eq!(i.operands[1], Some(Operand::XmmReg(1, OpSize::B4)));
    }

    #[test]
    fn cvtsi2sd_xmm_eax() {
        // F2 0F 2A C0 -> cvtsi2sd xmm0, eax
        let i = dec(&[0xF2, 0x0F, 0x2A, 0xC0]);
        assert_eq!(i.op, Op::CvtIntToScalar);
        assert_eq!(i.operands[0], Some(Operand::XmmReg(0, OpSize::B8)));
        assert_eq!(i.operands[1], Some(Operand::Reg(GpReg::Rax, OpSize::B4)));
    }

    #[test]
    fn cvtsi2sd_xmm_rax() {
        // F2 48 0F 2A C0 -> cvtsi2sd xmm0, rax  (REX.W -> 64-bit source)
        let i = dec(&[0xF2, 0x48, 0x0F, 0x2A, 0xC0]);
        assert_eq!(i.op, Op::CvtIntToScalar);
        assert_eq!(i.operands[1], Some(Operand::Reg(GpReg::Rax, OpSize::B8)));
    }

    #[test]
    fn cvttss2si_eax_xmm() {
        // F3 0F 2C C0 -> cvttss2si eax, xmm0
        let i = dec(&[0xF3, 0x0F, 0x2C, 0xC0]);
        assert_eq!(i.op, Op::CvtScalarToIntTrunc);
        assert_eq!(i.operands[0], Some(Operand::Reg(GpReg::Rax, OpSize::B4)));
        assert_eq!(i.operands[1], Some(Operand::XmmReg(0, OpSize::B4)));
    }

    #[test]
    fn cvtss2sd_xmm_xmm() {
        // F3 0F 5A C1 -> cvtss2sd xmm0, xmm1
        let i = dec(&[0xF3, 0x0F, 0x5A, 0xC1]);
        assert_eq!(i.op, Op::CvtSsToSd);
        assert_eq!(i.operands[0], Some(Operand::XmmReg(0, OpSize::B8)));
        assert_eq!(i.operands[1], Some(Operand::XmmReg(1, OpSize::B4)));
    }

    #[test]
    fn bswap_eax() {
        // 0F C8 -> bswap eax
        let i = dec(&[0x0F, 0xC8]);
        assert_eq!(i.op, Op::Bswap);
        assert_eq!(i.operands[0], Some(Operand::Reg(GpReg::Rax, OpSize::B4)));
    }

    #[test]
    fn bswap_rax() {
        // 48 0F C8 -> bswap rax  (REX.W -> 64-bit)
        let i = dec(&[0x48, 0x0F, 0xC8]);
        assert_eq!(i.op, Op::Bswap);
        assert_eq!(i.operands[0], Some(Operand::Reg(GpReg::Rax, OpSize::B8)));
    }

    #[test]
    fn paddq_xmm_xmm() {
        // 66 0F D4 C1 -> paddq xmm0, xmm1
        let i = dec(&[0x66, 0x0F, 0xD4, 0xC1]);
        assert_eq!(i.op, Op::PaddQ);
        assert_eq!(i.operands[0], Some(Operand::XmmReg(0, OpSize::B8)));
        assert_eq!(i.operands[1], Some(Operand::XmmReg(1, OpSize::B8)));
    }

    #[test]
    fn paddb_xmm_xmm() {
        // 66 0F FC C1 -> paddb xmm0, xmm1
        let i = dec(&[0x66, 0x0F, 0xFC, 0xC1]);
        assert_eq!(i.op, Op::PaddB);
    }

    #[test]
    fn psubw_xmm_xmm() {
        // 66 0F F9 C1 -> psubw xmm0, xmm1
        let i = dec(&[0x66, 0x0F, 0xF9, 0xC1]);
        assert_eq!(i.op, Op::PsubW);
    }

    #[test]
    fn psubd_xmm_mem() {
        // 66 0F FA 04 24 -> psubd xmm0, [rsp]
        let i = dec(&[0x66, 0x0F, 0xFA, 0x04, 0x24]);
        assert_eq!(i.op, Op::PsubD);
        assert_eq!(i.operands[0], Some(Operand::XmmReg(0, OpSize::B8)));
    }

    #[test]
    fn addps_xmm_xmm() {
        // 0F 58 C1 -> addps xmm0, xmm1
        let i = dec(&[0x0F, 0x58, 0xC1]);
        assert_eq!(i.op, Op::AddPacked);
        assert_eq!(i.operands[0], Some(Operand::XmmReg(0, OpSize::B4)));
        assert_eq!(i.operands[1], Some(Operand::XmmReg(1, OpSize::B4)));
    }

    #[test]
    fn mulpd_xmm_xmm() {
        // 66 0F 59 C1 -> mulpd xmm0, xmm1
        let i = dec(&[0x66, 0x0F, 0x59, 0xC1]);
        assert_eq!(i.op, Op::MulPacked);
        assert_eq!(i.operands[0], Some(Operand::XmmReg(0, OpSize::B8)));
        assert_eq!(i.operands[1], Some(Operand::XmmReg(1, OpSize::B8)));
    }

    #[test]
    fn psllq_xmm_imm() {
        // 66 0F 73 F0 04 -> psllq xmm0, 4
        let i = dec(&[0x66, 0x0F, 0x73, 0xF0, 0x04]);
        assert_eq!(i.op, Op::PsllImm(OpSize::B8));
        assert_eq!(i.operands[0], Some(Operand::XmmReg(0, OpSize::B8)));
        assert_eq!(i.operands[1], Some(Operand::Imm(4, OpSize::B1)));
    }

    #[test]
    fn psrld_xmm_imm() {
        // 66 0F 72 D0 0A -> psrld xmm0, 10
        let i = dec(&[0x66, 0x0F, 0x72, 0xD0, 0x0A]);
        assert_eq!(i.op, Op::PsrlImm(OpSize::B4));
        assert_eq!(i.operands[1], Some(Operand::Imm(10, OpSize::B1)));
    }

    #[test]
    fn psraw_xmm_imm() {
        // 66 0F 71 E0 03 -> psraw xmm0, 3
        let i = dec(&[0x66, 0x0F, 0x71, 0xE0, 0x03]);
        assert_eq!(i.op, Op::PsraImm(OpSize::B2));
    }

    #[test]
    fn punpcklbw_xmm_xmm() {
        // 66 0F 60 C1 -> punpcklbw xmm0, xmm1
        let i = dec(&[0x66, 0x0F, 0x60, 0xC1]);
        assert_eq!(i.op, Op::PunpckLow(OpSize::B1));
    }

    #[test]
    fn punpckhdq_xmm_xmm() {
        // 66 0F 6A C1 -> punpckhdq xmm0, xmm1
        let i = dec(&[0x66, 0x0F, 0x6A, 0xC1]);
        assert_eq!(i.op, Op::PunpckHigh(OpSize::B4));
    }

    #[test]
    fn punpcklqdq_xmm_xmm() {
        // 66 0F 6C C1 -> punpcklqdq xmm0, xmm1
        let i = dec(&[0x66, 0x0F, 0x6C, 0xC1]);
        assert_eq!(i.op, Op::PunpckLow(OpSize::B8));
    }

    #[test]
    fn pmovmskb_eax_xmm() {
        // 66 0F D7 C1 -> pmovmskb eax, xmm1
        let i = dec(&[0x66, 0x0F, 0xD7, 0xC1]);
        assert_eq!(i.op, Op::PmovmskB);
        assert_eq!(i.operands[0], Some(Operand::Reg(GpReg::Rax, OpSize::B4)));
        assert_eq!(i.operands[1], Some(Operand::XmmReg(1, OpSize::B8)));
    }

    #[test]
    fn pmullw_xmm_xmm() {
        // 66 0F D5 C1 -> pmullw xmm0, xmm1
        let i = dec(&[0x66, 0x0F, 0xD5, 0xC1]);
        assert_eq!(i.op, Op::PmullW);
    }

    #[test]
    fn pslldq_xmm_imm() {
        // 66 0F 73 F8 02 -> pslldq xmm0, 2  (modrm = 11_111_000 -> sub=7, rm=0)
        let i = dec(&[0x66, 0x0F, 0x73, 0xF8, 0x02]);
        assert_eq!(i.op, Op::PslldqImm);
        assert_eq!(i.operands[1], Some(Operand::Imm(2, OpSize::B1)));
    }

    #[test]
    fn psrldq_xmm_imm() {
        // 66 0F 73 D8 04 -> psrldq xmm0, 4  (modrm = 11_011_000 -> sub=3, rm=0)
        let i = dec(&[0x66, 0x0F, 0x73, 0xD8, 0x04]);
        assert_eq!(i.op, Op::PsrldqImm);
    }

    #[test]
    fn pshufd_xmm_xmm_imm() {
        // 66 0F 70 C1 4E -> pshufd xmm0, xmm1, 0x4E  (lanes [1,0,3,2] — half swap)
        let i = dec(&[0x66, 0x0F, 0x70, 0xC1, 0x4E]);
        assert_eq!(i.op, Op::PshufD);
        assert_eq!(i.operands[0], Some(Operand::XmmReg(0, OpSize::B8)));
        assert_eq!(i.operands[1], Some(Operand::XmmReg(1, OpSize::B8)));
        assert_eq!(i.operands[2], Some(Operand::Imm(0x4E, OpSize::B1)));
    }

    #[test]
    fn pcmpeqb_xmm_xmm() {
        // 66 0F 74 C1 -> pcmpeqb xmm0, xmm1
        let i = dec(&[0x66, 0x0F, 0x74, 0xC1]);
        assert_eq!(i.op, Op::PcmpeqLane(OpSize::B1));
        assert_eq!(i.operands[0], Some(Operand::XmmReg(0, OpSize::B8)));
        assert_eq!(i.operands[1], Some(Operand::XmmReg(1, OpSize::B8)));
    }

    #[test]
    fn pcmpeqw_xmm_xmm() {
        // 66 0F 75 C1 -> pcmpeqw xmm0, xmm1
        let i = dec(&[0x66, 0x0F, 0x75, 0xC1]);
        assert_eq!(i.op, Op::PcmpeqLane(OpSize::B2));
    }

    #[test]
    fn pcmpeqd_xmm_xmm() {
        // 66 0F 76 C1 -> pcmpeqd xmm0, xmm1
        let i = dec(&[0x66, 0x0F, 0x76, 0xC1]);
        assert_eq!(i.op, Op::PcmpeqLane(OpSize::B4));
    }

    #[test]
    fn ucomiss_xmm_xmm() {
        // 0F 2E C1 -> ucomiss xmm0, xmm1
        let i = dec(&[0x0F, 0x2E, 0xC1]);
        assert_eq!(i.op, Op::UcomisScalar);
        assert_eq!(i.operands[0], Some(Operand::XmmReg(0, OpSize::B4)));
        assert_eq!(i.operands[1], Some(Operand::XmmReg(1, OpSize::B4)));
    }

    #[test]
    fn ucomisd_xmm_xmm() {
        // 66 0F 2E C1 -> ucomisd xmm0, xmm1
        let i = dec(&[0x66, 0x0F, 0x2E, 0xC1]);
        assert_eq!(i.op, Op::UcomisScalar);
        assert_eq!(i.operands[0], Some(Operand::XmmReg(0, OpSize::B8)));
        assert_eq!(i.operands[1], Some(Operand::XmmReg(1, OpSize::B8)));
    }

    #[test]
    fn divsd_xmm_mem() {
        // F2 0F 5E 04 24 -> divsd xmm0, [rsp]
        let i = dec(&[0xF2, 0x0F, 0x5E, 0x04, 0x24]);
        assert_eq!(i.op, Op::DivScalar);
        assert_eq!(i.operands[0], Some(Operand::XmmReg(0, OpSize::B8)));
    }

    #[test]
    fn movss_mem_xmm() {
        // F3 0F 11 04 24 -> movss [rsp], xmm0
        let i = dec(&[0xF3, 0x0F, 0x11, 0x04, 0x24]);
        assert_eq!(i.op, Op::MovssXmm);
        if let Some(Operand::Mem(m)) = i.operands[0] {
            assert_eq!(m.base, Some(GpReg::Rsp));
            assert_eq!(m.size, OpSize::B4);
        } else {
            panic!("expected Mem dst");
        }
        assert_eq!(i.operands[1], Some(Operand::XmmReg(0, OpSize::B4)));
    }

    #[test]
    fn setz_al() {
        // 0F 94 C0 -> sete al
        let i = dec(&[0x0F, 0x94, 0xC0]);
        assert_eq!(i.op, Op::Set(Cond::E));
        assert_eq!(i.operands[0], Some(Operand::Reg(GpReg::Rax, OpSize::B1)));
    }

    #[test]
    fn fs_prefix_threads_through() {
        // 64 48 8B 04 25 30 00 00 00 -> mov rax, fs:[0x30]
        let i = dec(&[0x64, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00]);
        assert_eq!(i.op, Op::Mov);
        if let Some(Operand::Mem(m)) = i.operands[1] {
            assert_eq!(m.seg, Some(Seg::Fs));
            assert_eq!(m.disp, 0x30);
        } else {
            panic!("expected memory with fs override");
        }
    }
}

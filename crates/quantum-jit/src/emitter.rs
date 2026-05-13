// Bit-pattern encoders intentionally mirror the field layout from the
// reference manual; splitting them up would obscure the encoding while
// adding no real abstraction. Identity ops are kept where they make the
// bit-layout columns line up with the field tables.
#![allow(clippy::too_many_arguments, clippy::identity_op)]

//! AArch64 (A64) instruction emitter.
//!
//! From-scratch: no `dynasm`, no `cranelift`, no third-party assembler.
//! Every encoder writes a single little-endian 32-bit instruction word
//! to `code`. Bit layouts follow the Armv8-A reference manual section
//! C6 ("A64 Base Instructions") and C7 ("A64 SIMD/FP").
//!
//! Conventions:
//!   * `Reg::x(n)` is the 64-bit view, `Reg::w(n)` is the 32-bit view.
//!     `XZR`/`WZR` (zero register) is index 31 in the GPR class. SP is
//!     also index 31 but in the *stack-pointer* class; encoders that
//!     accept SP take `RegOrSp` rather than `Reg`.
//!   * Branch targets are `Label`s. Forward branches record a fixup;
//!     `bind` patches them when the label is bound. `finish()` panics
//!     if any label is still unbound.

use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reg(pub u8);

impl Reg {
    pub const fn x(n: u8) -> Self {
        debug_assert!(n < 32);
        Self(n)
    }
    pub const X0: Self = Self(0);
    pub const X1: Self = Self(1);
    pub const X2: Self = Self(2);
    pub const X3: Self = Self(3);
    pub const X4: Self = Self(4);
    pub const X5: Self = Self(5);
    pub const X6: Self = Self(6);
    pub const X7: Self = Self(7);
    pub const X8: Self = Self(8);
    pub const X16: Self = Self(16);
    pub const X17: Self = Self(17);
    pub const X19: Self = Self(19);
    pub const X29: Self = Self(29);
    pub const X30: Self = Self(30); // LR
    pub const XZR: Self = Self(31);
    pub const SP: Self = Self(31); // distinct class — disambiguated by encoder

    pub fn raw(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cond {
    Eq = 0b0000,
    Ne = 0b0001,
    Cs = 0b0010, // alias HS
    Cc = 0b0011, // alias LO
    Mi = 0b0100,
    Pl = 0b0101,
    Vs = 0b0110,
    Vc = 0b0111,
    Hi = 0b1000,
    Ls = 0b1001,
    Ge = 0b1010,
    Lt = 0b1011,
    Gt = 0b1100,
    Le = 0b1101,
    Al = 0b1110,
    Nv = 0b1111,
}

impl Cond {
    pub fn invert(self) -> Self {
        // Toggle bit 0 — well-defined for all condition codes except AL/NV.
        let v = (self as u8) ^ 1;
        // SAFETY: we only flip bit 0 within the 4-bit field; the result is
        // still a valid Cond discriminant.
        unsafe { core::mem::transmute::<u8, Cond>(v) }
    }
}

/// Width selector. `X` = 64-bit, `W` = 32-bit. Maps to the `sf` bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sf {
    W = 0,
    X = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShiftKind {
    Lsl = 0b00,
    Lsr = 0b01,
    Asr = 0b10,
    Ror = 0b11,
}

#[derive(Debug, Clone, Copy)]
pub struct Label(u32);

#[derive(Debug, Clone, Copy)]
enum FixupKind {
    /// 26-bit signed offset, word-aligned. B / BL.
    Branch26,
    /// 19-bit signed offset, word-aligned. B.cond / CBZ / CBNZ.
    Branch19,
    /// 14-bit signed offset, word-aligned. TBZ / TBNZ.
    Branch14,
}

#[derive(Debug)]
struct Fixup {
    word_index: usize,
    kind: FixupKind,
    label: u32,
}

#[derive(Debug, Default)]
pub struct Emitter {
    code: Vec<u32>,
    labels: Vec<Option<usize>>, // word index where bound
    fixups: Vec<Fixup>,
}

impl Emitter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn position(&self) -> usize {
        self.code.len()
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.code.len() * 4);
        for w in &self.code {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }

    pub fn words(&self) -> &[u32] {
        &self.code
    }

    pub fn make_label(&mut self) -> Label {
        let id = self.labels.len() as u32;
        self.labels.push(None);
        Label(id)
    }

    pub fn bind(&mut self, label: Label) {
        debug_assert!((label.0 as usize) < self.labels.len());
        let at = self.code.len();
        let slot = &mut self.labels[label.0 as usize];
        assert!(slot.is_none(), "label already bound");
        *slot = Some(at);
    }

    /// Resolve every pending fixup. Returns `Err(label_id)` for the first
    /// label that remained unbound at finalisation, or out-of-range for
    /// the instruction form.
    pub fn finish(&mut self) -> Result<(), FinishError> {
        let fixups = core::mem::take(&mut self.fixups);
        for f in fixups {
            let bound = self.labels[f.label as usize].ok_or(FinishError::UnboundLabel(f.label))?;
            let from = f.word_index as i64;
            let to = bound as i64;
            let delta = to - from;
            let word = self.code[f.word_index];
            self.code[f.word_index] = patch_branch(word, f.kind, delta)?;
        }
        Ok(())
    }

    fn push(&mut self, word: u32) {
        self.code.push(word);
    }

    /// Append a raw instruction word. Escape hatch for callers that
    /// hand-encode opcodes we haven't yet added a typed helper for. Use
    /// sparingly; everything in production should go through a typed
    /// encoder so the bit layout stays under test.
    pub fn raw_word(&mut self, word: u32) {
        self.push(word);
    }

    /// Emit an unfinished branch: store the raw opcode bits with zeroed
    /// offset and record a fixup for the label.
    fn emit_branch(&mut self, base_word: u32, kind: FixupKind, label: Label) {
        let word_index = self.code.len();
        self.push(base_word);
        if let Some(at) = self.labels[label.0 as usize] {
            let delta = at as i64 - word_index as i64;
            self.code[word_index] =
                patch_branch(base_word, kind, delta).expect("backward branch out of range");
        } else {
            self.fixups.push(Fixup {
                word_index,
                kind,
                label: label.0,
            });
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishError {
    UnboundLabel(u32),
    BranchOutOfRange,
}

fn patch_branch(base: u32, kind: FixupKind, delta_words: i64) -> Result<u32, FinishError> {
    match kind {
        FixupKind::Branch26 => {
            let imm = delta_words;
            if !(-(1 << 25)..(1 << 25)).contains(&imm) {
                return Err(FinishError::BranchOutOfRange);
            }
            Ok((base & 0xFC00_0000) | ((imm as u32) & 0x03FF_FFFF))
        }
        FixupKind::Branch19 => {
            let imm = delta_words;
            if !(-(1 << 18)..(1 << 18)).contains(&imm) {
                return Err(FinishError::BranchOutOfRange);
            }
            Ok((base & 0xFF00_001F) | (((imm as u32) & 0x0007_FFFF) << 5))
        }
        FixupKind::Branch14 => {
            let imm = delta_words;
            if !(-(1 << 13)..(1 << 13)).contains(&imm) {
                return Err(FinishError::BranchOutOfRange);
            }
            Ok((base & 0xFFF8_001F) | (((imm as u32) & 0x0000_3FFF) << 5))
        }
    }
}

// =============== Move wide (MOVZ / MOVN / MOVK) ===============

impl Emitter {
    fn movw(&mut self, sf: Sf, opc: u32, hw: u32, imm16: u16, rd: Reg) {
        debug_assert!(
            hw < if sf == Sf::X { 4 } else { 2 },
            "hw out of range for sf"
        );
        let w = ((sf as u32) << 31)
            | (opc << 29)
            | (0b100101 << 23)
            | (hw << 21)
            | ((imm16 as u32) << 5)
            | (rd.0 as u32);
        self.push(w);
    }

    pub fn movz64(&mut self, rd: Reg, imm16: u16, lsl: u32) {
        self.movw(Sf::X, 0b10, lsl / 16, imm16, rd);
    }

    pub fn movz32(&mut self, rd: Reg, imm16: u16, lsl: u32) {
        self.movw(Sf::W, 0b10, lsl / 16, imm16, rd);
    }

    pub fn movn64(&mut self, rd: Reg, imm16: u16, lsl: u32) {
        self.movw(Sf::X, 0b00, lsl / 16, imm16, rd);
    }

    pub fn movk64(&mut self, rd: Reg, imm16: u16, lsl: u32) {
        self.movw(Sf::X, 0b11, lsl / 16, imm16, rd);
    }

    pub fn movk32(&mut self, rd: Reg, imm16: u16, lsl: u32) {
        self.movw(Sf::W, 0b11, lsl / 16, imm16, rd);
    }

    /// Synthesise a 64-bit constant into `rd` using the minimum number of
    /// MOVZ + MOVK instructions for the supplied value.
    pub fn load_const64(&mut self, rd: Reg, value: u64) {
        // Special case: if value fits in a single MOVZ.
        if (value & !0xFFFF) == 0 {
            self.movz64(rd, value as u16, 0);
            return;
        }
        // Walk 16-bit lanes; emit MOVZ for the first non-zero one, MOVK
        // for subsequent non-zero ones.
        let mut emitted = false;
        for lane in 0..4u32 {
            let part = ((value >> (lane * 16)) & 0xFFFF) as u16;
            if part == 0 && emitted {
                continue;
            }
            if !emitted && part == 0 && lane != 3 {
                continue;
            }
            if !emitted {
                self.movz64(rd, part, lane * 16);
                emitted = true;
            } else {
                self.movk64(rd, part, lane * 16);
            }
        }
        if !emitted {
            self.movz64(rd, 0, 0);
        }
    }
}

// =============== Add/sub (immediate) ===============

impl Emitter {
    fn addsub_imm(&mut self, sf: Sf, op: u32, s: u32, shift: u32, imm12: u32, rn: Reg, rd: Reg) {
        debug_assert!(imm12 < (1 << 12));
        debug_assert!(shift <= 1);
        let w = ((sf as u32) << 31)
            | (op << 30)
            | (s << 29)
            | (0b100010 << 23)
            | (shift << 22)
            | (imm12 << 10)
            | ((rn.0 as u32) << 5)
            | (rd.0 as u32);
        self.push(w);
    }

    pub fn add64_imm(&mut self, rd: Reg, rn: Reg, imm: u32) {
        let (shift, imm12) = encode_addsub_imm(imm).expect("imm out of range");
        self.addsub_imm(Sf::X, 0, 0, shift, imm12, rn, rd);
    }

    pub fn adds64_imm(&mut self, rd: Reg, rn: Reg, imm: u32) {
        let (shift, imm12) = encode_addsub_imm(imm).expect("imm out of range");
        self.addsub_imm(Sf::X, 0, 1, shift, imm12, rn, rd);
    }

    pub fn sub64_imm(&mut self, rd: Reg, rn: Reg, imm: u32) {
        let (shift, imm12) = encode_addsub_imm(imm).expect("imm out of range");
        self.addsub_imm(Sf::X, 1, 0, shift, imm12, rn, rd);
    }

    pub fn subs64_imm(&mut self, rd: Reg, rn: Reg, imm: u32) {
        let (shift, imm12) = encode_addsub_imm(imm).expect("imm out of range");
        self.addsub_imm(Sf::X, 1, 1, shift, imm12, rn, rd);
    }

    pub fn cmp64_imm(&mut self, rn: Reg, imm: u32) {
        // Alias of SUBS XZR, Xn, #imm.
        self.subs64_imm(Reg::XZR, rn, imm);
    }
}

fn encode_addsub_imm(value: u32) -> Option<(u32, u32)> {
    if value < (1 << 12) {
        Some((0, value))
    } else if value & 0xFFF == 0 && (value >> 12) < (1 << 12) {
        Some((1, value >> 12))
    } else {
        None
    }
}

// =============== Add/sub (shifted register) ===============

impl Emitter {
    fn addsub_shifted(
        &mut self,
        sf: Sf,
        op: u32,
        s: u32,
        shift: ShiftKind,
        rm: Reg,
        imm6: u32,
        rn: Reg,
        rd: Reg,
    ) {
        debug_assert!(imm6 < 64);
        let w = ((sf as u32) << 31)
            | (op << 30)
            | (s << 29)
            | (0b01011 << 24)
            | ((shift as u32) << 22)
            | (0 << 21)
            | ((rm.0 as u32) << 16)
            | (imm6 << 10)
            | ((rn.0 as u32) << 5)
            | (rd.0 as u32);
        self.push(w);
    }

    pub fn add64(&mut self, rd: Reg, rn: Reg, rm: Reg) {
        self.addsub_shifted(Sf::X, 0, 0, ShiftKind::Lsl, rm, 0, rn, rd);
    }

    pub fn adds64(&mut self, rd: Reg, rn: Reg, rm: Reg) {
        self.addsub_shifted(Sf::X, 0, 1, ShiftKind::Lsl, rm, 0, rn, rd);
    }

    pub fn sub64(&mut self, rd: Reg, rn: Reg, rm: Reg) {
        self.addsub_shifted(Sf::X, 1, 0, ShiftKind::Lsl, rm, 0, rn, rd);
    }

    pub fn subs64(&mut self, rd: Reg, rn: Reg, rm: Reg) {
        self.addsub_shifted(Sf::X, 1, 1, ShiftKind::Lsl, rm, 0, rn, rd);
    }

    pub fn cmp64(&mut self, rn: Reg, rm: Reg) {
        self.subs64(Reg::XZR, rn, rm);
    }
}

// =============== Logical (shifted register + immediate) ===============

impl Emitter {
    fn logical_shifted(
        &mut self,
        sf: Sf,
        opc: u32,
        shift: ShiftKind,
        n: u32,
        rm: Reg,
        imm6: u32,
        rn: Reg,
        rd: Reg,
    ) {
        let w = ((sf as u32) << 31)
            | (opc << 29)
            | (0b01010 << 24)
            | ((shift as u32) << 22)
            | (n << 21)
            | ((rm.0 as u32) << 16)
            | (imm6 << 10)
            | ((rn.0 as u32) << 5)
            | (rd.0 as u32);
        self.push(w);
    }

    pub fn and64(&mut self, rd: Reg, rn: Reg, rm: Reg) {
        self.logical_shifted(Sf::X, 0b00, ShiftKind::Lsl, 0, rm, 0, rn, rd);
    }
    pub fn orr64(&mut self, rd: Reg, rn: Reg, rm: Reg) {
        self.logical_shifted(Sf::X, 0b01, ShiftKind::Lsl, 0, rm, 0, rn, rd);
    }
    pub fn eor64(&mut self, rd: Reg, rn: Reg, rm: Reg) {
        self.logical_shifted(Sf::X, 0b10, ShiftKind::Lsl, 0, rm, 0, rn, rd);
    }
    pub fn ands64(&mut self, rd: Reg, rn: Reg, rm: Reg) {
        self.logical_shifted(Sf::X, 0b11, ShiftKind::Lsl, 0, rm, 0, rn, rd);
    }

    /// MOV (register) — alias of ORR Xd, XZR, Xm.
    pub fn mov64(&mut self, rd: Reg, rm: Reg) {
        self.orr64(rd, Reg::XZR, rm);
    }
}

// =============== Data processing (1- and 2-source) ===============

impl Emitter {
    fn dp_2src(&mut self, sf: Sf, opcode: u32, rm: Reg, rn: Reg, rd: Reg) {
        let w = ((sf as u32) << 31)
            | (0 << 30)
            | (0 << 29)
            | (0b11010110 << 21)
            | ((rm.0 as u32) << 16)
            | (opcode << 10)
            | ((rn.0 as u32) << 5)
            | (rd.0 as u32);
        self.push(w);
    }

    pub fn udiv64(&mut self, rd: Reg, rn: Reg, rm: Reg) {
        self.dp_2src(Sf::X, 0b000010, rm, rn, rd);
    }
    pub fn sdiv64(&mut self, rd: Reg, rn: Reg, rm: Reg) {
        self.dp_2src(Sf::X, 0b000011, rm, rn, rd);
    }
    pub fn lslv64(&mut self, rd: Reg, rn: Reg, rm: Reg) {
        self.dp_2src(Sf::X, 0b001000, rm, rn, rd);
    }
    pub fn lsrv64(&mut self, rd: Reg, rn: Reg, rm: Reg) {
        self.dp_2src(Sf::X, 0b001001, rm, rn, rd);
    }
    pub fn asrv64(&mut self, rd: Reg, rn: Reg, rm: Reg) {
        self.dp_2src(Sf::X, 0b001010, rm, rn, rd);
    }
    pub fn rorv64(&mut self, rd: Reg, rn: Reg, rm: Reg) {
        self.dp_2src(Sf::X, 0b001011, rm, rn, rd);
    }

    /// MADD Rd, Rn, Rm, Ra — Rd = Ra + Rn*Rm.
    pub fn madd64(&mut self, rd: Reg, rn: Reg, rm: Reg, ra: Reg) {
        let w = (1 << 31)
            | (0b00 << 29)
            | (0b11011 << 24)
            | (0b000 << 21)
            | ((rm.0 as u32) << 16)
            | (0 << 15)
            | ((ra.0 as u32) << 10)
            | ((rn.0 as u32) << 5)
            | (rd.0 as u32);
        self.push(w);
    }

    /// MUL Rd, Rn, Rm — alias of MADD Rd, Rn, Rm, XZR.
    pub fn mul64(&mut self, rd: Reg, rn: Reg, rm: Reg) {
        self.madd64(rd, rn, rm, Reg::XZR);
    }

    /// MSUB Rd, Rn, Rm, Ra — Rd = Ra - Rn*Rm.
    pub fn msub64(&mut self, rd: Reg, rn: Reg, rm: Reg, ra: Reg) {
        let w = (1 << 31)
            | (0b00 << 29)
            | (0b11011 << 24)
            | (0b000 << 21)
            | ((rm.0 as u32) << 16)
            | (1 << 15)
            | ((ra.0 as u32) << 10)
            | ((rn.0 as u32) << 5)
            | (rd.0 as u32);
        self.push(w);
    }

    /// UMULH Rd, Rn, Rm — high 64 bits of unsigned 64x64.
    pub fn umulh64(&mut self, rd: Reg, rn: Reg, rm: Reg) {
        let w = 0x9BC0_7C00 | ((rm.0 as u32) << 16) | ((rn.0 as u32) << 5) | (rd.0 as u32);
        self.push(w);
    }

    /// SMULH Rd, Rn, Rm — high 64 bits of signed 64x64.
    pub fn smulh64(&mut self, rd: Reg, rn: Reg, rm: Reg) {
        let w = 0x9B40_7C00 | ((rm.0 as u32) << 16) | ((rn.0 as u32) << 5) | (rd.0 as u32);
        self.push(w);
    }
}

// =============== Conditional select / set ===============

impl Emitter {
    fn csel_form(&mut self, sf: Sf, op: u32, o2: u32, rm: Reg, cond: Cond, rn: Reg, rd: Reg) {
        let w = ((sf as u32) << 31)
            | (op << 30)
            | (0 << 29)
            | (0b11010100 << 21)
            | ((rm.0 as u32) << 16)
            | ((cond as u32) << 12)
            | (o2 << 10)
            | ((rn.0 as u32) << 5)
            | (rd.0 as u32);
        self.push(w);
    }

    pub fn csel64(&mut self, rd: Reg, rn: Reg, rm: Reg, cond: Cond) {
        self.csel_form(Sf::X, 0, 0b00, rm, cond, rn, rd);
    }
    pub fn csinc64(&mut self, rd: Reg, rn: Reg, rm: Reg, cond: Cond) {
        self.csel_form(Sf::X, 0, 0b01, rm, cond, rn, rd);
    }
    pub fn csinv64(&mut self, rd: Reg, rn: Reg, rm: Reg, cond: Cond) {
        self.csel_form(Sf::X, 1, 0b00, rm, cond, rn, rd);
    }
    pub fn csneg64(&mut self, rd: Reg, rn: Reg, rm: Reg, cond: Cond) {
        self.csel_form(Sf::X, 1, 0b01, rm, cond, rn, rd);
    }

    /// CSET — alias of CSINC Rd, XZR, XZR, !cond.
    pub fn cset64(&mut self, rd: Reg, cond: Cond) {
        self.csinc64(rd, Reg::XZR, Reg::XZR, cond.invert());
    }
}

// =============== Load / Store (immediate, unsigned offset) ===============

impl Emitter {
    fn ldst_uoff(&mut self, size: u32, v: u32, opc: u32, imm12: u32, rn: Reg, rt: Reg) {
        debug_assert!(imm12 < (1 << 12));
        let w = (size << 30)
            | (0b111 << 27)
            | (v << 26)
            | (0b01 << 24)
            | (opc << 22)
            | (imm12 << 10)
            | ((rn.0 as u32) << 5)
            | (rt.0 as u32);
        self.push(w);
    }

    pub fn ldr64(&mut self, rt: Reg, rn: Reg, offset: u32) {
        debug_assert!(offset.is_multiple_of(8));
        self.ldst_uoff(0b11, 0, 0b01, offset / 8, rn, rt);
    }

    pub fn ldr32(&mut self, rt: Reg, rn: Reg, offset: u32) {
        debug_assert!(offset.is_multiple_of(4));
        self.ldst_uoff(0b10, 0, 0b01, offset / 4, rn, rt);
    }

    pub fn ldrb(&mut self, rt: Reg, rn: Reg, offset: u32) {
        self.ldst_uoff(0b00, 0, 0b01, offset, rn, rt);
    }

    pub fn ldrh(&mut self, rt: Reg, rn: Reg, offset: u32) {
        debug_assert!(offset.is_multiple_of(2));
        self.ldst_uoff(0b01, 0, 0b01, offset / 2, rn, rt);
    }

    pub fn str64(&mut self, rt: Reg, rn: Reg, offset: u32) {
        debug_assert!(offset.is_multiple_of(8));
        self.ldst_uoff(0b11, 0, 0b00, offset / 8, rn, rt);
    }

    pub fn str32(&mut self, rt: Reg, rn: Reg, offset: u32) {
        debug_assert!(offset.is_multiple_of(4));
        self.ldst_uoff(0b10, 0, 0b00, offset / 4, rn, rt);
    }

    pub fn strb(&mut self, rt: Reg, rn: Reg, offset: u32) {
        self.ldst_uoff(0b00, 0, 0b00, offset, rn, rt);
    }

    pub fn strh(&mut self, rt: Reg, rn: Reg, offset: u32) {
        debug_assert!(offset.is_multiple_of(2));
        self.ldst_uoff(0b01, 0, 0b00, offset / 2, rn, rt);
    }
}

// =============== Load/Store pair ===============

impl Emitter {
    fn ldstp(
        &mut self,
        opc: u32,
        v: u32,
        load: u32,
        idx_mode: u32,
        imm7: i32,
        rt2: Reg,
        rn: Reg,
        rt: Reg,
    ) {
        let imm7_bits = (imm7 as u32) & 0x7F;
        let w = (opc << 30)
            | (0b101 << 27)
            | (v << 26)
            | (idx_mode << 23)
            | (load << 22)
            | (imm7_bits << 15)
            | ((rt2.0 as u32) << 10)
            | ((rn.0 as u32) << 5)
            | (rt.0 as u32);
        self.push(w);
    }

    /// STP Xt, Xt2, [Xn, #imm]! — pre-indexed.
    pub fn stp64_pre(&mut self, rt: Reg, rt2: Reg, rn: Reg, imm: i32) {
        debug_assert!(imm & 7 == 0);
        let scaled = imm / 8;
        debug_assert!((-64..64).contains(&scaled));
        self.ldstp(0b10, 0, 0, 0b011, scaled, rt2, rn, rt);
    }

    /// LDP Xt, Xt2, [Xn], #imm — post-indexed.
    pub fn ldp64_post(&mut self, rt: Reg, rt2: Reg, rn: Reg, imm: i32) {
        debug_assert!(imm & 7 == 0);
        let scaled = imm / 8;
        debug_assert!((-64..64).contains(&scaled));
        self.ldstp(0b10, 0, 1, 0b001, scaled, rt2, rn, rt);
    }

    /// STP Xt, Xt2, [Xn, #imm] — signed offset.
    pub fn stp64(&mut self, rt: Reg, rt2: Reg, rn: Reg, imm: i32) {
        debug_assert!(imm & 7 == 0);
        let scaled = imm / 8;
        debug_assert!((-64..64).contains(&scaled));
        self.ldstp(0b10, 0, 0, 0b010, scaled, rt2, rn, rt);
    }

    /// LDP Xt, Xt2, [Xn, #imm] — signed offset.
    pub fn ldp64(&mut self, rt: Reg, rt2: Reg, rn: Reg, imm: i32) {
        debug_assert!(imm & 7 == 0);
        let scaled = imm / 8;
        debug_assert!((-64..64).contains(&scaled));
        self.ldstp(0b10, 0, 1, 0b010, scaled, rt2, rn, rt);
    }
}

// =============== Branches ===============

impl Emitter {
    pub fn b(&mut self, label: Label) {
        let base = 0b000101 << 26;
        self.emit_branch(base, FixupKind::Branch26, label);
    }

    pub fn bl(&mut self, label: Label) {
        let base = 0b100101 << 26;
        self.emit_branch(base, FixupKind::Branch26, label);
    }

    pub fn b_cond(&mut self, cond: Cond, label: Label) {
        let base = (0b01010100 << 24) | ((cond as u32) & 0xF);
        self.emit_branch(base, FixupKind::Branch19, label);
    }

    pub fn cbz64(&mut self, rt: Reg, label: Label) {
        let base = (1 << 31) | (0b011010 << 25) | (rt.0 as u32);
        self.emit_branch(base, FixupKind::Branch19, label);
    }

    pub fn cbnz64(&mut self, rt: Reg, label: Label) {
        let base = (1 << 31) | (0b011010 << 25) | (1 << 24) | (rt.0 as u32);
        self.emit_branch(base, FixupKind::Branch19, label);
    }

    pub fn tbz(&mut self, rt: Reg, bit: u32, label: Label) {
        debug_assert!(bit < 64);
        let b5 = (bit >> 5) & 1;
        let b40 = bit & 0x1F;
        let base = (b5 << 31) | (0b011011 << 25) | (b40 << 19) | (rt.0 as u32);
        self.emit_branch(base, FixupKind::Branch14, label);
    }

    pub fn tbnz(&mut self, rt: Reg, bit: u32, label: Label) {
        debug_assert!(bit < 64);
        let b5 = (bit >> 5) & 1;
        let b40 = bit & 0x1F;
        let base = (b5 << 31) | (0b011011 << 25) | (1 << 24) | (b40 << 19) | (rt.0 as u32);
        self.emit_branch(base, FixupKind::Branch14, label);
    }

    pub fn br(&mut self, rn: Reg) {
        self.push(0xD61F_0000 | ((rn.0 as u32) << 5));
    }

    pub fn blr(&mut self, rn: Reg) {
        self.push(0xD63F_0000 | ((rn.0 as u32) << 5));
    }

    pub fn ret(&mut self) {
        self.ret_to(Reg::X30);
    }

    pub fn ret_to(&mut self, rn: Reg) {
        self.push(0xD65F_0000 | ((rn.0 as u32) << 5));
    }
}

// =============== System ===============

impl Emitter {
    pub fn nop(&mut self) {
        self.push(0xD503_201F);
    }

    pub fn brk(&mut self, imm16: u16) {
        self.push(0xD420_0000 | ((imm16 as u32) << 5));
    }

    pub fn isb(&mut self) {
        self.push(0xD503_30DF); // CRm=15, op2=6
    }

    pub fn dmb_ish(&mut self) {
        self.push(0xD503_3BBF);
    }

    pub fn mrs_nzcv(&mut self, rt: Reg) {
        self.push(0xD53B_4200 | (rt.0 as u32));
    }

    pub fn msr_nzcv(&mut self, rt: Reg) {
        self.push(0xD51B_4200 | (rt.0 as u32));
    }

    pub fn mrs_tpidr_el0(&mut self, rt: Reg) {
        // MRS Xt, TPIDR_EL0 — op0=3, op1=3, CRn=13, CRm=0, op2=2.
        self.push(0xD53B_D040 | (rt.0 as u32));
    }
}

// =============== Tests (bit-pattern golden) ===============

#[cfg(test)]
mod tests {
    use super::*;

    fn one(f: impl FnOnce(&mut Emitter)) -> u32 {
        let mut e = Emitter::new();
        f(&mut e);
        assert_eq!(e.words().len(), 1, "expected one instruction");
        e.words()[0]
    }

    #[test]
    fn movz_x0_42() {
        // movz x0, #42  -> 0xD2800540
        assert_eq!(one(|e| e.movz64(Reg::X0, 42, 0)), 0xD280_0540);
    }

    #[test]
    fn movz_w0_42() {
        // movz w0, #42  -> 0x52800540
        assert_eq!(one(|e| e.movz32(Reg::X0, 42, 0)), 0x5280_0540);
    }

    #[test]
    fn movk_x0_lsl_16() {
        // movk x0, #0xBEEF, lsl #16 -> 0xF2B7DDE0 (confirmed via clang -c)
        assert_eq!(one(|e| e.movk64(Reg::X0, 0xBEEF, 16)), 0xF2B7_DDE0);
    }

    #[test]
    fn add_x0_x1_x2() {
        // add x0, x1, x2 -> 0x8B020020
        assert_eq!(one(|e| e.add64(Reg::X0, Reg::X1, Reg::X2)), 0x8B02_0020);
    }

    #[test]
    fn sub_x0_x1_x2() {
        // sub x0, x1, x2 -> 0xCB020020
        assert_eq!(one(|e| e.sub64(Reg::X0, Reg::X1, Reg::X2)), 0xCB02_0020);
    }

    #[test]
    fn add_x0_x1_imm_42() {
        // add x0, x1, #42 -> 0x9100A820
        assert_eq!(one(|e| e.add64_imm(Reg::X0, Reg::X1, 42)), 0x9100_A820);
    }

    #[test]
    fn sub_sp_imm_lsl12() {
        // sub sp, sp, #1, lsl #12 -> 0xD14007FF (confirmed via clang -c)
        assert_eq!(one(|e| e.sub64_imm(Reg::SP, Reg::SP, 1 << 12)), 0xD140_07FF);
    }

    #[test]
    fn cmp_x0_x1() {
        // cmp x0, x1  -> subs xzr, x0, x1 -> 0xEB01001F
        assert_eq!(one(|e| e.cmp64(Reg::X0, Reg::X1)), 0xEB01_001F);
    }

    #[test]
    fn orr_mov_alias() {
        // mov x0, x1 -> orr x0, xzr, x1 -> 0xAA0103E0
        assert_eq!(one(|e| e.mov64(Reg::X0, Reg::X1)), 0xAA01_03E0);
    }

    #[test]
    fn mul_x0_x1_x2() {
        // mul x0, x1, x2 -> madd x0, x1, x2, xzr -> 0x9B027C20
        assert_eq!(one(|e| e.mul64(Reg::X0, Reg::X1, Reg::X2)), 0x9B02_7C20);
    }

    #[test]
    fn udiv_sdiv() {
        assert_eq!(one(|e| e.udiv64(Reg::X0, Reg::X1, Reg::X2)), 0x9AC2_0820);
        assert_eq!(one(|e| e.sdiv64(Reg::X0, Reg::X1, Reg::X2)), 0x9AC2_0C20);
    }

    #[test]
    fn csel_eq() {
        // csel x0, x1, x2, eq -> 0x9A82_0020
        assert_eq!(
            one(|e| e.csel64(Reg::X0, Reg::X1, Reg::X2, Cond::Eq)),
            0x9A82_0020
        );
    }

    #[test]
    fn cset_ne() {
        // cset x0, ne -> csinc x0, xzr, xzr, eq -> 0x9A9F07E0
        // (confirmed via clang -c arm64-apple-darwin)
        assert_eq!(one(|e| e.cset64(Reg::X0, Cond::Ne)), 0x9A9F_07E0);
    }

    #[test]
    fn ldr_str_x_offset() {
        // ldr x0, [x1, #16] -> 0xF9400820
        assert_eq!(one(|e| e.ldr64(Reg::X0, Reg::X1, 16)), 0xF940_0820);
        // str x0, [x1, #16] -> 0xF9000820
        assert_eq!(one(|e| e.str64(Reg::X0, Reg::X1, 16)), 0xF900_0820);
    }

    #[test]
    fn ldr_str_w_offset() {
        // ldr w0, [x1, #4] -> 0xB9400420
        assert_eq!(one(|e| e.ldr32(Reg::X0, Reg::X1, 4)), 0xB940_0420);
        // str w0, [x1, #4] -> 0xB9000420
        assert_eq!(one(|e| e.str32(Reg::X0, Reg::X1, 4)), 0xB900_0420);
    }

    #[test]
    fn ldrb_strb() {
        // ldrb w0, [x1] -> 0x39400020
        assert_eq!(one(|e| e.ldrb(Reg::X0, Reg::X1, 0)), 0x3940_0020);
        // strb w0, [x1] -> 0x39000020
        assert_eq!(one(|e| e.strb(Reg::X0, Reg::X1, 0)), 0x3900_0020);
    }

    #[test]
    fn stp_pre_indexed() {
        // stp x29, x30, [sp, #-16]! -> 0xA9BF7BFD
        assert_eq!(
            one(|e| e.stp64_pre(Reg::X29, Reg::X30, Reg::SP, -16)),
            0xA9BF_7BFD
        );
    }

    #[test]
    fn ldp_post_indexed() {
        // ldp x29, x30, [sp], #16 -> 0xA8C17BFD
        assert_eq!(
            one(|e| e.ldp64_post(Reg::X29, Reg::X30, Reg::SP, 16)),
            0xA8C1_7BFD
        );
    }

    #[test]
    fn ret_default() {
        // ret -> 0xD65F03C0
        assert_eq!(one(|e| e.ret()), 0xD65F_03C0);
    }

    #[test]
    fn br_blr() {
        // br x16 -> 0xD61F0200
        assert_eq!(one(|e| e.br(Reg::X16)), 0xD61F_0200);
        // blr x16 -> 0xD63F0200
        assert_eq!(one(|e| e.blr(Reg::X16)), 0xD63F_0200);
    }

    #[test]
    fn nop_brk() {
        assert_eq!(one(|e| e.nop()), 0xD503_201F);
        assert_eq!(one(|e| e.brk(0)), 0xD420_0000);
        assert_eq!(one(|e| e.brk(1)), 0xD420_0020);
    }

    #[test]
    fn mrs_msr_nzcv() {
        // mrs x0, nzcv -> 0xD53B4200
        assert_eq!(one(|e| e.mrs_nzcv(Reg::X0)), 0xD53B_4200);
        // msr nzcv, x0 -> 0xD51B4200
        assert_eq!(one(|e| e.msr_nzcv(Reg::X0)), 0xD51B_4200);
    }

    #[test]
    fn forward_b_to_bound_label() {
        let mut e = Emitter::new();
        let target = e.make_label();
        e.b(target); // forward branch
        e.nop();
        e.bind(target);
        e.ret();
        e.finish().expect("finish");
        // First word should now branch +2 words: 0x14000002
        assert_eq!(e.words()[0], 0x1400_0002);
    }

    #[test]
    fn backward_b_cond_inplace_patch() {
        let mut e = Emitter::new();
        let top = e.make_label();
        e.bind(top);
        e.nop();
        // b.ne top -> backward branch, immediately patched.
        e.b_cond(Cond::Ne, top);
        // Backward delta from word-index 1 to 0 = -1, encoded as 19-bit signed.
        // b.ne -4 (bytes) -> 0x54FFFFE1
        assert_eq!(e.words()[1], 0x54FF_FFE1);
    }

    #[test]
    fn load_const64_decomposes_into_movz_movk() {
        let mut e = Emitter::new();
        e.load_const64(Reg::X0, 0xCAFE_BABE_DEAD_BEEFu64);
        // 4 instructions: movz then 3 movks for non-zero lanes.
        assert_eq!(e.words().len(), 4);
        // movz x0, #0xBEEF -> 0xD297DDE0
        assert_eq!(e.words()[0], 0xD297_DDE0);
        // movk x0, #0xDEAD, lsl #16 -> 0xF2BBD5A0
        assert_eq!(e.words()[1], 0xF2BB_D5A0);
        // movk x0, #0xBABE, lsl #32 -> 0xF2D757C0
        assert_eq!(e.words()[2], 0xF2D7_57C0);
        // movk x0, #0xCAFE, lsl #48 -> 0xF2F95FC0
        assert_eq!(e.words()[3], 0xF2F9_5FC0);
    }

    #[test]
    fn unbound_label_fails_finish() {
        let mut e = Emitter::new();
        let l = e.make_label();
        e.b(l);
        assert!(matches!(e.finish(), Err(FinishError::UnboundLabel(_))));
    }
}

//! Shared instruction representation. Decoder produces `Inst`s; emitter and
//! lifter consume them. Keep the surface small and total — we add variants
//! as we lift more opcodes.

#![allow(dead_code)]

/// x86_64 architectural register, 64-bit view. Sub-register access is
/// encoded by the operand size on the containing `Inst`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum GpReg {
    Rax = 0,
    Rcx = 1,
    Rdx = 2,
    Rbx = 3,
    Rsp = 4,
    Rbp = 5,
    Rsi = 6,
    Rdi = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
}

impl GpReg {
    pub fn from_index(i: u8) -> Option<Self> {
        if i < 16 {
            // SAFETY: `i` is in range and the enum is contiguous repr(u8).
            Some(unsafe { core::mem::transmute::<u8, GpReg>(i) })
        } else {
            None
        }
    }
}

/// Width of an integer operand in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpSize {
    B1 = 1,
    B2 = 2,
    B4 = 4,
    B8 = 8,
}

/// Memory operand: `[base + index*scale + disp]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mem {
    pub base: Option<GpReg>,
    pub index: Option<GpReg>,
    pub scale: u8, // 1, 2, 4, or 8
    pub disp: i32,
    pub size: OpSize,
    /// Segment override, if any. For amd64 user code we typically only see FS/GS.
    pub seg: Option<Seg>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seg {
    Fs,
    Gs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Reg(GpReg, OpSize),
    /// XMM register: 0..15. The `OpSize` carries the access width
    /// (B4 = SS scalar, B8 = SD scalar / MOVQ, B16 isn't a B-enum
    /// value — packed 128-bit moves represent themselves as a custom
    /// `MovdqaXmm` op rather than overloading the size field).
    XmmReg(u8, OpSize),
    Imm(i64, OpSize),
    Mem(Mem),
    /// RIP-relative memory: effective address = next_rip + disp.
    RipRel(i32, OpSize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cond {
    O,
    NO,
    B,
    NB,
    E,
    NE,
    BE,
    A,
    S,
    NS,
    P,
    NP,
    L,
    NL,
    LE,
    G,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    // Data movement
    Mov,
    Movzx,
    Movsx,
    Movsxd,
    Lea,
    Xchg,
    Push,
    Pop,
    Pushfq,
    Popfq,
    Cmov(Cond),
    // Arithmetic
    Add,
    Adc,
    Sub,
    Sbb,
    Inc,
    Dec,
    Neg,
    Mul,
    Imul,
    Div,
    Idiv,
    Cdq,
    Cqo,
    Cwde,
    // Bitwise / logic
    And,
    Or,
    Xor,
    Not,
    Test,
    Cmp,
    Shl,
    Shr,
    Sar,
    Rol,
    Ror,
    Rcl,
    Rcr,
    // Bit manipulation
    Bt,
    Bts,
    Btr,
    Btc,
    Bsf,
    Bsr,
    // Atomic / interlocked
    Xadd,
    Cmpxchg,
    // Set on condition
    Set(Cond),
    // Control flow
    Call,
    CallIndirect,
    Ret,
    RetImm,
    Jmp,
    JmpIndirect,
    Jcc(Cond),
    Leave,
    Enter,
    Int3,
    Int,
    Ud2,
    Hlt,
    Syscall,
    // Flag / direction
    Cld,
    Std,
    Clc,
    Stc,
    Cmc,
    // String (decode-only; we don't lift these for the e2e test path)
    Movs,
    Stos,
    Lods,
    Cmps,
    Scas,
    // Misc
    Nop,
    // SSE2 scalar moves emitted by compilers even in integer code
    MovqXmm,
    MovsdXmm,
    MovssXmm,
    /// 128-bit packed move (covers both MOVDQA aligned and MOVDQU
    /// unaligned — they share semantics on modern hardware).
    MovdqXmm,
    /// 128-bit packed bitwise XOR.
    PxorXmm,
    /// 128-bit packed bitwise AND.
    PandXmm,
    /// 128-bit packed bitwise OR.
    PorXmm,
    /// Scalar FP arithmetic. The `OpSize` carried on the operand
    /// distinguishes single (B4) from double (B8) precision.
    AddScalar,
    SubScalar,
    MulScalar,
    DivScalar,
    /// Decoder bailout — opcode recognised but not lifted yet. Stores the
    /// raw byte length so callers can advance the IP.
    Unhandled,
}

/// One decoded instruction. `len` is the byte length consumed in the guest.
#[derive(Debug, Clone)]
pub struct Inst {
    pub op: Op,
    pub operands: [Option<Operand>; 3],
    pub len: u8,
    /// Raw guest address of the first byte, set by the decoder caller.
    pub guest_rip: u64,
}

impl Inst {
    pub const fn empty(op: Op, guest_rip: u64, len: u8) -> Self {
        Self {
            op,
            operands: [None, None, None],
            len,
            guest_rip,
        }
    }
}

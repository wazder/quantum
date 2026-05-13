//! Basic-block translator.
//!
//! `translate` decodes a sequence of x86 instructions starting at a
//! given guest RIP, lifts each one through `Lifter`, and resolves intra-
//! block branches via the emitter's label/fixup machinery. Branch
//! targets that fall outside the decoded range fail loudly — callers
//! that want cross-block control flow should slice their input around
//! known basic-block boundaries.
//!
//! Termination is driven by an explicit set of terminator opcodes
//! supplied by the caller (`UD2`/`RET` for "stop here forever",
//! plus optionally `JMP`/`Jcc` once the dispatcher exists).

use alloc::vec::Vec;

use crate::decoder::Decoder;
use crate::emitter::{Emitter, FinishError, Label};
use crate::iform::{Inst, Op, Operand};
use crate::lifter::{Lifter, LifterError, cond_x86_to_a64};

#[derive(Debug)]
pub enum BlockError {
    Decode(crate::decoder::Error),
    Lift(LifterError),
    /// A Jcc/JMP rel target falls outside the decoded range.
    TargetOutOfBlock {
        branch_rip: u64,
        target_rip: u64,
    },
    /// A condition code has no AArch64 mapping (PF/NP).
    UnsupportedCondition,
    /// Operand shape didn't match what the op expected (decoder bug).
    BadOperand,
    Finish(FinishError),
}

impl From<crate::decoder::Error> for BlockError {
    fn from(e: crate::decoder::Error) -> Self {
        Self::Decode(e)
    }
}

impl From<LifterError> for BlockError {
    fn from(e: LifterError) -> Self {
        Self::Lift(e)
    }
}

impl From<FinishError> for BlockError {
    fn from(e: FinishError) -> Self {
        Self::Finish(e)
    }
}

pub struct Block {
    pub host_bytes: Vec<u8>,
    pub guest_len: usize,
}

/// Translate a sequence of guest instructions into AArch64 bytes.
///
/// `bytes` is read by the decoder; `start_rip` is the guest virtual
/// address of `bytes[0]`. `is_terminator` decides when to stop reading
/// — typically `|op| matches!(op, Op::Ud2 | Op::Ret)`.
pub fn translate(
    bytes: &[u8],
    start_rip: u64,
    is_terminator: impl Fn(&Op) -> bool,
) -> Result<Block, BlockError> {
    // Pass 1: decode every instruction up to and including the
    // terminator.
    let mut insts: Vec<Inst> = Vec::new();
    let mut decoder = Decoder::new(bytes, start_rip);
    loop {
        let inst = decoder.next()?;
        let terminate = is_terminator(&inst.op);
        insts.push(inst);
        if terminate || decoder.remaining() == 0 {
            break;
        }
    }
    let guest_len = decoder.pos();

    // Pass 2: emit AArch64 bytes. Pre-allocate one label per decoded
    // instruction so intra-block branches can name their target by
    // guest RIP.
    let mut emitter = Emitter::new();
    let mut labels: Vec<(u64, Label)> = Vec::with_capacity(insts.len());
    for inst in &insts {
        labels.push((inst.guest_rip, emitter.make_label()));
    }
    let find_label =
        |rip: u64| -> Option<Label> { labels.iter().find(|(r, _)| *r == rip).map(|(_, l)| *l) };

    for (i, inst) in insts.iter().enumerate() {
        emitter.bind(labels[i].1);

        match inst.op {
            Op::Jcc(cond) => {
                let rel = match inst.operands[0] {
                    Some(Operand::Imm(rel, _)) => rel,
                    _ => return Err(BlockError::BadOperand),
                };
                let target_rip = inst
                    .guest_rip
                    .wrapping_add(inst.len as u64)
                    .wrapping_add(rel as u64);
                let target = find_label(target_rip).ok_or(BlockError::TargetOutOfBlock {
                    branch_rip: inst.guest_rip,
                    target_rip,
                })?;
                let a64_cond = cond_x86_to_a64(cond).ok_or(BlockError::UnsupportedCondition)?;
                emitter.b_cond(a64_cond, target);
            }
            Op::Jmp => {
                let rel = match inst.operands[0] {
                    Some(Operand::Imm(rel, _)) => rel,
                    _ => return Err(BlockError::BadOperand),
                };
                let target_rip = inst
                    .guest_rip
                    .wrapping_add(inst.len as u64)
                    .wrapping_add(rel as u64);
                let target = find_label(target_rip).ok_or(BlockError::TargetOutOfBlock {
                    branch_rip: inst.guest_rip,
                    target_rip,
                })?;
                emitter.b(target);
            }
            _ => {
                Lifter::new(&mut emitter).lift(inst)?;
            }
        }
    }

    emitter.finish()?;
    Ok(Block {
        host_bytes: emitter.bytes(),
        guest_len,
    })
}

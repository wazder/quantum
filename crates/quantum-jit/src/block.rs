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
    /// Lift with location info: which guest RIP, and the offending op's
    /// raw bytes (first 16 of the instruction).
    LiftAt {
        rip: u64,
        op: Op,
        bytes: alloc::vec::Vec<u8>,
        err: LifterError,
    },
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

/// Detect a Steam-DRM `int3; jmp -3` anti-debug trap at the start of
/// the decoded instruction stream and return the RIP that "the
/// debugger" would resume at (i.e., immediately past the trap pair).
fn detect_drm_int3_trap(insts: &[Inst]) -> Option<u64> {
    if insts.len() < 2 {
        return None;
    }
    let int3 = &insts[0];
    let jmp = &insts[1];
    if !matches!(int3.op, Op::Int3) {
        return None;
    }
    if !matches!(jmp.op, Op::Jmp) {
        return None;
    }
    let rel = match jmp.operands[0]? {
        Operand::Imm(rel, _) => rel,
        _ => return None,
    };
    let jmp_end = jmp.guest_rip.wrapping_add(jmp.len as u64);
    let target = jmp_end.wrapping_add(rel as u64);
    if target == int3.guest_rip {
        // Standard pattern: jump-back to the int3 itself. Skip past both.
        Some(jmp_end)
    } else {
        None
    }
}

/// Sentinel value the dispatcher recognises as "guest hit UD2 / stop".
/// Must match `quantum_runtime::dispatcher::STOP_SENTINEL`. Re-declared
/// here to keep quantum-jit free of a runtime dependency.
pub const STOP_SENTINEL: u64 = 0xDEAD_DEAD_DEAD_DEAD;

/// Guest ISA mode for translation. PE32+ images are `Long`; legacy
/// 32-bit PE32 images are `Legacy32`. The decoder uses different
/// prefix and default-operand-size rules between the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsaMode {
    Long,
    Legacy32,
}

/// Translate one basic block in dispatcher mode.
///
/// "Basic block" here means: instructions starting at `start_rip` and
/// running until the first control-flow op (JMP, Jcc, RET, UD2). On
/// exit the block writes the next guest RIP to X0 and returns to the
/// dispatcher (a host RET). The dispatcher then looks up the next RIP
/// in its `BlockMap` and jumps in (or translates first on miss).
///
/// Compared to `translate_with_stack`, this:
///   * Stops at the *first* control-flow op rather than running through
///     an entire user-supplied terminator set.
///   * Emits dispatcher exits (`mov x0, <next_rip>; ret`) for every
///     terminator instead of host RETs and intra-block labels.
///   * Supports out-of-block JMP/Jcc targets natively.
pub fn translate_for_dispatcher(
    bytes: &[u8],
    start_rip: u64,
    mode: IsaMode,
) -> Result<Block, BlockError> {
    use crate::emitter::Reg;

    let mut decoder = match mode {
        IsaMode::Long => Decoder::new(bytes, start_rip),
        IsaMode::Legacy32 => Decoder::new_legacy32(bytes, start_rip),
    };
    let mut insts: Vec<Inst> = Vec::new();

    loop {
        let inst = decoder.next()?;
        let is_terminator = matches!(
            inst.op,
            Op::Jmp | Op::Jcc(_) | Op::Ret | Op::RetImm | Op::Ud2 | Op::JmpIndirect | Op::Call
        );
        insts.push(inst);
        if is_terminator || decoder.remaining() == 0 {
            break;
        }
    }
    let guest_len = decoder.pos();

    let mut emitter = Emitter::new();

    // (We used to peephole the Steam DRM `int3; jmp -3` trap into a no-op
    // that skipped past both instructions. That was wrong when a DRM
    // stub dynamically registers an UnhandledExceptionFilter via
    // GetProcAddress + SetUnhandledExceptionFilter — Sekiro does this —
    // because the filter never got a chance to set up the post-trap
    // stack state. The detector helper stays for future opt-in use;
    // by default we let BRK fire so the SEH dispatcher in quantum-cli
    // routes through the registered filter, which is what Windows would
    // do.
    let _ = detect_drm_int3_trap(&insts);

    // ---- Dispatcher prologue ----
    // Save host callee-saved regs we touch:
    //   X19 (guest RSP), X24 (gs_base), X25 (fs_base), X28 (ctx ptr),
    //   X29 (FP), X30 (LR).
    // Then capture the AAPCS64 arg0 (X0 = *GuestContext) into X28 and
    // reload all 16 guest GPRs + gs_base + fs_base from ctx.
    emitter.stp64_pre(Reg::X29, Reg::X30, Reg::SP, -16);
    emitter.stp64_pre(Reg::x(19), Reg::x(28), Reg::SP, -16);
    emitter.stp64_pre(Reg::x(24), Reg::x(25), Reg::SP, -16);
    emitter.mov64(Reg::x(28), Reg::X0);
    emit_ctx_to_regs(&mut emitter);
    // gs_base / fs_base sit just past flags in GuestContext (offsets
    // 144 / 152). User code never writes to them so the epilogue
    // doesn't spill back.
    emitter.ldr64(Reg::x(24), Reg::x(28), 144);
    emitter.ldr64(Reg::x(25), Reg::x(28), 152);

    // ---- Body ----
    let last = insts.len() - 1;
    for inst in &insts[..last] {
        if let Err(e) = Lifter::new(&mut emitter).lift(inst) {
            let inst_off = inst.guest_rip.wrapping_sub(start_rip) as usize;
            let raw = bytes
                .get(inst_off..inst_off + inst.len as usize)
                .unwrap_or(&[])
                .to_vec();
            return Err(BlockError::LiftAt {
                rip: inst.guest_rip,
                op: inst.op,
                bytes: raw,
                err: e,
            });
        }
    }

    // ---- Terminator ----
    let term = &insts[last];
    match term.op {
        Op::Ud2 => emit_epilogue_const_rip(&mut emitter, STOP_SENTINEL),
        Op::RetImm => {
            // Pop return addr, then pop imm16 bytes from caller stack.
            let extra = match term.operands[0] {
                Some(Operand::Imm(imm, _)) => imm as u32,
                _ => return Err(BlockError::BadOperand),
            };
            emitter.ldr64(Reg::X16, Reg::x(19), 0);
            emitter.add64_imm(Reg::x(19), Reg::x(19), 8 + extra);
            emit_regs_to_ctx(&mut emitter);
            emitter.mov64(Reg::X0, Reg::X16);
            emit_host_epilogue(&mut emitter);
        }
        Op::Ret => {
            // Pop guest stack into X16, advance X19, then dispatcher exit
            // with X16 as the next RIP.
            emitter.ldr64(Reg::X16, Reg::x(19), 0);
            emitter.add64_imm(Reg::x(19), Reg::x(19), 8);
            emit_regs_to_ctx(&mut emitter);
            emitter.mov64(Reg::X0, Reg::X16);
            emit_host_epilogue(&mut emitter);
        }
        Op::Jmp => {
            let rel = match term.operands[0] {
                Some(Operand::Imm(rel, _)) => rel,
                _ => return Err(BlockError::BadOperand),
            };
            let target = term
                .guest_rip
                .wrapping_add(term.len as u64)
                .wrapping_add(rel as u64);
            emit_epilogue_const_rip(&mut emitter, target);
        }
        Op::Call => {
            // Direct CALL rel32: push return address on guest stack and
            // dispatcher-exit with the call target as next_rip.
            //   sub  x19, x19, #8
            //   load_const64 x16, <return_addr>
            //   str  x16, [x19]
            //   (then standard epilogue with next_rip = target)
            let rel = match term.operands[0] {
                Some(Operand::Imm(rel, _)) => rel,
                _ => return Err(BlockError::BadOperand),
            };
            let target = term
                .guest_rip
                .wrapping_add(term.len as u64)
                .wrapping_add(rel as u64);
            let return_addr = term.guest_rip.wrapping_add(term.len as u64);
            use crate::emitter::Reg;
            emitter.sub64_imm(Reg::x(19), Reg::x(19), 8);
            emitter.load_const64(Reg::X16, return_addr);
            emitter.str64(Reg::X16, Reg::x(19), 0);
            emit_epilogue_const_rip(&mut emitter, target);
        }
        Op::Jcc(cond) => {
            let rel = match term.operands[0] {
                Some(Operand::Imm(rel, _)) => rel,
                _ => return Err(BlockError::BadOperand),
            };
            let taken_rip = term
                .guest_rip
                .wrapping_add(term.len as u64)
                .wrapping_add(rel as u64);
            let fallthrough_rip = term.guest_rip.wrapping_add(term.len as u64);
            let a64_cond = cond_x86_to_a64(cond).ok_or(BlockError::UnsupportedCondition)?;
            let taken_label = emitter.make_label();
            emitter.b_cond(a64_cond, taken_label);
            // Fallthrough side.
            emit_epilogue_const_rip(&mut emitter, fallthrough_rip);
            // Taken side.
            emitter.bind(taken_label);
            emit_epilogue_const_rip(&mut emitter, taken_rip);
        }
        Op::JmpIndirect => {
            // Resolve the indirect target into X16 and use it as next_rip.
            //   Operand::Reg(r)         -> X16 = host_reg(r)
            //   Operand::Mem(_) | RipRel -> X16 = effective addr; X16 = *X16
            let target = term.operands[0].ok_or(BlockError::BadOperand)?;
            match target {
                Operand::Reg(r, _) => {
                    let hr = crate::lifter::host_reg(r);
                    emitter.mov64(Reg::X16, hr);
                }
                Operand::Mem(_) | Operand::RipRel(_, _) => {
                    // Build the effective address in X16 via a tiny lifter
                    // (re-using addr_into_xtmp), then dereference it.
                    let leftover = {
                        let mut lif = Lifter::new(&mut emitter);
                        lif.addr_into_xtmp(&target, term, Reg::X16)?
                    };
                    emitter.ldr64(Reg::X16, Reg::X16, leftover);
                }
                _ => return Err(BlockError::BadOperand),
            }
            emit_regs_to_ctx(&mut emitter);
            emitter.mov64(Reg::X0, Reg::X16);
            emit_host_epilogue(&mut emitter);
        }
        _ => {
            // No terminator decoded — bytes ran out. Stop the
            // dispatcher cleanly.
            emit_epilogue_const_rip(&mut emitter, STOP_SENTINEL);
        }
    }

    emitter.finish()?;
    Ok(Block {
        host_bytes: emitter.bytes(),
        guest_len,
    })
}

/// Load guest GPRs from `[X28 + offset]` into their pinned host regs.
/// Offsets match `GuestContext::gprs[idx] * 8`.
fn emit_ctx_to_regs(emitter: &mut Emitter) {
    use crate::emitter::Reg;
    let ctx = Reg::x(28);
    emitter.ldr64(Reg::X0, ctx, 0); // RAX
    emitter.ldr64(Reg::X1, ctx, 8); // RCX
    emitter.ldr64(Reg::X2, ctx, 16); // RDX
    emitter.ldr64(Reg::X3, ctx, 24); // RBX
    emitter.ldr64(Reg::x(19), ctx, 32); // RSP
    emitter.ldr64(Reg::x(5), ctx, 40); // RBP
    emitter.ldr64(Reg::x(6), ctx, 48); // RSI
    emitter.ldr64(Reg::x(7), ctx, 56); // RDI
    emitter.ldr64(Reg::x(8), ctx, 64); // R8
    emitter.ldr64(Reg::x(9), ctx, 72); // R9
    emitter.ldr64(Reg::x(10), ctx, 80); // R10
    emitter.ldr64(Reg::x(11), ctx, 88); // R11
    emitter.ldr64(Reg::x(12), ctx, 96); // R12
    emitter.ldr64(Reg::x(13), ctx, 104); // R13
    emitter.ldr64(Reg::x(14), ctx, 112); // R14
    emitter.ldr64(Reg::x(15), ctx, 120); // R15
}

/// Inverse of `emit_ctx_to_regs`: spill pinned host regs back to ctx.
fn emit_regs_to_ctx(emitter: &mut Emitter) {
    use crate::emitter::Reg;
    let ctx = Reg::x(28);
    emitter.str64(Reg::X0, ctx, 0);
    emitter.str64(Reg::X1, ctx, 8);
    emitter.str64(Reg::X2, ctx, 16);
    emitter.str64(Reg::X3, ctx, 24);
    emitter.str64(Reg::x(19), ctx, 32);
    emitter.str64(Reg::x(5), ctx, 40);
    emitter.str64(Reg::x(6), ctx, 48);
    emitter.str64(Reg::x(7), ctx, 56);
    emitter.str64(Reg::x(8), ctx, 64);
    emitter.str64(Reg::x(9), ctx, 72);
    emitter.str64(Reg::x(10), ctx, 80);
    emitter.str64(Reg::x(11), ctx, 88);
    emitter.str64(Reg::x(12), ctx, 96);
    emitter.str64(Reg::x(13), ctx, 104);
    emitter.str64(Reg::x(14), ctx, 112);
    emitter.str64(Reg::x(15), ctx, 120);
}

/// Common epilogue tail: pop the saved host regs and RET. X0 must be
/// pre-loaded with the next-block guest RIP.
fn emit_host_epilogue(emitter: &mut Emitter) {
    use crate::emitter::Reg;
    emitter.ldp64_post(Reg::x(24), Reg::x(25), Reg::SP, 16);
    emitter.ldp64_post(Reg::x(19), Reg::x(28), Reg::SP, 16);
    emitter.ldp64_post(Reg::X29, Reg::X30, Reg::SP, 16);
    emitter.ret();
}

/// Dispatcher exit with a constant next-block RIP. Spills regs, sets
/// X0, and tails the host epilogue.
fn emit_epilogue_const_rip(emitter: &mut Emitter, next_rip: u64) {
    use crate::emitter::Reg;
    emit_regs_to_ctx(emitter);
    emitter.load_const64(Reg::X0, next_rip);
    emit_host_epilogue(emitter);
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
    translate_with_stack(bytes, start_rip, None, is_terminator)
}

/// Like `translate`, but also emits a prologue that:
///   * saves the host's `X19` (callee-saved) on the host stack
///   * loads `stack_top` into `X19` so the guest's pinned RSP points at
///     a real guest stack region
///
/// Pass `Some(stack_top)` when the block contains PUSH/POP or any other
/// op that touches RSP. The host's X19 is restored if the lifted block
/// emits a RET; blocks that exit via ExitProcess longjmp don't reach
/// the restore (and don't need it — the surrounding setjmp restores
/// callee-saved regs).
pub fn translate_with_stack(
    bytes: &[u8],
    start_rip: u64,
    stack_top: Option<u64>,
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

    // Optional guest-stack prologue: save host X19, then load
    // stack_top into X19 so the lifter's PUSH/POP find a real stack.
    // X20 is paired purely to keep the stack 16-byte aligned.
    if let Some(top) = stack_top {
        emitter.stp64_pre(
            crate::emitter::Reg::x(19),
            crate::emitter::Reg::x(20),
            crate::emitter::Reg::SP,
            -16,
        );
        emitter.load_const64(crate::emitter::Reg::x(19), top);
    }
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

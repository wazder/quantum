//! Cross-block control flow dispatcher.
//!
//! The current `block::translate` is single-block: the lifted code
//! ends in a host `RET` that returns to the *Rust* caller. That works
//! for tests that wrap the JIT'd block as a function, but a real
//! guest is a graph of basic blocks reached via JMP/Jcc/RET — and
//! every one of those branch targets is some other block we may not
//! have translated yet.
//!
//! The dispatcher inverts the model:
//!
//!   * Every translated block ends in `mov x0, <next_guest_rip>; ret`.
//!     The "next RIP" is whichever branch target the block's terminator
//!     produces (JMP rel target, the fallthrough or taken side of a
//!     Jcc, the guest stack value for RET, …).
//!   * The `Dispatcher` holds a `BlockMap` (guest RIP → host code
//!     pointer). On each block exit, it reads the returned RIP, looks
//!     it up, translates on miss, and jumps in again.
//!   * A reserved sentinel value (`STOP_SENTINEL`) means "guest hit
//!     UD2 / we're done" — the dispatcher loop returns to the caller.
//!
//! Block chaining (patching one block's exit to branch directly to
//! another translated block) is a separate, later optimisation. With
//! the dispatcher alone, every block boundary costs one round-trip
//! through Rust — slow but correct.

use alloc::collections::BTreeMap;
use core::ptr::NonNull;

use quantum_core::Result;

use crate::codecache::CodeCache;

/// Returned in X0 when a block terminator is `UD2` (or any other
/// "stop forever" form). The dispatcher loop exits when it sees this
/// value. Chosen for being unlikely to collide with a real guest RIP.
pub const STOP_SENTINEL: u64 = 0xDEAD_DEAD_DEAD_DEAD;

/// Persistent guest register state across dispatcher round-trips.
///
/// AArch64 X0..X15 are caller-saved at the AAPCS64 level, so the
/// moment Rust runs (between block invocations) it can clobber them.
/// The dispatcher therefore can't keep guest GPRs live in those host
/// regs while Rust is on top of the stack — we have to spill on every
/// block exit and reload on every block entry.
///
/// Layout matches the x86_64 GPR encoding order so the block prologue
/// can index `ctx.gprs[reg]` with the same number the decoder produces:
/// `[RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8..R15]`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct GuestContext {
    /// 16 general-purpose registers indexed by x86 GpReg ordinal.
    pub gprs: [u64; 16],
    /// Last-known guest RIP. Block exit code writes the next RIP here
    /// before returning to the dispatcher.
    pub rip: u64,
    /// EFLAGS image (only NZCV is currently meaningful).
    pub flags: u64,
    /// Effective base of `gs:[…]` accesses. On Win64 this is the
    /// guest's TEB. The lifter adds `gs_base + disp` for any memory
    /// operand whose segment override is GS.
    pub gs_base: u64,
    /// Effective base of `fs:[…]` accesses. Win32 had this point at
    /// the TIB; Win64 leaves it free for user code. Most modern guests
    /// don't read fs; we still carry it for completeness.
    pub fs_base: u64,
}

/// Call a JIT'd block with the supplied `GuestContext`. The block
/// reloads guest GPRs from `ctx` on entry, runs, spills back to `ctx`
/// on exit, and returns the next guest RIP.
///
/// # Safety
/// `host_code` must point at executable AArch64 code emitted by
/// `block::translate_for_dispatcher`; the prologue/epilogue contract
/// is what makes this round-trip well-defined.
pub unsafe fn invoke_block_with_ctx(host_code: NonNull<u8>, ctx: &mut GuestContext) -> u64 {
    let f: extern "C" fn(*mut GuestContext) -> u64 =
        unsafe { core::mem::transmute(host_code.as_ptr()) };
    f(ctx)
}

pub struct Dispatcher {
    pub code_cache: CodeCache,
    pub block_map: BTreeMap<u64, NonNull<u8>>,
}

// SAFETY: the dispatcher owns its code cache and pointers within it.
// The `NonNull<u8>` values are never dereferenced except through host
// indirect-call instructions in the JIT execution path.
unsafe impl Send for Dispatcher {}

impl Dispatcher {
    pub fn new(cache_size: usize) -> Result<Self> {
        Ok(Self {
            code_cache: CodeCache::new(cache_size)?,
            block_map: BTreeMap::new(),
        })
    }

    pub fn lookup(&self, guest_rip: u64) -> Option<NonNull<u8>> {
        self.block_map.get(&guest_rip).copied()
    }

    pub fn install(&mut self, guest_rip: u64, host_bytes: &[u8]) -> Result<NonNull<u8>> {
        let ptr = self.code_cache.install(host_bytes)?;
        self.block_map.insert(guest_rip, ptr);
        Ok(ptr)
    }

    /// Number of cached blocks.
    pub fn block_count(&self) -> usize {
        self.block_map.len()
    }
}

/// Call a JIT'd block once and capture the guest RIP it requested next.
///
/// The block's host code must end with `mov x0, <next_rip>; ret`, so a
/// plain `extern "C" fn() -> u64` correctly captures the value.
///
/// # Safety
/// `host_code` must point at executable, properly aligned AArch64 code
/// that ends in a `RET` and respects the AAPCS64 register-preservation
/// contract for any non-trivial registers it uses (the block translator
/// arranges this).
pub unsafe fn invoke_block(host_code: NonNull<u8>) -> u64 {
    // SAFETY: caller upholds that host_code is a valid `extern "C"`
    // function. `transmute` is the standard way to call dynamically
    // generated code from Rust.
    let f: extern "C" fn() -> u64 = unsafe { core::mem::transmute(host_code.as_ptr()) };
    f()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthesise a tiny block: `mov x0, #0xCAFE; ret`. Validates that
    /// the dispatcher invocation path correctly captures the value the
    /// block writes to X0.
    #[test]
    fn invokes_a_block_and_reads_x0() {
        // movz x0, #0xCAFE -> sf=1, opc=10, hw=00, imm16=0xCAFE, Rd=0
        let movz = 0xD280_0000u32 | (0xCAFEu32 << 5);
        let ret = 0xD65F_03C0u32;
        let mut bytes = [0u8; 8];
        bytes[0..4].copy_from_slice(&movz.to_le_bytes());
        bytes[4..8].copy_from_slice(&ret.to_le_bytes());

        let mut disp = Dispatcher::new(4096).expect("dispatcher");
        let ptr = disp.install(0x1000, &bytes).expect("install");
        assert_eq!(disp.block_count(), 1);
        assert!(disp.lookup(0x1000).is_some());

        // SAFETY: synthesized block is a leaf `extern "C" fn() -> u64`.
        let got = unsafe { invoke_block(ptr) };
        assert_eq!(got, 0xCAFE);
    }
}

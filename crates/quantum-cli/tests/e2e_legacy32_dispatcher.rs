//! E2E: minimal 32-bit (legacy) JIT pipeline.
//!
//! Translates a hand-assembled x86 32-bit code stream
//!   `mov eax, 42 ; ud2`
//! using `IsaMode::Legacy32`, runs it through the Dispatcher, and
//! asserts the guest EAX (== ctx.gprs[0]) is 42 when the dispatcher
//! returns.
//!
//! The Legacy32 path needs to:
//!   * decode `B8 2A 00 00 00` as MOV r32, imm32 even without REX
//!   * decode `0F 0B` as UD2 (terminator → block writes STOP_SENTINEL
//!     and returns)
//!   * lift both into AArch64 using the same W-register width semantics
//!     the 64-bit pipeline already uses for `OpSize::B4` operands.

use core::ptr::NonNull;

use quantum_jit::block::{self, IsaMode};
use quantum_runtime::{Dispatcher, GuestContext, STOP_SENTINEL, invoke_block_with_ctx};

#[test]
fn legacy32_mov_eax_42_then_ud2() {
    // x86 32-bit bytes:
    //   B8 2A 00 00 00   mov eax, 42
    //   0F 0B            ud2
    let bytes: &[u8] = &[0xB8, 0x2A, 0x00, 0x00, 0x00, 0x0F, 0x0B];

    let entry_eip: u64 = 0x0040_1000;
    let block = block::translate_for_dispatcher(bytes, entry_eip, IsaMode::Legacy32)
        .expect("translate legacy32 block");

    let disp = Dispatcher::new(4096).expect("dispatcher");
    let ptr: NonNull<u8> = disp.install(entry_eip, &block.host_bytes).expect("install");

    let mut ctx = GuestContext::default();
    // RSP doesn't matter for this program (no push/pop), but the
    // dispatcher prologue still spills/reloads it, so give it a sane
    // value to be safe.
    ctx.gprs[4] = 0x10_0000;

    // SAFETY: the block was emitted by `translate_for_dispatcher` and
    // respects the prologue/epilogue contract.
    let next_rip = unsafe { invoke_block_with_ctx(ptr, &mut ctx) };
    assert_eq!(
        next_rip, STOP_SENTINEL,
        "ud2 should terminate the dispatcher with STOP_SENTINEL"
    );
    // EAX is the low 32 bits of guest gprs[0] in our pinning.
    let eax = (ctx.gprs[0] as u32) as u64;
    assert_eq!(eax, 42, "guest EAX should hold the constant we moved");
}

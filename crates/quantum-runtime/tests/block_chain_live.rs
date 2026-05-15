//! Block-chaining live execution test. The unit test in
//! `dispatcher.rs` verifies the encoded B word is in the right
//! place after `patch_chain`; this one goes one step further and
//! actually *executes* a chained pair of blocks, asserting control
//! lands at the intended destination.
//!
//! Two synthesized blocks:
//!
//!   Block A (host bytes):
//!     mov x0, #0xAAAA           ; just so RAX has a sentinel value
//!     <patch_site> B +1         ; placeholder
//!     mov x0, #0xBBBB           ; cold path: overwrite to 0xBBBB
//!     ret                       ; ret to caller (X0 captured)
//!
//!   Block B (host bytes):
//!     mov x0, #0xCAFE           ; if reached, X0 = 0xCAFE
//!     ret
//!
//! Without patch: invoking A returns 0xBBBB (cold path runs).
//! After patch_chain(A_site, B_addr): invoking A *should* return
//! 0xCAFE — control jumped straight into B at the patched B.

use core::ptr::NonNull;
use quantum_runtime::Dispatcher;

fn movz_imm(rd: u32, imm16: u16) -> u32 {
    // MOVZ Xd, #imm16 (LSL #0): sf=1, opc=10, 100101=movz, hw=00, imm16, Rd.
    0xD280_0000_u32 | ((imm16 as u32) << 5) | (rd & 0x1F)
}

const RET_X30: u32 = 0xD65F_03C0;
const B_PLUS_1: u32 = 0x1400_0001;

#[test]
fn chain_patch_actually_jumps_to_target_block() {
    let disp = Dispatcher::new(8192).expect("dispatcher");

    // Block A: 5 instructions = 20 bytes. The B +1 placeholder is at
    // offset 4.
    let mut block_a = [0u8; 20];
    block_a[0..4].copy_from_slice(&movz_imm(0, 0xAAAA).to_le_bytes());
    block_a[4..8].copy_from_slice(&B_PLUS_1.to_le_bytes()); // patch site
    block_a[8..12].copy_from_slice(&movz_imm(0, 0xBBBB).to_le_bytes());
    block_a[12..16].copy_from_slice(&RET_X30.to_le_bytes());
    // 16..20 padding; alignment.
    block_a[16..20].copy_from_slice(&0xD503_201F_u32.to_le_bytes()); // NOP

    // Block B: 2 instructions = 8 bytes.
    let mut block_b = [0u8; 8];
    block_b[0..4].copy_from_slice(&movz_imm(0, 0xCAFE).to_le_bytes());
    block_b[4..8].copy_from_slice(&RET_X30.to_le_bytes());

    let ptr_a: NonNull<u8> = disp.install(0x1000, &block_a).expect("install A");
    let ptr_b: NonNull<u8> = disp.install(0x2000, &block_b).expect("install B");

    // Cold (unpatched) execution returns 0xBBBB.
    let f_a: extern "C" fn() -> u64 = unsafe { core::mem::transmute(ptr_a.as_ptr()) };
    assert_eq!(f_a(), 0xBBBB, "pre-patch A must run cold path");

    // Patch A's exit to land in B's start.
    let patch_site = unsafe { ptr_a.as_ptr().add(4) as *mut u32 };
    let ok = unsafe { disp.patch_chain(patch_site, ptr_b.as_ptr() as *const u8) };
    assert!(ok, "patch_chain must accept in-range target");

    // Post-patch execution should reach B's body and return 0xCAFE.
    let f_a2: extern "C" fn() -> u64 = unsafe { core::mem::transmute(ptr_a.as_ptr()) };
    let got = f_a2();
    assert_eq!(
        got, 0xCAFE,
        "patched A must chain to B; got 0x{got:04X}"
    );
}

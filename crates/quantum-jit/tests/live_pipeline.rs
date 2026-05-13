//! Live end-to-end pipeline test: x86 bytes → decoder → lifter → code
//! cache → execute. Validates the W^X flip and codesigning + JIT
//! entitlement plumbing.
//!
//! Each test assembles a short x86 sequence, runs the full pipeline,
//! transmutes the resulting code pointer to a host function and asserts
//! the observed return value (in RAX, pinned to X0) matches the x86
//! semantics computed in pure Rust.

use quantum_jit::decoder::Decoder;
use quantum_jit::emitter::Emitter;
use quantum_jit::lifter::Lifter;
use quantum_runtime::CodeCache;

/// Lift `bytes` as a sequence of x86 instructions (stops when bytes
/// runs out) into an `Emitter`. Returns the host bytes ready to install.
fn lift_all(bytes: &[u8]) -> Vec<u8> {
    let mut e = Emitter::new();
    let mut d = Decoder::new(bytes, 0);
    while d.remaining() > 0 {
        let inst = d.next().expect("decode");
        let mut l = Lifter::new(&mut e);
        l.lift(&inst).expect("lift");
    }
    e.finish().expect("finish");
    e.bytes()
}

fn run_returns_u64(bytes: &[u8]) -> u64 {
    let host_bytes = lift_all(bytes);
    let mut cache = CodeCache::new(4096).expect("cache");
    let p = cache.install(&host_bytes).expect("install");
    // SAFETY: the lifted code respects AAPCS64: it writes X0 with the
    // intended return value and returns to the caller via RET. No stack
    // setup is required because we don't spill.
    let f: extern "C" fn() -> u64 = unsafe { core::mem::transmute(p.as_ptr()) };
    f()
}

#[test]
fn mov_eax_42_then_ret_returns_42() {
    // mov eax, 42 ; ret
    let bytes = [0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3];
    assert_eq!(run_returns_u64(&bytes), 42);
}

#[test]
fn mov_rax_imm64_then_ret_returns_value() {
    // mov rax, 0xCAFEBABEu64 ; ret
    // 48 B8 BE BA FE CA 00 00 00 00 ; C3
    let bytes = [
        0x48, 0xB8, 0xBE, 0xBA, 0xFE, 0xCA, 0x00, 0x00, 0x00, 0x00, 0xC3,
    ];
    assert_eq!(run_returns_u64(&bytes), 0xCAFE_BABE);
}

#[test]
fn add_rax_rbx_sums_inputs() {
    // mov rax, 10 ; mov rbx, 32 ; add rax, rbx ; ret
    // 48 C7 C0 0A 00 00 00 ; 48 C7 C3 20 00 00 00 ; 48 01 D8 ; C3
    //
    // 48 C7 C0 .. is mov r/m64, imm32. The decoder handles this as group 11 /0.
    let bytes = [
        0x48, 0xC7, 0xC0, 0x0A, 0x00, 0x00, 0x00, // mov rax, 10
        0x48, 0xC7, 0xC3, 0x20, 0x00, 0x00, 0x00, // mov rbx, 32
        0x48, 0x01, 0xD8, // add rax, rbx
        0xC3, // ret
    ];
    assert_eq!(run_returns_u64(&bytes), 42);
}

#[test]
fn sub_rax_rbx_correct() {
    // mov rax, 100 ; mov rbx, 58 ; sub rax, rbx ; ret -> 42
    let bytes = [
        0x48, 0xC7, 0xC0, 0x64, 0x00, 0x00, 0x00,
        0x48, 0xC7, 0xC3, 0x3A, 0x00, 0x00, 0x00,
        0x48, 0x29, 0xD8, // sub rax, rbx
        0xC3,
    ];
    assert_eq!(run_returns_u64(&bytes), 42);
}

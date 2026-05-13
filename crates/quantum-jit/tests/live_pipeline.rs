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

static MEM_FIXTURE: u64 = 0x1122_3344_5566_7788;

#[test]
fn mov_rax_from_memory_via_rbx() {
    // mov rbx, &MEM_FIXTURE ; mov rax, [rbx] ; ret
    let addr = (&MEM_FIXTURE as *const u64) as u64;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x48, 0xBB]); // mov rbx, imm64
    bytes.extend_from_slice(&addr.to_le_bytes());
    bytes.extend_from_slice(&[0x48, 0x8B, 0x03]); // mov rax, [rbx]
    bytes.push(0xC3); // ret
    assert_eq!(run_returns_u64(&bytes), MEM_FIXTURE);
}

extern "C" fn host_double(x: u64) -> u64 {
    x * 2
}

static mut HOST_THUNK_SLOT: u64 = 0;

#[test]
fn call_indirect_through_iat_slot() {
    // SAFETY: written once before any concurrent reader.
    unsafe {
        HOST_THUNK_SLOT = host_double as *const () as u64;
    }
    let slot_ptr = core::ptr::addr_of!(HOST_THUNK_SLOT) as u64;

    // Layout we want lifted:
    //   mov rcx, 21          ; 7 bytes (REX.W mov r/m64, imm32 via group 11 /0)
    //   call qword ptr [rip + 0] ; 6 bytes (target is the next instruction)
    //   ret                  ; 1 byte
    //
    // For RIP-relative the decoder computes target = (call_guest_rip + call_len + disp).
    // We arrange `guest_rip` so the resolved target lands exactly on `slot_ptr`.
    //
    //   call instruction starts at byte 7 within `bytes`
    //   call has length 6 and disp=0
    //   target = (start + 7) + 6 + 0 = start + 13
    //   Set start = slot_ptr - 13 so target == slot_ptr.

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x48, 0xC7, 0xC1, 0x15, 0x00, 0x00, 0x00]); // mov rcx, 21
    bytes.extend_from_slice(&[0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]); // call [rip + 0]
    bytes.push(0xC3); // ret

    let start_rip = slot_ptr.wrapping_sub(13);

    let mut emitter = quantum_jit::emitter::Emitter::new();
    let mut decoder = quantum_jit::decoder::Decoder::new(&bytes, start_rip);
    while decoder.remaining() > 0 {
        let inst = decoder.next().expect("decode");
        quantum_jit::lifter::Lifter::new(&mut emitter)
            .lift(&inst)
            .expect("lift");
    }
    emitter.finish().expect("finish");

    let host_bytes = emitter.bytes();
    let mut cache = CodeCache::new(4096).expect("cache");
    let p = cache.install(&host_bytes).expect("install");
    let f: extern "C" fn() -> u64 = unsafe { core::mem::transmute(p.as_ptr()) };
    assert_eq!(f(), 42); // host_double(21) == 42
}

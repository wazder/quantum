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
        0x48, 0xC7, 0xC0, 0x64, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC3, 0x3A, 0x00, 0x00, 0x00, 0x48,
        0x29, 0xD8, // sub rax, rbx
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
fn and_or_test_setnz_movzx_chain() {
    // mov eax, 0x100       ; B8 00 01 00 00
    // sub eax, 1            ; 83 E8 01           -> eax = 0xFF, ZF=0
    // test eax, eax         ; 85 C0              -> ZF=0 (eax!=0)
    // setnz cl              ; 0F 95 C1           -> cl = 1
    // movzx eax, cl         ; 0F B6 C1           -> eax = 1
    // ret                   ; C3
    let bytes = [
        0xB8, 0x00, 0x01, 0x00, 0x00, // mov eax, 0x100
        0x83, 0xE8, 0x01, // sub eax, 1
        0x85, 0xC0, // test eax, eax
        0x0F, 0x95, 0xC1, // setnz cl
        0x0F, 0xB6, 0xC1, // movzx eax, cl
        0xC3, // ret
    ];
    assert_eq!(run_returns_u64(&bytes), 1);
}

#[test]
fn and_or_inc_dec_chain() {
    // mov eax, 0xFF         ; B8 FF 00 00 00     -> eax = 0xFF
    // mov ebx, 0x0F         ; BB 0F 00 00 00     -> ebx = 0x0F
    // and eax, ebx          ; 21 D8              -> eax = 0x0F
    // inc eax               ; FF C0              -> eax = 0x10
    // dec ebx               ; FF CB              -> ebx = 0x0E
    // or eax, ebx           ; 09 D8              -> eax = 0x1E
    // ret                   ; C3
    let bytes = [
        0xB8, 0xFF, 0x00, 0x00, 0x00, // mov eax, 0xFF
        0xBB, 0x0F, 0x00, 0x00, 0x00, // mov ebx, 0x0F
        0x21, 0xD8, // and eax, ebx
        0xFF, 0xC0, // inc eax
        0xFF, 0xCB, // dec ebx
        0x09, 0xD8, // or eax, ebx
        0xC3,
    ];
    assert_eq!(run_returns_u64(&bytes), 0x1E);
}

#[test]
fn cmov_picks_branch_on_flag() {
    // mov eax, 11           ; B8 0B 00 00 00
    // mov ebx, 22           ; BB 16 00 00 00
    // mov ecx, 99           ; B9 63 00 00 00
    // cmp eax, ebx          ; 39 D8         -> eax < ebx, ZF=0, SF≠OF so signed-less
    // cmovl eax, ecx        ; 0F 4C C1     -> eax = ecx = 99
    // ret
    let bytes = [
        0xB8, 0x0B, 0x00, 0x00, 0x00, // mov eax, 11
        0xBB, 0x16, 0x00, 0x00, 0x00, // mov ebx, 22
        0xB9, 0x63, 0x00, 0x00, 0x00, // mov ecx, 99
        0x39, 0xD8, // cmp eax, ebx (32-bit; CMP eax,ebx encoding uses opcode 39 r/m,r)
        0x0F, 0x4C, 0xC1, // cmovl eax, ecx
        0xC3,
    ];
    assert_eq!(run_returns_u64(&bytes), 99);
}

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

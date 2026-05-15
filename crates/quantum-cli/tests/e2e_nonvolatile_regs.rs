//! Win64 non-volatile register preservation across a thunk call.
//!
//! Win64 guarantees RBX/RBP/RSI/RDI/R12-R15 survive a CALL. Our JIT
//! pins those to AArch64 caller-saved registers (X3/X5/X6/X7/X12-X15),
//! so without explicit save/restore around the host BLR a Rust thunk
//! clobbers them — silently corrupting guest state in a way that no
//! existing test caught (dispatcher mode spills/reloads at block
//! boundaries, masking the bug across blocks but NOT within a block).
//!
//! This guest exercises the in-block case:
//!
//!     mov ebx, 0xCAFE                       ; RBX sentinel (pinned X3)
//!     call qword ptr [rip + iat_getpid]     ; clobbers caller-saved
//!     mov ecx, ebx                          ; ECX = RBX (must survive)
//!     call qword ptr [rip + iat_exit]       ; ExitProcess(RBX)
//!     ud2
//!
//! If preservation works → exit code 0xCAFE. If RBX is clobbered the
//! exit code is whatever GetCurrentProcessId left in X3 (a PID, or
//! scratch garbage) — never 0xCAFE.

use quantum_jit::decoder::Decoder;
use quantum_jit::emitter::Emitter;
use quantum_jit::iform::Op;
use quantum_jit::lifter::Lifter;
use quantum_kernel32::process::run_with_exit_trap;
use quantum_kernel32::resolve;
use quantum_loader::{PeFile, apply_relocations, imports, load};
use quantum_runtime::{CodeCache, GuestStack, MachVmManager};

fn build_pe() -> Vec<u8> {
    let mut bytes = vec![0u8; 0xC00];

    bytes[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes());
    bytes[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

    let pe_off = 0x80usize;
    bytes[pe_off..pe_off + 4].copy_from_slice(&0x0000_4550u32.to_le_bytes());

    let coff = pe_off + 4;
    bytes[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    bytes[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
    bytes[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
    bytes[coff + 18..coff + 20].copy_from_slice(&0x22u16.to_le_bytes());

    let opt = coff + 20;
    bytes[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
    bytes[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    bytes[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes());
    bytes[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
    bytes[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
    bytes[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

    // IMPORT dir → RVA 0x2010, size 40 (one descriptor + terminator).
    let dd1 = opt + 112 + 8;
    bytes[dd1..dd1 + 4].copy_from_slice(&0x2010u32.to_le_bytes());
    bytes[dd1 + 4..dd1 + 8].copy_from_slice(&40u32.to_le_bytes());

    let sh1 = opt + 240;
    bytes[sh1..sh1 + 5].copy_from_slice(b".text");
    bytes[sh1 + 8..sh1 + 12].copy_from_slice(&0x100u32.to_le_bytes());
    bytes[sh1 + 12..sh1 + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[sh1 + 16..sh1 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[sh1 + 20..sh1 + 24].copy_from_slice(&0x400u32.to_le_bytes());
    bytes[sh1 + 36..sh1 + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    let sh2 = sh1 + 40;
    bytes[sh2..sh2 + 6].copy_from_slice(b".idata");
    // vsize 0x200 so RVA 0x2000..0x2200 (incl. the spaced-out
    // hint/name + DLL-name table up to 0x2120) is all mapped.
    bytes[sh2 + 8..sh2 + 12].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[sh2 + 12..sh2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    bytes[sh2 + 16..sh2 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[sh2 + 20..sh2 + 24].copy_from_slice(&0x600u32.to_le_bytes());
    bytes[sh2 + 36..sh2 + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes());

    // .text:
    //   RVA 0x1000  bb fe ca 00 00       mov ebx, 0xCAFE             (5)
    //   RVA 0x1005  ff 15 <disp32>       call [rip + iat_getpid]     (6)
    //                  next 0x100B, target IAT[0]@0x2000, disp=0xFF5
    //   RVA 0x100B  89 d9                mov ecx, ebx                (2)
    //   RVA 0x100D  ff 15 <disp32>       call [rip + iat_exit]       (6)
    //                  next 0x1013, target IAT[1]@0x2008,
    //                  disp = 0x2008 - 0x1013 = 0xFF5
    //   RVA 0x1013  0f 0b                ud2                         (2)
    let t = 0x400usize;
    bytes[t..t + 5].copy_from_slice(&[0xBB, 0xFE, 0xCA, 0x00, 0x00]);
    bytes[t + 5..t + 11].copy_from_slice(&[0xFF, 0x15, 0xF5, 0x0F, 0x00, 0x00]);
    bytes[t + 11..t + 13].copy_from_slice(&[0x89, 0xD9]);
    bytes[t + 13..t + 19].copy_from_slice(&[0xFF, 0x15, 0xF5, 0x0F, 0x00, 0x00]);
    bytes[t + 19..t + 21].copy_from_slice(&[0x0F, 0x0B]);

    // .idata layout (RVA 0x2000 = file 0x600). Hint/name entries are
    // spaced 0x40 apart so "GetCurrentProcessId" (22 bytes incl. hint
    // + NUL) can't overrun into the next entry.
    //   IAT[0]  @0x2000 -> name @0x20A0  (GetCurrentProcessId)
    //   IAT[1]  @0x2008 -> name @0x20E0  (ExitProcess)
    //   descr   @0x2010 : ILT=0x2050 Name=0x2120 IAT=0x2000
    //   ILT[0]  @0x2050 -> 0x20A0 ; ILT[1] @0x2058 -> 0x20E0 ; term @0x2060
    let id = 0x600usize;
    bytes[id..id + 8].copy_from_slice(&0x20A0u64.to_le_bytes()); // IAT[0]
    bytes[id + 8..id + 16].copy_from_slice(&0x20E0u64.to_le_bytes()); // IAT[1]

    let desc = id + 0x10;
    bytes[desc..desc + 4].copy_from_slice(&0x2050u32.to_le_bytes()); // ILT
    bytes[desc + 12..desc + 16].copy_from_slice(&0x2120u32.to_le_bytes()); // Name
    bytes[desc + 16..desc + 20].copy_from_slice(&0x2000u32.to_le_bytes()); // IAT

    bytes[id + 0x50..id + 0x58].copy_from_slice(&0x20A0u64.to_le_bytes()); // ILT[0]
    bytes[id + 0x58..id + 0x60].copy_from_slice(&0x20E0u64.to_le_bytes()); // ILT[1]
    // ILT terminator at id+0x60 stays zero.

    bytes[id + 0xA0..id + 0xA2].copy_from_slice(&0u16.to_le_bytes()); // hint
    let n0 = b"GetCurrentProcessId\0";
    bytes[id + 0xA2..id + 0xA2 + n0.len()].copy_from_slice(n0);

    bytes[id + 0xE0..id + 0xE2].copy_from_slice(&0u16.to_le_bytes()); // hint
    let n1 = b"ExitProcess\0";
    bytes[id + 0xE2..id + 0xE2 + n1.len()].copy_from_slice(n1);

    let dll = b"KERNEL32.DLL\0";
    bytes[id + 0x120..id + 0x120 + dll.len()].copy_from_slice(dll);

    bytes
}

#[test]
fn rbx_survives_a_thunk_call() {
    let pe_bytes = build_pe();
    let pe = PeFile::parse(&pe_bytes).expect("parse");
    let mem = MachVmManager::new();
    let mut image = load(&pe, &mem).expect("load");
    apply_relocations(&mut image).expect("reloc");
    let imp = imports::parse(&image).expect("imports");
    imports::wire_iat(&mut image, &imp, resolve).expect("wire IAT");

    let stack = GuestStack::default_size().expect("stack");
    let entry_va = image.actual_base + image.entry_rva as u64;
    let entry_bytes: Vec<u8> = image
        .rva_to_slice(image.entry_rva, 64)
        .expect("entry bytes")
        .to_vec();

    let mut emitter = Emitter::new();
    // Prologue: load X19 (guest RSP) so the thunk's args-5..8 loads
    // and the non-volatile save/restore have a valid stack. Reserve
    // 0x40 below the top for the Win64 shadow space contract.
    let rsp = stack.top() - 0x40;
    emitter.load_const64(quantum_jit::emitter::Reg::x(19), rsp);

    let mut decoder = Decoder::new(&entry_bytes, entry_va);
    loop {
        let inst = decoder.next().expect("decode");
        Lifter::new(&mut emitter).lift(&inst).expect("lift");
        // The block has two CallIndirects that must NOT terminate
        // lifting; only UD2 / RET ends the flat block.
        if matches!(inst.op, Op::Ud2 | Op::Ret) {
            break;
        }
    }
    emitter.finish().expect("finish");

    let mut cache = CodeCache::new(8192).expect("cache");
    let entry_fn_ptr = cache.install(&emitter.bytes()).expect("install");
    let entry: extern "C" fn() = unsafe { core::mem::transmute(entry_fn_ptr.as_ptr()) };

    let exit_code = run_with_exit_trap(|| {
        entry();
    });

    assert_eq!(
        exit_code, 0xCAFE,
        "RBX (pinned X3) must survive the GetCurrentProcessId thunk; \
         got {exit_code:#X} — register preservation around BLR is broken"
    );
}

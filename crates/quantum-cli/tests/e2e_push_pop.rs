//! E2E: real PUSH/POP against a guest stack region.
//!
//! Guest program:
//!     mov  ecx, 7
//!     push rcx                  ; stack: [7]
//!     mov  ecx, 999             ; clobber to prove POP reads from stack
//!     pop  rcx                  ; rcx = 7
//!     call qword ptr [rip + iat_exit]
//!     ud2

use quantum_jit::block;
use quantum_jit::iform::Op;
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
    bytes[sh2 + 8..sh2 + 12].copy_from_slice(&0x100u32.to_le_bytes());
    bytes[sh2 + 12..sh2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    bytes[sh2 + 16..sh2 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[sh2 + 20..sh2 + 24].copy_from_slice(&0x600u32.to_le_bytes());
    bytes[sh2 + 36..sh2 + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes());

    // --- .text raw bytes ---
    //   RVA 0x1000  mov ecx, 7                  ; 5 bytes (B9 07 00 00 00)
    //   RVA 0x1005  push rcx                    ; 1 byte  (51)
    //   RVA 0x1006  mov ecx, 999                ; 5 bytes (B9 E7 03 00 00)
    //   RVA 0x100B  pop  rcx                    ; 1 byte  (59)
    //   RVA 0x100C  call qword ptr [rip + disp] ; 6 bytes  (target IAT @ 0x2000)
    //                                              disp = 0x2000 - 0x1012 = 0xFEE
    //   RVA 0x1012  ud2                          ; 2 bytes
    let text_raw = 0x400usize;
    let mut p = 0usize;
    bytes[text_raw + p..text_raw + p + 5].copy_from_slice(&[0xB9, 0x07, 0x00, 0x00, 0x00]);
    p += 5;
    bytes[text_raw + p] = 0x51;
    p += 1;
    bytes[text_raw + p..text_raw + p + 5].copy_from_slice(&[0xB9, 0xE7, 0x03, 0x00, 0x00]);
    p += 5;
    bytes[text_raw + p] = 0x59;
    p += 1;
    bytes[text_raw + p..text_raw + p + 6].copy_from_slice(&[0xFF, 0x15, 0xEE, 0x0F, 0x00, 0x00]);
    p += 6;
    bytes[text_raw + p..text_raw + p + 2].copy_from_slice(&[0x0F, 0x0B]);

    // .idata: same layout as the other e2e tests — one IAT slot for
    // ExitProcess, one descriptor, hint/name + DLL name.
    let idata_raw = 0x600usize;
    bytes[idata_raw..idata_raw + 8].copy_from_slice(&0x2060u64.to_le_bytes());

    let desc = idata_raw + 0x10;
    bytes[desc..desc + 4].copy_from_slice(&0x2040u32.to_le_bytes());
    bytes[desc + 12..desc + 16].copy_from_slice(&0x2080u32.to_le_bytes());
    bytes[desc + 16..desc + 20].copy_from_slice(&0x2000u32.to_le_bytes());

    bytes[idata_raw + 0x40..idata_raw + 0x48].copy_from_slice(&0x2060u64.to_le_bytes());

    bytes[idata_raw + 0x60..idata_raw + 0x62].copy_from_slice(&0u16.to_le_bytes());
    let en = b"ExitProcess\0";
    bytes[idata_raw + 0x62..idata_raw + 0x62 + en.len()].copy_from_slice(en);

    let dll = b"KERNEL32.DLL\0";
    bytes[idata_raw + 0x80..idata_raw + 0x80 + dll.len()].copy_from_slice(dll);

    bytes
}

#[test]
fn push_then_pop_round_trips_through_guest_stack() {
    let pe_bytes = build_pe();
    let pe = PeFile::parse(&pe_bytes).expect("parse");
    let mem = MachVmManager::new();
    let mut image = load(&pe, &mem).expect("load");
    apply_relocations(&mut image).expect("reloc");
    let imports = imports::parse(&image).expect("imports");
    imports::wire_iat(&mut image, &imports, resolve).expect("wire IAT");

    // Allocate a real guest stack region. The block translator will
    // emit a prologue that loads X19 (= guest RSP) with stack.top()
    // before running any PUSH/POP-bearing code.
    let stack = GuestStack::default_size().expect("guest stack");

    let entry_va = image.actual_base + image.entry_rva as u64;
    let entry_bytes: Vec<u8> = image
        .rva_to_slice(image.entry_rva, 32)
        .expect("entry bytes")
        .to_vec();

    // Reserve 0x40 below stack.top() so lift_call_indirect's
    // [X19+0x20..0x38] arg5..8 loads stay inside the mapped region
    // when the lifted block calls ExitProcess.
    let stack_top = stack.top() - 0x40;
    let block = block::translate_with_stack(&entry_bytes, entry_va, Some(stack_top), |op| {
        matches!(op, Op::Ud2 | Op::Ret)
    })
    .expect("translate block");

    let mut cache = CodeCache::new(8192).expect("cache");
    let entry_fn_ptr = cache.install(&block.host_bytes).expect("install");

    // SAFETY: see the e2e_exit_process test; ExitProcess longjmps out.
    let entry: extern "C" fn() = unsafe { core::mem::transmute(entry_fn_ptr.as_ptr()) };

    let exit_code = run_with_exit_trap(|| {
        entry();
    });

    assert_eq!(
        exit_code, 7,
        "expected POP to restore RCX to 7 after the intervening clobber"
    );
}

//! Register-operand CallIndirect — the lowest level shape of a C++
//! virtual method call. Pattern:
//!
//!     mov rax, qword ptr [rip + iat_exit]   ; load function pointer
//!     mov ecx, 42                            ; arg0 = 42
//!     call rax                               ; FF D0 — call through reg
//!     ud2
//!
//! Before Task 1 of the gece push'u, `addr_into_xtmp` returned
//! BadOperands for Operand::Reg, so this whole pattern faulted in
//! block translation. After the fix, `lift_call_indirect` handles
//! Operand::Reg by emitting `mov X16, host_reg(r)` and falling
//! through to the standard arg-marshal + BLR.

use quantum_jit::decoder::Decoder;
use quantum_jit::emitter::Emitter;
use quantum_jit::iform::Op;
use quantum_jit::lifter::Lifter;
use quantum_kernel32::process::run_with_exit_trap;
use quantum_kernel32::resolve;
use quantum_loader::{PeFile, apply_relocations, imports, load};
use quantum_runtime::{CodeCache, MachVmManager};

fn build_pe() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x800];

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

    // .text layout:
    //   RVA 0x1000  mov rax, qword ptr [rip + disp]    ; 7 bytes
    //                  next-rip = 0x1007, target = 0x2000 → disp = 0xFF9
    //                  encoding: 48 8B 05 + disp32
    //   RVA 0x1007  mov ecx, 42                        ; 5 bytes
    //                  encoding: B9 2A 00 00 00
    //   RVA 0x100C  call rax                           ; 2 bytes (FF D0)
    //   RVA 0x100E  ud2                                ; 2 bytes (0F 0B)
    let text_raw = 0x400usize;
    bytes[text_raw..text_raw + 7]
        .copy_from_slice(&[0x48, 0x8B, 0x05, 0xF9, 0x0F, 0x00, 0x00]);
    bytes[text_raw + 7..text_raw + 12]
        .copy_from_slice(&[0xB9, 0x2A, 0x00, 0x00, 0x00]);
    bytes[text_raw + 12..text_raw + 14].copy_from_slice(&[0xFF, 0xD0]);
    bytes[text_raw + 14..text_raw + 16].copy_from_slice(&[0x0F, 0x0B]);

    // .idata: single IAT slot for ExitProcess at RVA 0x2000.
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
fn register_indirect_call_through_iat_loaded_pointer() {
    let pe_bytes = build_pe();
    let pe = PeFile::parse(&pe_bytes).expect("parse");
    let mem = MachVmManager::new();
    let mut image = load(&pe, &mem).expect("load");
    apply_relocations(&mut image).expect("reloc");
    let imp = imports::parse(&image).expect("imports");
    imports::wire_iat(&mut image, &imp, resolve).expect("wire IAT");

    let entry_va = image.actual_base + image.entry_rva as u64;
    let entry_bytes: Vec<u8> = image
        .rva_to_slice(image.entry_rva, 32)
        .expect("entry bytes")
        .to_vec();

    let mut emitter = Emitter::new();
    let mut decoder = Decoder::new(&entry_bytes, entry_va);
    loop {
        let inst = decoder.next().expect("decode");
        let terminator = matches!(inst.op, Op::Ud2 | Op::Ret | Op::CallIndirect);
        Lifter::new(&mut emitter).lift(&inst).expect("lift");
        if terminator {
            break;
        }
    }
    emitter.finish().expect("finish");

    let mut cache = CodeCache::new(4096).expect("cache");
    let entry_fn_ptr = cache.install(&emitter.bytes()).expect("install");

    // SAFETY: lifted code does `call rax` where rax was just loaded
    // with the ExitProcess host pointer from the wired IAT; ExitProcess
    // longjmps out via the trap.
    let entry: extern "C" fn() = unsafe { core::mem::transmute(entry_fn_ptr.as_ptr()) };

    let exit_code = run_with_exit_trap(|| {
        entry();
    });

    assert_eq!(exit_code, 42, "ExitProcess(42) reached through `call rax`");
}

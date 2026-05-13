//! Multi-call e2e: a hand-assembled Win64 PE that calls WriteFile to
//! write a short message to a captured handle, then ExitProcess(0).
//!
//! Guest program:
//!     mov ecx, 1                      ; handle (we pretend stdout=1)
//!     lea rdx, [rip + msg]            ; lpBuffer
//!     mov r8d, MSG_LEN                ; nNumberOfBytesToWrite
//!     xor r9d, r9d                    ; lpNumberOfBytesWritten = NULL
//!     call qword ptr [rip + iat_write] ; WriteFile
//!     xor ecx, ecx                    ; exit code 0
//!     call qword ptr [rip + iat_exit] ; ExitProcess
//!     ud2

use quantum_jit::decoder::Decoder;
use quantum_jit::emitter::Emitter;
use quantum_jit::iform::Op;
use quantum_jit::lifter::Lifter;
use quantum_kernel32::process::run_with_exit_trap;
use quantum_kernel32::resolve;
use quantum_loader::{PeFile, apply_relocations, imports, load};
use quantum_runtime::{CodeCache, MachVmManager};

/// Build the Win64 PE described in the module comment. Layout:
///   .text  at RVA 0x1000 (file 0x400, raw 0x200)
///   .data  at RVA 0x2000 (file 0x600, raw 0x200) — message string
///   .idata at RVA 0x3000 (file 0x800, raw 0x400) — IAT + descriptors
fn build_pe(msg: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 0xC00];

    // DOS header
    bytes[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes());
    bytes[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

    // PE signature
    let pe_off = 0x80usize;
    bytes[pe_off..pe_off + 4].copy_from_slice(&0x0000_4550u32.to_le_bytes());

    // COFF header
    let coff = pe_off + 4;
    bytes[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    bytes[coff + 2..coff + 4].copy_from_slice(&3u16.to_le_bytes()); // 3 sections
    bytes[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
    bytes[coff + 18..coff + 20].copy_from_slice(&0x22u16.to_le_bytes());

    // Optional header (PE32+)
    let opt = coff + 20;
    bytes[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
    bytes[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    bytes[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[opt + 56..opt + 60].copy_from_slice(&0x4000u32.to_le_bytes()); // size of image
    bytes[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
    bytes[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
    bytes[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

    // Data directory [1] IMPORT: at RVA 0x3010, size = 60 (3 descriptors)
    let dd1 = opt + 112 + 8;
    bytes[dd1..dd1 + 4].copy_from_slice(&0x3010u32.to_le_bytes());
    bytes[dd1 + 4..dd1 + 8].copy_from_slice(&60u32.to_le_bytes());

    // Section header 1: .text
    let sh1 = opt + 240;
    bytes[sh1..sh1 + 5].copy_from_slice(b".text");
    bytes[sh1 + 8..sh1 + 12].copy_from_slice(&0x100u32.to_le_bytes());
    bytes[sh1 + 12..sh1 + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[sh1 + 16..sh1 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[sh1 + 20..sh1 + 24].copy_from_slice(&0x400u32.to_le_bytes());
    bytes[sh1 + 36..sh1 + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    // Section header 2: .data
    let sh2 = sh1 + 40;
    bytes[sh2..sh2 + 5].copy_from_slice(b".data");
    bytes[sh2 + 8..sh2 + 12].copy_from_slice(&0x100u32.to_le_bytes());
    bytes[sh2 + 12..sh2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    bytes[sh2 + 16..sh2 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[sh2 + 20..sh2 + 24].copy_from_slice(&0x600u32.to_le_bytes());
    bytes[sh2 + 36..sh2 + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes()); // INIT|R|W

    // Section header 3: .idata
    let sh3 = sh2 + 40;
    bytes[sh3..sh3 + 6].copy_from_slice(b".idata");
    bytes[sh3 + 8..sh3 + 12].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[sh3 + 12..sh3 + 16].copy_from_slice(&0x3000u32.to_le_bytes());
    bytes[sh3 + 16..sh3 + 20].copy_from_slice(&0x400u32.to_le_bytes());
    bytes[sh3 + 20..sh3 + 24].copy_from_slice(&0x800u32.to_le_bytes());
    bytes[sh3 + 36..sh3 + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes());

    // --- .text raw bytes at file 0x400 (mapped at RVA 0x1000) ---
    let text_raw = 0x400usize;
    let mut p = 0usize;

    // mov ecx, 1                ; 5 bytes
    bytes[text_raw + p..text_raw + p + 5].copy_from_slice(&[0xB9, 0x01, 0x00, 0x00, 0x00]);
    p += 5; // RVA now 0x1005

    // lea rdx, [rip + disp32]    ; 7 bytes (REX.W + 8D /reg=2 + ModRM rip-rel)
    //   instruction at RVA 0x1005, length 7, next at 0x100C.
    //   target = RVA 0x2000 (msg), so disp = 0x2000 - 0x100C = 0xFF4
    bytes[text_raw + p..text_raw + p + 7]
        .copy_from_slice(&[0x48, 0x8D, 0x15, 0xF4, 0x0F, 0x00, 0x00]);
    p += 7; // RVA now 0x100C

    // mov r8d, msg.len()          ; 7 bytes (REX.B + C7 /0 with imm32)
    bytes[text_raw + p..text_raw + p + 3].copy_from_slice(&[0x41, 0xC7, 0xC0]);
    bytes[text_raw + p + 3..text_raw + p + 7].copy_from_slice(&(msg.len() as u32).to_le_bytes());
    p += 7; // RVA now 0x1013

    // xor r9d, r9d                ; 3 bytes (REX.RB + 31 /reg=9, rm=9)
    //   31 C9 with REX.R+B: opcode 31 + ModRM 0xC9 (mod=11, reg=001, rm=001)
    //   With REX.R+B (0x45), reg field extended to 9 and rm to 9 -> r9d
    bytes[text_raw + p..text_raw + p + 3].copy_from_slice(&[0x45, 0x31, 0xC9]);
    p += 3; // RVA now 0x1016

    // call qword ptr [rip + disp32] -> WriteFile IAT slot at RVA 0x3000
    //   instruction at RVA 0x1016, length 6, next at 0x101C.
    //   target = RVA 0x3000, so disp = 0x3000 - 0x101C = 0x1FE4
    bytes[text_raw + p..text_raw + p + 6].copy_from_slice(&[0xFF, 0x15, 0xE4, 0x1F, 0x00, 0x00]);
    p += 6; // RVA now 0x101C

    // xor ecx, ecx                ; 2 bytes (31 C9)
    bytes[text_raw + p..text_raw + p + 2].copy_from_slice(&[0x31, 0xC9]);
    p += 2; // RVA now 0x101E

    // call qword ptr [rip + disp32] -> ExitProcess IAT slot at RVA 0x3008
    //   instruction at RVA 0x101E, length 6, next at 0x1024.
    //   target = RVA 0x3008, so disp = 0x3008 - 0x1024 = 0x1FE4
    bytes[text_raw + p..text_raw + p + 6].copy_from_slice(&[0xFF, 0x15, 0xE4, 0x1F, 0x00, 0x00]);
    p += 6; // RVA now 0x1024

    // ud2
    bytes[text_raw + p..text_raw + p + 2].copy_from_slice(&[0x0F, 0x0B]);

    // --- .data raw bytes at file 0x600 (mapped at RVA 0x2000) ---
    let data_raw = 0x600usize;
    bytes[data_raw..data_raw + msg.len()].copy_from_slice(msg);

    // --- .idata raw bytes at file 0x800 (mapped at RVA 0x3000) ---
    //
    //   RVA 0x3000: IAT[0] -> hint/name for WriteFile (placeholder; will
    //                          be overwritten by wire_iat)
    //   RVA 0x3008: IAT[1] -> hint/name for ExitProcess
    //   RVA 0x3010: IMAGE_IMPORT_DESCRIPTOR (20 bytes, KERNEL32.DLL)
    //   RVA 0x3024: descriptor terminator (20 bytes)
    //   RVA 0x3050: ILT[0] -> hint/name @ RVA 0x3080
    //   RVA 0x3058: ILT[1] -> hint/name @ RVA 0x3090
    //   RVA 0x3060: ILT terminator
    //   RVA 0x3080: u16 hint=0 + "WriteFile\0"
    //   RVA 0x3090: u16 hint=0 + "ExitProcess\0"
    //   RVA 0x30B0: "KERNEL32.DLL\0"
    let idata_raw = 0x800usize;
    bytes[idata_raw..idata_raw + 8].copy_from_slice(&0x3080u64.to_le_bytes()); // IAT[0]
    bytes[idata_raw + 8..idata_raw + 16].copy_from_slice(&0x3090u64.to_le_bytes()); // IAT[1]
    // IAT terminator at RVA 0x3010 — but that overlaps with the import
    // descriptor below. We end the IAT array with the implicit
    // boundary; wire_iat walks the import descriptor's ILT instead.

    // IMAGE_IMPORT_DESCRIPTOR
    let desc = idata_raw + 0x10;
    bytes[desc..desc + 4].copy_from_slice(&0x3050u32.to_le_bytes()); // ILT
    bytes[desc + 12..desc + 16].copy_from_slice(&0x30B0u32.to_le_bytes()); // Name
    bytes[desc + 16..desc + 20].copy_from_slice(&0x3000u32.to_le_bytes()); // FirstThunk (IAT)
    // Terminator at idata_raw + 0x24 (RVA 0x3024) — zeros.

    // ILT entries at RVA 0x3050
    bytes[idata_raw + 0x50..idata_raw + 0x58].copy_from_slice(&0x3080u64.to_le_bytes());
    bytes[idata_raw + 0x58..idata_raw + 0x60].copy_from_slice(&0x3090u64.to_le_bytes());
    // ILT terminator at RVA 0x3060 — zeros.

    // Hint/name at RVA 0x3080 for WriteFile
    bytes[idata_raw + 0x80..idata_raw + 0x82].copy_from_slice(&0u16.to_le_bytes());
    let wn = b"WriteFile\0";
    bytes[idata_raw + 0x82..idata_raw + 0x82 + wn.len()].copy_from_slice(wn);

    // Hint/name at RVA 0x3090 for ExitProcess
    bytes[idata_raw + 0x90..idata_raw + 0x92].copy_from_slice(&0u16.to_le_bytes());
    let en = b"ExitProcess\0";
    bytes[idata_raw + 0x92..idata_raw + 0x92 + en.len()].copy_from_slice(en);

    // DLL name at RVA 0x30B0
    let dll = b"KERNEL32.DLL\0";
    bytes[idata_raw + 0xB0..idata_raw + 0xB0 + dll.len()].copy_from_slice(dll);

    bytes
}

#[test]
fn write_then_exit_runs_to_completion() {
    let msg = b"hello, quantum\n";
    let pe_bytes = build_pe(msg);
    let pe = PeFile::parse(&pe_bytes).expect("parse");
    let mem = MachVmManager::new();
    let mut image = load(&pe, &mem).expect("load");
    apply_relocations(&mut image).expect("reloc");

    let imports = imports::parse(&image).expect("imports");
    assert_eq!(imports.dlls.len(), 1);
    assert_eq!(imports.dlls[0].entries.len(), 2);
    imports::wire_iat(&mut image, &imports, resolve).expect("wire IAT");

    let entry_va = image.actual_base + image.entry_rva as u64;
    let entry_bytes: Vec<u8> = image
        .rva_to_slice(image.entry_rva, 64)
        .expect("entry bytes")
        .to_vec();

    let mut emitter = Emitter::new();
    let mut decoder = Decoder::new(&entry_bytes, entry_va);
    loop {
        let inst = decoder.next().expect("decode");
        let terminator = matches!(inst.op, Op::Ud2 | Op::Ret);
        Lifter::new(&mut emitter).lift(&inst).expect("lift");
        if terminator {
            break;
        }
    }
    emitter.finish().expect("finish");

    let mut cache = CodeCache::new(8192).expect("cache");
    let entry_fn_ptr = cache.install(&emitter.bytes()).expect("install");

    // SAFETY: the lifted code calls WriteFile then ExitProcess; ExitProcess
    // longjmps out via the trap installed by run_with_exit_trap.
    let entry: extern "C" fn() = unsafe { core::mem::transmute(entry_fn_ptr.as_ptr()) };

    let exit_code = run_with_exit_trap(|| {
        entry();
    });

    assert_eq!(exit_code, 0, "expected ExitProcess(0)");
}

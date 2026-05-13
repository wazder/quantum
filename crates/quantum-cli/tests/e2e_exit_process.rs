//! Quantum's first end-to-end test: hand-assemble a tiny Win64 PE,
//! load it, wire its IAT to the kernel32 thunk table, JIT-translate
//! the entry point, execute it on the host CPU, and assert that the
//! guest's `ExitProcess(42)` reaches the harness with the expected
//! exit code.
//!
//! Guest program:
//!     mov ecx, 42                  ; B9 2A 00 00 00
//!     call qword ptr [rip + 0xFF5] ; FF 15 F5 0F 00 00  -> IAT slot at RVA 0x2000
//!     ud2                          ; 0F 0B (unreachable: ExitProcess never returns)

use quantum_jit::decoder::Decoder;
use quantum_jit::emitter::Emitter;
use quantum_jit::iform::Op;
use quantum_jit::lifter::Lifter;
use quantum_kernel32::process::run_with_exit_trap;
use quantum_kernel32::resolve;
use quantum_loader::{PeFile, apply_relocations, imports, load};
use quantum_runtime::{CodeCache, MachVmManager};

fn build_pe_calling_exitprocess() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x800];

    // DOS header
    bytes[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes());
    bytes[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

    // PE signature
    let pe_off = 0x80usize;
    bytes[pe_off..pe_off + 4].copy_from_slice(&0x0000_4550u32.to_le_bytes());

    // COFF header
    let coff = pe_off + 4;
    bytes[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
    bytes[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
    bytes[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes()); // optional header size
    bytes[coff + 18..coff + 20].copy_from_slice(&0x22u16.to_le_bytes()); // characteristics

    // Optional header (PE32+)
    let opt = coff + 20;
    bytes[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
    bytes[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry RVA
    bytes[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes()); // image base
    bytes[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section align
    bytes[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file align
    bytes[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // size of image
    bytes[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes()); // size of headers
    bytes[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // subsystem (Windows CUI)
    bytes[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

    // Data directory [1] (IMPORT) -> RVA 0x2010, size = 40 bytes (one descriptor + terminator)
    let dd1 = opt + 112 + 8;
    bytes[dd1..dd1 + 4].copy_from_slice(&0x2010u32.to_le_bytes());
    bytes[dd1 + 4..dd1 + 8].copy_from_slice(&40u32.to_le_bytes());

    // Section header 1: .text
    let sh1 = opt + 240;
    bytes[sh1..sh1 + 5].copy_from_slice(b".text");
    bytes[sh1 + 8..sh1 + 12].copy_from_slice(&0x100u32.to_le_bytes()); // vsize
    bytes[sh1 + 12..sh1 + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // rva
    bytes[sh1 + 16..sh1 + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
    bytes[sh1 + 20..sh1 + 24].copy_from_slice(&0x400u32.to_le_bytes()); // raw ptr
    bytes[sh1 + 36..sh1 + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    // Section header 2: .idata
    let sh2 = sh1 + 40;
    bytes[sh2..sh2 + 6].copy_from_slice(b".idata");
    bytes[sh2 + 8..sh2 + 12].copy_from_slice(&0x100u32.to_le_bytes());
    bytes[sh2 + 12..sh2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    bytes[sh2 + 16..sh2 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[sh2 + 20..sh2 + 24].copy_from_slice(&0x600u32.to_le_bytes());
    bytes[sh2 + 36..sh2 + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes());

    // .text raw bytes
    let text_raw = 0x400usize;
    // mov ecx, 42
    bytes[text_raw..text_raw + 5].copy_from_slice(&[0xB9, 0x2A, 0x00, 0x00, 0x00]);
    // call qword ptr [rip + 0xFF5]
    //   call instruction at RVA 0x1005, length 6, next inst at 0x100B
    //   target IAT slot at RVA 0x2000 -> disp = 0x2000 - 0x100B = 0xFF5
    bytes[text_raw + 5..text_raw + 11].copy_from_slice(&[0xFF, 0x15, 0xF5, 0x0F, 0x00, 0x00]);
    // ud2 (decoder produces this even though it's unreachable in flight)
    bytes[text_raw + 11..text_raw + 13].copy_from_slice(&[0x0F, 0x0B]);

    // .idata raw bytes at file 0x600 (mapped to RVA 0x2000)
    let idata_raw = 0x600usize;
    // RVA 0x2000: IAT slot 0 -> points to hint/name at RVA 0x2060
    bytes[idata_raw..idata_raw + 8].copy_from_slice(&0x2060u64.to_le_bytes());
    // RVA 0x2008: IAT terminator (zeros — already zero)

    // RVA 0x2010: IMAGE_IMPORT_DESCRIPTOR (20 bytes -> ends at RVA 0x2024).
    let desc = idata_raw + 0x10;
    bytes[desc..desc + 4].copy_from_slice(&0x2040u32.to_le_bytes()); // OriginalFirstThunk (ILT)
    bytes[desc + 12..desc + 16].copy_from_slice(&0x2080u32.to_le_bytes()); // Name
    bytes[desc + 16..desc + 20].copy_from_slice(&0x2000u32.to_le_bytes()); // FirstThunk (IAT)
    // RVA 0x2024: descriptor terminator (20 bytes of zeros -> ends at RVA 0x2038).

    // RVA 0x2040: ILT slot 0 -> hint/name at RVA 0x2060 (kept clear of the
    // terminator descriptor region at 0x2024..0x2038).
    bytes[idata_raw + 0x40..idata_raw + 0x48].copy_from_slice(&0x2060u64.to_le_bytes());
    // RVA 0x2048: ILT terminator (zeros)

    // RVA 0x2060: u16 hint=0 + "ExitProcess\0"
    bytes[idata_raw + 0x60..idata_raw + 0x62].copy_from_slice(&0u16.to_le_bytes());
    let name = b"ExitProcess\0";
    bytes[idata_raw + 0x62..idata_raw + 0x62 + name.len()].copy_from_slice(name);

    // RVA 0x2080: "KERNEL32.DLL\0"
    let dll = b"KERNEL32.DLL\0";
    bytes[idata_raw + 0x80..idata_raw + 0x80 + dll.len()].copy_from_slice(dll);

    bytes
}

#[test]
fn loads_runs_calls_exit_process_42() {
    let pe_bytes = build_pe_calling_exitprocess();
    let pe = PeFile::parse(&pe_bytes).expect("parse");
    let mem = MachVmManager::new();
    let mut image = load(&pe, &mem).expect("load");
    apply_relocations(&mut image).expect("reloc");

    // Walk the import directory and stamp each IAT slot with the
    // resolved host thunk pointer.
    let imports = imports::parse(&image).expect("imports parse");
    assert_eq!(imports.dlls.len(), 1, "expected exactly one imported DLL");
    assert_eq!(imports.dlls[0].name, "KERNEL32.DLL");
    imports::wire_iat(&mut image, &imports, resolve).expect("wire IAT");

    // Sanity check: the IAT slot should now hold ExitProcess's host address.
    let iat_slot = image.rva_to_slice(0x2000, 8).expect("iat slot");
    let installed = u64::from_le_bytes(iat_slot.try_into().unwrap());
    assert_eq!(installed, resolve("KERNEL32.DLL", "ExitProcess").unwrap());

    // JIT-translate from the entry point until we hit a terminator
    // (UD2 / RET / call-that-never-returns).
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

    // SAFETY: lifted code is a leaf-ish function that ends in a call to
    // ExitProcess; we never return through the JIT frame because
    // ExitProcess longjmps directly out to the trap installed by
    // `run_with_exit_trap`.
    let entry: extern "C" fn() = unsafe { core::mem::transmute(entry_fn_ptr.as_ptr()) };

    let exit_code = run_with_exit_trap(|| {
        entry();
    });

    assert_eq!(exit_code, 42, "ExitProcess should have been called with 42");
}

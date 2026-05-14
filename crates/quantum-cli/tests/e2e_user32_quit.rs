//! E2E: a JIT'd Win64 guest reaches user32 *and* kernel32 entries
//! through their respective IAT slots. Proves that multi-DLL imports
//! resolve correctly all the way through wire_iat → lifted CALL.
//!
//! Guest program:
//!     mov  ecx, 42
//!     call qword ptr [rip + iat_postquit] ; user32.PostQuitMessage(42)
//!     mov  ecx, 42
//!     call qword ptr [rip + iat_exit]     ; kernel32.ExitProcess(42)
//!     ud2
//!
//! After the run we assert that PostQuitMessage flipped the global
//! quit flag (windows_state::take_quit == Some(42)) AND that the
//! captured exit code is 42.

use quantum_jit::decoder::Decoder;
use quantum_jit::emitter::Emitter;
use quantum_jit::iform::Op;
use quantum_jit::lifter::Lifter;
use quantum_kernel32::process::run_with_exit_trap;
use quantum_kernel32::resolve;
use quantum_kernel32::windows_state;
use quantum_loader::{PeFile, apply_relocations, imports, load};
use quantum_runtime::{CodeCache, MachVmManager};

/// Layout:
///   .text  at RVA 0x1000 (file 0x400)
///   .idata at RVA 0x2000 (file 0x600)
///
/// IAT table at RVA 0x2000 contains, in order:
///   0x2000  USER32.DLL!PostQuitMessage   (8 bytes)
///   0x2008  USER32 terminator            (8 bytes of 0)
///   0x2010  KERNEL32.DLL!ExitProcess     (8 bytes)
///   0x2018  KERNEL32 terminator          (8 bytes of 0)
///
/// IMAGE_IMPORT_DESCRIPTORs start at RVA 0x2020 (3 × 20 bytes:
///   user32, kernel32, terminator).
fn build_pe() -> Vec<u8> {
    let mut bytes = vec![0u8; 0xC00];

    bytes[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes());
    bytes[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

    let pe_off = 0x80usize;
    bytes[pe_off..pe_off + 4].copy_from_slice(&0x0000_4550u32.to_le_bytes());

    let coff = pe_off + 4;
    bytes[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    bytes[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
    bytes[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
    bytes[coff + 18..coff + 20].copy_from_slice(&0x22u16.to_le_bytes());

    let opt = coff + 20;
    bytes[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
    bytes[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    bytes[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // size of image
    bytes[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes()); // size of headers
    bytes[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // subsystem=Windows CUI
    bytes[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

    // IMPORT directory at RVA 0x2020, size = 60 (3 descriptors).
    let dd1 = opt + 112 + 8;
    bytes[dd1..dd1 + 4].copy_from_slice(&0x2020u32.to_le_bytes());
    bytes[dd1 + 4..dd1 + 8].copy_from_slice(&60u32.to_le_bytes());

    // Section header 1: .text
    let sh1 = opt + 240;
    bytes[sh1..sh1 + 5].copy_from_slice(b".text");
    bytes[sh1 + 8..sh1 + 12].copy_from_slice(&0x100u32.to_le_bytes());
    bytes[sh1 + 12..sh1 + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[sh1 + 16..sh1 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[sh1 + 20..sh1 + 24].copy_from_slice(&0x400u32.to_le_bytes());
    bytes[sh1 + 36..sh1 + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    // Section header 2: .idata (placed at RVA 0x2000, file 0x600)
    let sh2 = sh1 + 40;
    bytes[sh2..sh2 + 6].copy_from_slice(b".idata");
    bytes[sh2 + 8..sh2 + 12].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[sh2 + 12..sh2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    bytes[sh2 + 16..sh2 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[sh2 + 20..sh2 + 24].copy_from_slice(&0x600u32.to_le_bytes());
    bytes[sh2 + 36..sh2 + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes());

    // ---- .text ----
    // RVA 0x1000: mov ecx, 42                 (5 bytes)
    // RVA 0x1005: call qword ptr [rip + d1]   (6 bytes) — user32!PostQuitMessage
    //   call's next-IP at RVA 0x100B, target IAT slot at RVA 0x2000
    //   disp = 0x2000 - 0x100B = 0xFF5
    // RVA 0x100B: mov ecx, 42                 (5 bytes)
    // RVA 0x1010: call qword ptr [rip + d2]   (6 bytes) — kernel32!ExitProcess
    //   call's next-IP at RVA 0x1016, target IAT slot at RVA 0x2010
    //   disp = 0x2010 - 0x1016 = 0xFFA
    // RVA 0x1016: ud2                          (2 bytes)
    let text_raw = 0x400usize;
    bytes[text_raw..text_raw + 5].copy_from_slice(&[0xB9, 0x2A, 0x00, 0x00, 0x00]);
    bytes[text_raw + 5..text_raw + 11].copy_from_slice(&[0xFF, 0x15, 0xF5, 0x0F, 0x00, 0x00]);
    bytes[text_raw + 11..text_raw + 16].copy_from_slice(&[0xB9, 0x2A, 0x00, 0x00, 0x00]);
    bytes[text_raw + 16..text_raw + 22].copy_from_slice(&[0xFF, 0x15, 0xFA, 0x0F, 0x00, 0x00]);
    bytes[text_raw + 22..text_raw + 24].copy_from_slice(&[0x0F, 0x0B]);

    // ---- .idata at file 0x600 (RVA 0x2000) ----
    let idata_raw = 0x600usize;

    // IAT — placeholders, wire_iat fills with real host pointers.
    // We seed with hint/name table RVAs so the loader's "fix unresolved
    // slots" path has a value to overwrite.
    bytes[idata_raw..idata_raw + 0x08].copy_from_slice(&0x20A0u64.to_le_bytes()); // -> hint/name "PostQuitMessage"
    bytes[idata_raw + 0x08..idata_raw + 0x10].copy_from_slice(&0u64.to_le_bytes()); // U32 terminator
    bytes[idata_raw + 0x10..idata_raw + 0x18].copy_from_slice(&0x20C0u64.to_le_bytes()); // -> hint/name "ExitProcess"
    bytes[idata_raw + 0x18..idata_raw + 0x20].copy_from_slice(&0u64.to_le_bytes()); // K32 terminator

    // IMAGE_IMPORT_DESCRIPTOR table at RVA 0x2020.
    // [0] user32 — ILT at RVA 0x2050, Name at RVA 0x20E0, IAT at RVA 0x2000.
    let desc0 = idata_raw + 0x20;
    bytes[desc0..desc0 + 4].copy_from_slice(&0x2050u32.to_le_bytes());
    bytes[desc0 + 12..desc0 + 16].copy_from_slice(&0x20E0u32.to_le_bytes());
    bytes[desc0 + 16..desc0 + 20].copy_from_slice(&0x2000u32.to_le_bytes());

    // [1] kernel32 — ILT at RVA 0x2070, Name at RVA 0x20F0, IAT at RVA 0x2010.
    let desc1 = idata_raw + 0x34;
    bytes[desc1..desc1 + 4].copy_from_slice(&0x2070u32.to_le_bytes());
    bytes[desc1 + 12..desc1 + 16].copy_from_slice(&0x20F0u32.to_le_bytes());
    bytes[desc1 + 16..desc1 + 20].copy_from_slice(&0x2010u32.to_le_bytes());

    // [2] descriptor terminator (zeros at desc1 + 20).

    // ILTs.
    // user32 ILT at RVA 0x2050: [0] -> hint/name @ 0x20A0, [1] terminator.
    bytes[idata_raw + 0x50..idata_raw + 0x58].copy_from_slice(&0x20A0u64.to_le_bytes());
    // 0x2058: zeros.

    // kernel32 ILT at RVA 0x2070: [0] -> hint/name @ 0x20C0, [1] terminator.
    bytes[idata_raw + 0x70..idata_raw + 0x78].copy_from_slice(&0x20C0u64.to_le_bytes());

    // Hint/name "PostQuitMessage" at RVA 0x20A0.
    bytes[idata_raw + 0xA0..idata_raw + 0xA2].copy_from_slice(&0u16.to_le_bytes());
    let p1 = b"PostQuitMessage\0";
    bytes[idata_raw + 0xA2..idata_raw + 0xA2 + p1.len()].copy_from_slice(p1);

    // Hint/name "ExitProcess" at RVA 0x20C0.
    bytes[idata_raw + 0xC0..idata_raw + 0xC2].copy_from_slice(&0u16.to_le_bytes());
    let p2 = b"ExitProcess\0";
    bytes[idata_raw + 0xC2..idata_raw + 0xC2 + p2.len()].copy_from_slice(p2);

    // DLL names.
    let u32_name = b"USER32.DLL\0";
    bytes[idata_raw + 0xE0..idata_raw + 0xE0 + u32_name.len()].copy_from_slice(u32_name);
    let k32_name = b"KERNEL32.DLL\0";
    bytes[idata_raw + 0xF0..idata_raw + 0xF0 + k32_name.len()].copy_from_slice(k32_name);

    bytes
}

#[test]
fn guest_calls_user32_and_kernel32_through_iat() {
    // Clear any leftover quit from earlier tests in the binary.
    let _ = windows_state::take_quit();

    let pe_bytes = build_pe();
    let pe = PeFile::parse(&pe_bytes).expect("parse");
    let mem = MachVmManager::new();
    let mut image = load(&pe, &mem).expect("load");
    apply_relocations(&mut image).expect("reloc");

    let imp = imports::parse(&image).expect("imports");
    assert_eq!(imp.dlls.len(), 2, "expected USER32 + KERNEL32 descriptors");
    assert!(
        imp.dlls
            .iter()
            .any(|d| d.name.eq_ignore_ascii_case("USER32.DLL"))
    );
    assert!(
        imp.dlls
            .iter()
            .any(|d| d.name.eq_ignore_ascii_case("KERNEL32.DLL"))
    );
    imports::wire_iat(&mut image, &imp, resolve).expect("wire IAT");

    // Sanity-check IAT slots: PostQuitMessage and ExitProcess.
    let slot_pq = u64::from_le_bytes(
        image
            .rva_to_slice(0x2000, 8)
            .expect("iat slot pq")
            .try_into()
            .unwrap(),
    );
    let slot_ep = u64::from_le_bytes(
        image
            .rva_to_slice(0x2010, 8)
            .expect("iat slot ep")
            .try_into()
            .unwrap(),
    );
    assert_eq!(slot_pq, resolve("USER32.DLL", "PostQuitMessage").unwrap());
    assert_eq!(slot_ep, resolve("KERNEL32.DLL", "ExitProcess").unwrap());

    // JIT-translate the entry block.
    let entry_va = image.actual_base + image.entry_rva as u64;
    let entry_bytes: Vec<u8> = image
        .rva_to_slice(image.entry_rva, 64)
        .expect("entry bytes")
        .to_vec();

    let mut emitter = Emitter::new();
    let mut decoder = Decoder::new(&entry_bytes, entry_va);
    loop {
        let inst = decoder.next().expect("decode");
        let terminator = matches!(inst.op, Op::Ud2 | Op::Ret | Op::CallIndirect);
        Lifter::new(&mut emitter).lift(&inst).expect("lift");
        if terminator {
            // We must keep lifting past CallIndirect until we hit UD2
            // — but only because there's a second CallIndirect after.
            // ExitProcess never returns, so the second call's bytes
            // are dead. Stopping at the first CallIndirect would
            // leak host frame state, but since ExitProcess longjmps
            // we never restore anyway.
            if matches!(inst.op, Op::Ud2 | Op::Ret) {
                break;
            }
        }
    }
    emitter.finish().expect("finish");

    let mut cache = CodeCache::new(8192).expect("cache");
    let entry_fn_ptr = cache.install(&emitter.bytes()).expect("install");

    let entry: extern "C" fn() = unsafe { core::mem::transmute(entry_fn_ptr.as_ptr()) };

    let exit_code = run_with_exit_trap(|| {
        entry();
    });

    assert_eq!(exit_code, 42, "ExitProcess(42) should have fired");
    assert_eq!(
        windows_state::take_quit(),
        Some(42),
        "PostQuitMessage(42) should have flipped the quit flag"
    );
}

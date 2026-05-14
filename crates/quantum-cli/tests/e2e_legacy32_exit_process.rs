//! E2E: hand-assembled PE32 (32-bit) that calls `ExitProcess(42)` via the IAT.
//!
//! Validates the full Steam-track foundation:
//!   * PE32 parser path (magic 0x010B, 224-byte optional header)
//!   * 32-bit image bitness propagated to JIT
//!   * legacy `call [abs32]` decoding (absolute disp, not RIP-relative)
//!   * 32-bit IAT thunks (4-byte slots)
//!   * stdcall-style indirect call ABI: first stack arg → AAPCS64 W0
//!   * `ExitProcess` longjmp surfaces in `run_with_exit_trap`
//!
//! Guest program at RVA 0x1000:
//!     push 42                   ; 68 2A 00 00 00
//!     call dword ptr [0x402000] ; FF 15 00 20 40 00   (absolute IAT slot)
//!     ud2                       ; 0F 0B  (unreachable; ExitProcess longjmps)

use core::ptr::NonNull;
use std::sync::Arc;

use quantum_jit::block::{self, IsaMode};
use quantum_kernel32::process::run_with_exit_trap;
use quantum_kernel32::resolve;
use quantum_loader::{PeFile, apply_relocations, imports, load};
use quantum_runtime::{
    Dispatcher, GuestContext, GuestStack, MachVmManager, STOP_SENTINEL, invoke_block_with_ctx,
};

fn build_pe32() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x800];

    // DOS header
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

    // PE signature
    let pe_off = 0x80usize;
    bytes[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");

    // COFF header
    let coff = pe_off + 4;
    bytes[coff..coff + 2].copy_from_slice(&0x014Cu16.to_le_bytes()); // Machine = i386
    bytes[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes()); // sections
    bytes[coff + 16..coff + 18].copy_from_slice(&224u16.to_le_bytes()); // optional header size
    // Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
    bytes[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes());

    // Optional header (PE32 = 224 bytes)
    let opt = coff + 20;
    bytes[opt..opt + 2].copy_from_slice(&0x010Bu16.to_le_bytes()); // Magic PE32
    bytes[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // EntryPoint
    bytes[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes()); // ImageBase (PE32 specific offset)
    bytes[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    bytes[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
    bytes[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
    bytes[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
    bytes[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // Subsystem CONSOLE
    bytes[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

    // Data directory [1] (IMPORT) at opt+96 + 8 = opt+104
    let dd1 = opt + 96 + 8;
    bytes[dd1..dd1 + 4].copy_from_slice(&0x2010u32.to_le_bytes()); // ImportDir RVA
    bytes[dd1 + 4..dd1 + 8].copy_from_slice(&40u32.to_le_bytes()); // size

    // Section table — starts at opt + 224
    let sh1 = opt + 224;
    bytes[sh1..sh1 + 5].copy_from_slice(b".text");
    bytes[sh1 + 8..sh1 + 12].copy_from_slice(&0x100u32.to_le_bytes());
    bytes[sh1 + 12..sh1 + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[sh1 + 16..sh1 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[sh1 + 20..sh1 + 24].copy_from_slice(&0x400u32.to_le_bytes());
    bytes[sh1 + 36..sh1 + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // CODE+EXEC+READ

    let sh2 = sh1 + 40;
    bytes[sh2..sh2 + 6].copy_from_slice(b".idata");
    bytes[sh2 + 8..sh2 + 12].copy_from_slice(&0x100u32.to_le_bytes());
    bytes[sh2 + 12..sh2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    bytes[sh2 + 16..sh2 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[sh2 + 20..sh2 + 24].copy_from_slice(&0x600u32.to_le_bytes());
    bytes[sh2 + 36..sh2 + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes());

    // .text raw bytes
    //   push 42                       ; 68 2A 00 00 00
    //   call dword ptr [0x00402000]   ; FF 15 00 20 40 00
    //   ud2                           ; 0F 0B
    let text_raw = 0x400usize;
    bytes[text_raw..text_raw + 5].copy_from_slice(&[0x68, 0x2A, 0x00, 0x00, 0x00]);
    bytes[text_raw + 5..text_raw + 11].copy_from_slice(&[0xFF, 0x15, 0x00, 0x20, 0x40, 0x00]);
    bytes[text_raw + 11..text_raw + 13].copy_from_slice(&[0x0F, 0x0B]);

    // .idata @ raw 0x600
    let idata_raw = 0x600usize;

    // IAT @ RVA 0x2000 (4-byte slot in PE32) — initially holds Hint/Name RVA.
    bytes[idata_raw..idata_raw + 4].copy_from_slice(&0x2060u32.to_le_bytes());
    // IAT slot 1: terminator (already zero).

    // Import descriptor @ RVA 0x2010 = raw 0x610
    let desc = idata_raw + 0x10;
    bytes[desc..desc + 4].copy_from_slice(&0x2040u32.to_le_bytes()); // OriginalFirstThunk (ILT)
    bytes[desc + 12..desc + 16].copy_from_slice(&0x2080u32.to_le_bytes()); // Name
    bytes[desc + 16..desc + 20].copy_from_slice(&0x2000u32.to_le_bytes()); // FirstThunk (IAT)
    // Descriptor terminator (20 zero bytes at desc + 20).

    // ILT @ RVA 0x2040 = raw 0x640. Slot 0 points to Hint/Name; slot 1 = 0.
    bytes[idata_raw + 0x40..idata_raw + 0x44].copy_from_slice(&0x2060u32.to_le_bytes());

    // Hint/Name @ RVA 0x2060 = raw 0x660.
    bytes[idata_raw + 0x60..idata_raw + 0x62].copy_from_slice(&0u16.to_le_bytes());
    let n = b"ExitProcess\0";
    bytes[idata_raw + 0x62..idata_raw + 0x62 + n.len()].copy_from_slice(n);

    // DLL name @ RVA 0x2080 = raw 0x680.
    let dll = b"KERNEL32.DLL\0";
    bytes[idata_raw + 0x80..idata_raw + 0x80 + dll.len()].copy_from_slice(dll);

    bytes
}

/// Blocked on macOS 64-bit pagezero. The default `__PAGEZERO` segment
/// is 4 GiB on Apple Silicon, so `mach_vm_allocate` refuses any address
/// below 0x100000000. A 32-bit PE32 with `ImageBase = 0x00400000` and
/// embedded `call dword ptr [0x00402000]` absolute references therefore
/// can't be mapped at its preferred base — and after relocation the
/// patched disp32 doesn't fit in 32 bits anyway.
///
/// Shrinking pagezero via `-pagezero_size` linker flag built fine but
/// macOS killed the resulting test binary with SIGKILL before main —
/// hardened-runtime + small-pagezero is rejected outright on recent
/// Apple Silicon kernels (tested on 25.4).
///
/// The end-to-end 32-bit path needs either:
///  - a thunking layer (IAT slots point to low-mapped thunks that BR
///    to actual host functions above 4 GiB), or
///  - a special-entitlement build that the kernel accepts with shrunk
///    pagezero.
///
/// Both are non-trivial. For now we ignore the test but keep it as a
/// reference for the full PE32+IAT round trip we want to enable.
#[test]
#[ignore = "pagezero blocks 32-bit guest mapping on Apple Silicon — see docstring"]
fn pe32_calls_exit_process_42() {
    let pe_bytes = build_pe32();
    let pe = PeFile::parse(&pe_bytes).expect("parse PE32");
    assert_eq!(
        pe.opt.kind,
        quantum_loader::PeKind::Pe32,
        "test PE must parse as PE32"
    );

    let mem = MachVmManager::new();
    let mut image = load(&pe, &mem).expect("load");
    apply_relocations(&mut image).expect("reloc");
    assert_eq!(image.bitness, quantum_loader::Bitness::X86);
    eprintln!(
        "[diag] preferred_base={:#x} actual_base={:#x}",
        image.preferred_base, image.actual_base
    );

    let imp = imports::parse(&image).expect("imports");
    imports::wire_iat(&mut image, &imp, resolve).expect("wire IAT");

    let stack = GuestStack::default_size().expect("stack");
    let mut ctx = GuestContext::default();
    ctx.gprs[4] = stack.entry_rsp(STOP_SENTINEL);

    let disp = Arc::new(Dispatcher::new(16 * 1024).expect("dispatcher"));
    let entry_eip = image.actual_base + image.entry_rva as u64;

    let exit_code = run_with_exit_trap(|| {
        let mut current = entry_eip;
        for _ in 0..256 {
            let ptr: NonNull<u8> = if let Some(p) = disp.lookup(current) {
                p
            } else {
                let rva = (current - image.actual_base) as u32;
                let win = 64usize;
                let bytes: Vec<u8> = image
                    .rva_to_slice(rva, win.min(image.len() - rva as usize))
                    .expect("rva")
                    .to_vec();
                let block = block::translate_for_dispatcher(&bytes, current, IsaMode::Legacy32)
                    .expect("translate legacy32");
                disp.install(current, &block.host_bytes).expect("install")
            };
            let next = unsafe { invoke_block_with_ctx(ptr, &mut ctx) };
            if next == STOP_SENTINEL {
                break;
            }
            current = next;
        }
    });

    assert_eq!(exit_code, 42, "guest ExitProcess(42) should reach the trap");
}

//! E2E: a guest function with a standard Win64 prologue / epilogue
//! around a call into another guest function. Verifies the
//! 8-byte-misaligned RSP entry contract plus shadow-space allocation
//! propagate correctly through the dispatcher.
//!
//!     main:
//!       push rbp                      ; rsp now 16-aligned
//!       mov  rbp, rsp
//!       sub  rsp, 0x20                ; 32 bytes shadow space
//!       call foo                      ; pushes 8 -> 8-misaligned at foo entry
//!       add  rsp, 0x20
//!       pop  rbp                      ; restore
//!       mov  rcx, rax                 ; ExitProcess(foo's return)
//!       call qword ptr [rip + IAT_EXIT]
//!       ud2
//!
//!     foo:
//!       mov  eax, 0x42
//!       ret

use core::ptr::NonNull;

use quantum_jit::block;
use quantum_kernel32::process::run_with_exit_trap;
use quantum_kernel32::resolve;
use quantum_loader::{PeFile, apply_relocations, imports, load};
use quantum_runtime::{
    Dispatcher, GuestContext, GuestStack, MachVmManager, STOP_SENTINEL, invoke_block_with_ctx,
};

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
    //   0x1000  push rbp                  55                       (1)
    //   0x1001  mov  rbp, rsp             48 89 E5                 (3)
    //   0x1004  sub  rsp, 0x20            48 83 EC 20              (4)
    //   0x1008  call foo (rel32)          E8 13 00 00 00           (5)
    //              next 0x100D, foo @ 0x1020 -> rel = 0x13
    //   0x100D  add  rsp, 0x20            48 83 C4 20              (4)
    //   0x1011  pop  rbp                  5D                       (1)
    //   0x1012  mov  rcx, rax             48 89 C1                 (3)
    //   0x1015  call [rip + 0xFE5]        FF 15 E5 0F 00 00        (6)
    //              next 0x101B, IAT @ 0x2000 -> disp = 0xFE5
    //   0x101B  ud2                       0F 0B                    (2)
    //   0x101D-0x101F (gap)
    //   0x1020  foo: mov eax, 0x42        B8 42 00 00 00           (5)
    //   0x1025  ret                       C3                       (1)
    let text_raw = 0x400usize;
    bytes[text_raw] = 0x55;
    bytes[text_raw + 0x01..text_raw + 0x04].copy_from_slice(&[0x48, 0x89, 0xE5]);
    bytes[text_raw + 0x04..text_raw + 0x08].copy_from_slice(&[0x48, 0x83, 0xEC, 0x20]);
    bytes[text_raw + 0x08..text_raw + 0x0D].copy_from_slice(&[0xE8, 0x13, 0x00, 0x00, 0x00]);
    bytes[text_raw + 0x0D..text_raw + 0x11].copy_from_slice(&[0x48, 0x83, 0xC4, 0x20]);
    bytes[text_raw + 0x11] = 0x5D;
    bytes[text_raw + 0x12..text_raw + 0x15].copy_from_slice(&[0x48, 0x89, 0xC1]);
    bytes[text_raw + 0x15..text_raw + 0x1B].copy_from_slice(&[0xFF, 0x15, 0xE5, 0x0F, 0x00, 0x00]);
    bytes[text_raw + 0x1B..text_raw + 0x1D].copy_from_slice(&[0x0F, 0x0B]);
    bytes[text_raw + 0x20..text_raw + 0x25].copy_from_slice(&[0xB8, 0x42, 0x00, 0x00, 0x00]);
    bytes[text_raw + 0x25] = 0xC3;

    // .idata
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

fn run_via_dispatcher(
    disp: &mut Dispatcher,
    image: &quantum_loader::LoadedImage,
    ctx: &mut GuestContext,
    start_rip: u64,
) {
    let mut current_rip = start_rip;
    let mut iters = 0;
    loop {
        iters += 1;
        assert!(iters < 1000);
        let ptr: NonNull<u8> = if let Some(p) = disp.lookup(current_rip) {
            p
        } else {
            let rva = (current_rip - image.actual_base) as u32;
            let bytes: Vec<u8> = image.rva_to_slice(rva, 64).unwrap().to_vec();
            let block = block::translate_for_dispatcher(
                &bytes,
                current_rip,
                quantum_jit::block::IsaMode::Long,
            )
            .unwrap();
            disp.install(current_rip, &block.host_bytes).unwrap()
        };
        let next = unsafe { invoke_block_with_ctx(ptr, ctx) };
        if next == STOP_SENTINEL {
            break;
        }
        current_rip = next;
    }
}

#[test]
fn win64_prologue_with_shadow_space_round_trips() {
    let pe_bytes = build_pe();
    let pe = PeFile::parse(&pe_bytes).expect("parse");
    let mem = MachVmManager::new();
    let mut image = load(&pe, &mem).expect("load");
    apply_relocations(&mut image).expect("reloc");
    let imp = imports::parse(&image).expect("imports");
    imports::wire_iat(&mut image, &imp, resolve).expect("wire IAT");

    let stack = GuestStack::default_size().expect("stack");
    let mut ctx = GuestContext::default();
    // Initialise RSP per the Win64 entry contract (8-misaligned,
    // STOP_SENTINEL as the fake return address). entry_rsp puts RSP
    // at top-8 which doesn't leave the 0x20 shadow space + arg slots
    // that lift_call_indirect now reads. Step further down.
    ctx.gprs[4] = stack.entry_rsp(STOP_SENTINEL) - 0x40;

    let mut disp = Dispatcher::new(16384).expect("dispatcher");
    let entry_va = image.actual_base + image.entry_rva as u64;

    let exit_code = run_with_exit_trap(|| {
        run_via_dispatcher(&mut disp, &image, &mut ctx, entry_va);
    });

    assert_eq!(exit_code, 0x42);
}

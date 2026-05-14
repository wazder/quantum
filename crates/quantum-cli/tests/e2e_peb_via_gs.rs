//! E2E: guest reads `TEB.ThreadId` via `gs:[0x48]` and exits with it.
//! Proves the segment-base plumbing — `X24 = gs_base` loaded from
//! `GuestContext.gs_base` by the dispatcher prologue, and the lifter's
//! `Mem.seg` handling in `mem_address_into`.
//!
//! Guest program:
//!     mov  rax, gs:[0x48]    ; rax = TEB.ThreadId (we set it to 0x42)
//!     mov  ecx, eax
//!     call qword ptr [rip + IAT_EXIT]
//!     ud2

use core::ptr::NonNull;

use quantum_jit::block;
use quantum_kernel32::process::run_with_exit_trap;
use quantum_kernel32::resolve;
use quantum_loader::{PeFile, apply_relocations, imports, load};
use quantum_runtime::{
    Dispatcher, GuestContext, GuestStack, MachVmManager, ProcessControlBlock, STOP_SENTINEL,
    invoke_block_with_ctx,
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
    //   0x1000  mov rax, gs:[0x48]     65 48 8B 04 25 48 00 00 00     (9)
    //   0x1009  mov ecx, eax           89 C1                          (2)
    //   0x100B  call [rip + 0xFEF]     FF 15 EF 0F 00 00              (6)
    //                                   next at 0x1011, IAT @ 0x2000
    //                                   disp = 0x2000 - 0x1011 = 0xFEF
    //   0x1011  ud2                    0F 0B                          (2)
    let text_raw = 0x400usize;
    let mut p = 0usize;
    bytes[text_raw + p..text_raw + p + 9]
        .copy_from_slice(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x48, 0x00, 0x00, 0x00]);
    p += 9;
    bytes[text_raw + p..text_raw + p + 2].copy_from_slice(&[0x89, 0xC1]);
    p += 2;
    bytes[text_raw + p..text_raw + p + 6].copy_from_slice(&[0xFF, 0x15, 0xEF, 0x0F, 0x00, 0x00]);
    p += 6;
    bytes[text_raw + p..text_raw + p + 2].copy_from_slice(&[0x0F, 0x0B]);

    // .idata — ExitProcess only
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
fn guest_reads_teb_through_gs_segment() {
    let pe_bytes = build_pe();
    let pe = PeFile::parse(&pe_bytes).expect("parse");
    let mem = MachVmManager::new();
    let mut image = load(&pe, &mem).expect("load");
    apply_relocations(&mut image).expect("reloc");
    let imp = imports::parse(&image).expect("imports");
    imports::wire_iat(&mut image, &imp, resolve).expect("wire IAT");

    // Build a TEB with a sentinel ThreadId — that's what the guest
    // reads through gs:[0x48].
    let pcb = ProcessControlBlock::new(image.actual_base, 0, 0x42).expect("PEB/TEB");

    let stack = GuestStack::default_size().expect("stack");
    let mut ctx = GuestContext::default();
    // 0x40 reservation for Win64 shadow + stack args (lift_call_indirect
    // loads X4..X7 from [RSP+0x20..0x38]).
    ctx.gprs[4] = stack.top() - 0x40;
    ctx.gs_base = pcb.teb_addr;

    let mut disp = Dispatcher::new(16384).expect("dispatcher");
    let entry_va = image.actual_base + image.entry_rva as u64;

    let exit_code = run_with_exit_trap(|| {
        run_via_dispatcher(&mut disp, &image, &mut ctx, entry_va);
    });

    // gs:[0x48] -> TEB.ThreadId == 0x42; exit code carries it.
    assert_eq!(exit_code, 0x42);
}

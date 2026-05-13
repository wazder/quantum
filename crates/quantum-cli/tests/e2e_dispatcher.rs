//! E2E: cross-block control flow through the Dispatcher.
//!
//! Guest program has two basic blocks separated by an unconditional
//! JMP. Each block ends in a dispatcher exit (`mov x0, <next_rip>;
//! ret`) and the Rust driver loops, translating blocks on demand.
//!
//!     Block A @ RVA 0x1000:
//!         mov  ecx, 42
//!         jmp  .B               ; rel32 to RVA 0x1010
//!
//!     <gap>
//!
//!     Block B @ RVA 0x1010:
//!         call qword ptr [rip + IAT_EXIT]
//!         ud2

use core::ptr::NonNull;

use quantum_jit::block;
use quantum_kernel32::process::run_with_exit_trap;
use quantum_kernel32::resolve;
use quantum_loader::{PeFile, apply_relocations, imports, load};
use quantum_runtime::{
    Dispatcher, GuestContext, MachVmManager, STOP_SENTINEL, invoke_block_with_ctx,
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
    //   RVA 0x1000  mov ecx, 42                 ; 5 bytes
    //   RVA 0x1005  jmp +6                       ; 5 bytes (E9 06 00 00 00)
    //                  next at 0x100A, target = 0x100A + 6 = 0x1010
    //   RVA 0x100A  <gap, zeros>                ; 6 bytes
    //   RVA 0x1010  call qword ptr [rip + disp] ; 6 bytes, IAT @ 0x2000
    //                  disp = 0x2000 - 0x1016 = 0xFEA
    //   RVA 0x1016  ud2
    let text_raw = 0x400usize;
    bytes[text_raw..text_raw + 5].copy_from_slice(&[0xB9, 0x2A, 0x00, 0x00, 0x00]);
    bytes[text_raw + 5..text_raw + 10].copy_from_slice(&[0xE9, 0x06, 0x00, 0x00, 0x00]);
    bytes[text_raw + 0x10..text_raw + 0x16].copy_from_slice(&[0xFF, 0x15, 0xEA, 0x0F, 0x00, 0x00]);
    bytes[text_raw + 0x16..text_raw + 0x18].copy_from_slice(&[0x0F, 0x0B]);

    // --- .idata at file 0x600 (RVA 0x2000), ExitProcess only ---
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

/// Drive a Dispatcher: translate-on-demand, jump in, capture next RIP,
/// loop until STOP_SENTINEL. Guest GPRs live in the `GuestContext`
/// across round-trips; each block reloads them on entry and spills
/// them on exit.
fn run_via_dispatcher(
    disp: &mut Dispatcher,
    image: &quantum_loader::LoadedImage,
    ctx: &mut GuestContext,
    start_rip: u64,
) {
    let mut current_rip = start_rip;
    let mut iterations = 0;
    loop {
        iterations += 1;
        assert!(iterations < 1000, "dispatcher loop did not terminate");

        let ptr: NonNull<u8> = if let Some(p) = disp.lookup(current_rip) {
            p
        } else {
            let rva = (current_rip - image.actual_base) as u32;
            let bytes: Vec<u8> = image
                .rva_to_slice(rva, 64)
                .expect("block bytes in-bounds")
                .to_vec();
            let block =
                block::translate_for_dispatcher(&bytes, current_rip, None).expect("translate");
            disp.install(current_rip, &block.host_bytes)
                .expect("install")
        };

        // SAFETY: block respects the dispatcher prologue/epilogue
        // contract (load ctx regs, run, spill regs, return next RIP).
        let next_rip = unsafe { invoke_block_with_ctx(ptr, ctx) };
        if next_rip == STOP_SENTINEL {
            break;
        }
        current_rip = next_rip;
    }
}

#[test]
fn two_blocks_with_unconditional_jmp() {
    let pe_bytes = build_pe();
    let pe = PeFile::parse(&pe_bytes).expect("parse");
    let mem = MachVmManager::new();
    let mut image = load(&pe, &mem).expect("load");
    apply_relocations(&mut image).expect("reloc");
    let imp = imports::parse(&image).expect("imports");
    imports::wire_iat(&mut image, &imp, resolve).expect("wire IAT");

    let mut disp = Dispatcher::new(16384).expect("dispatcher");
    let entry_va = image.actual_base + image.entry_rva as u64;
    let mut ctx = GuestContext::default();

    let exit_code = run_with_exit_trap(|| {
        run_via_dispatcher(&mut disp, &image, &mut ctx, entry_va);
    });

    // ExitProcess(42) longjmps back through run_with_exit_trap.
    assert_eq!(exit_code, 42);
    // Dispatcher should have translated at least two blocks (A and B).
    assert!(
        disp.block_count() >= 2,
        "expected ≥2 cached blocks, got {}",
        disp.block_count()
    );
}

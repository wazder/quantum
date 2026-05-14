//! E2E: guest calls its own function via CALL rel32, the function
//! returns via RET, then control flows to ExitProcess. Three
//! basic blocks linked through the dispatcher's guest-stack-aware
//! call/return convention.
//!
//! Guest program layout:
//!
//!     Block "main" @ RVA 0x1000:
//!         mov  ecx, 0
//!         call foo                ; rel32; pushes return RIP, jumps to .B
//!     Block "post-call" @ RVA 0x100A:
//!         call qword ptr [rip + IAT_EXIT]
//!         ud2
//!     Block "foo" @ RVA 0x1020:
//!         mov  ecx, 42
//!         ret
//!
//! Expected: ExitProcess(42).

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
    //   RVA 0x1000  mov ecx, 0                  ; 5 bytes (B9 00 00 00 00)
    //   RVA 0x1005  call foo                    ; 5 bytes (E8 + rel32)
    //                  next at 0x100A, target foo @ 0x1020, rel = 0x16
    //   RVA 0x100A  call qword ptr [rip + disp] ; 6 bytes
    //                  next at 0x1010, target IAT @ 0x2000, disp = 0xFF0
    //   RVA 0x1010  ud2                          ; 2 bytes
    //   RVA 0x1012  <gap>                        ; 0xE bytes
    //   RVA 0x1020  foo: mov ecx, 42             ; 5 bytes (B9 2A 00 00 00)
    //   RVA 0x1025  ret                          ; 1 byte  (C3)
    let text_raw = 0x400usize;
    bytes[text_raw..text_raw + 5].copy_from_slice(&[0xB9, 0x00, 0x00, 0x00, 0x00]);
    bytes[text_raw + 5..text_raw + 10].copy_from_slice(&[0xE8, 0x16, 0x00, 0x00, 0x00]);
    bytes[text_raw + 0xA..text_raw + 0x10].copy_from_slice(&[0xFF, 0x15, 0xF0, 0x0F, 0x00, 0x00]);
    bytes[text_raw + 0x10..text_raw + 0x12].copy_from_slice(&[0x0F, 0x0B]);
    bytes[text_raw + 0x20..text_raw + 0x25].copy_from_slice(&[0xB9, 0x2A, 0x00, 0x00, 0x00]);
    bytes[text_raw + 0x25] = 0xC3;

    // --- .idata ---
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
        assert!(iters < 1000, "dispatcher loop did not terminate");
        let ptr: NonNull<u8> = if let Some(p) = disp.lookup(current_rip) {
            p
        } else {
            let rva = (current_rip - image.actual_base) as u32;
            let bytes: Vec<u8> = image.rva_to_slice(rva, 64).expect("block bytes").to_vec();
            let block =
                block::translate_for_dispatcher(&bytes, current_rip, quantum_jit::block::IsaMode::Long).expect("translate");
            disp.install(current_rip, &block.host_bytes)
                .expect("install")
        };
        let next_rip = unsafe { invoke_block_with_ctx(ptr, ctx) };
        if next_rip == STOP_SENTINEL {
            break;
        }
        current_rip = next_rip;
    }
}

#[test]
fn guest_calls_own_function_then_exit() {
    let pe_bytes = build_pe();
    let pe = PeFile::parse(&pe_bytes).expect("parse");
    let mem = MachVmManager::new();
    let mut image = load(&pe, &mem).expect("load");
    apply_relocations(&mut image).expect("reloc");
    let imp = imports::parse(&image).expect("imports");
    imports::wire_iat(&mut image, &imp, resolve).expect("wire IAT");

    // CALL needs a real guest stack — the dispatcher will push the
    // return RIP onto it.
    let stack = GuestStack::default_size().expect("stack");
    let mut ctx = GuestContext::default();
    ctx.gprs[4] = stack.top(); // RSP

    let mut disp = Dispatcher::new(16384).expect("dispatcher");
    let entry_va = image.actual_base + image.entry_rva as u64;

    let exit_code = run_with_exit_trap(|| {
        run_via_dispatcher(&mut disp, &image, &mut ctx, entry_va);
    });

    assert_eq!(
        exit_code, 42,
        "foo() set ECX=42 then RET; ExitProcess saw 42"
    );
    // We should have translated 3 blocks: main (1000), foo (1020), post-call (100A).
    assert!(
        disp.block_count() >= 3,
        "expected ≥3 cached blocks, got {}",
        disp.block_count()
    );
}

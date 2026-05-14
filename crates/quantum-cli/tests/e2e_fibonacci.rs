//! E2E: a guest Fibonacci function. Combines a loop with intra-block
//! conditional branch, register-to-register moves, arithmetic, and a
//! final ExitProcess call that uses the loop result as the exit code.
//!
//!     mov  eax, 1                ; a = 1
//!     mov  ebx, 1                ; b = 1
//!     mov  ecx, 8                ; n = 8 iterations -> fib(10) = 55
//!   .loop:
//!     mov  edx, eax              ; tmp = a
//!     add  eax, ebx              ; a += b
//!     mov  ebx, edx              ; b = tmp
//!     dec  ecx
//!     jnz  .loop
//!     mov  ecx, eax              ; exit code = a (fib value)
//!     call qword ptr [rip + IAT_EXIT]
//!     ud2

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
    //   0x1000  mov eax, 1            B8 01 00 00 00              (5)
    //   0x1005  mov ebx, 1            BB 01 00 00 00              (5)
    //   0x100A  mov ecx, 8            B9 08 00 00 00              (5)
    // .loop @ 0x100F
    //   0x100F  mov edx, eax          89 C2                       (2)
    //   0x1011  add eax, ebx          01 D8                       (2)
    //   0x1013  mov ebx, edx          89 D3                       (2)
    //   0x1015  dec ecx               FF C9                       (2)
    //   0x1017  jnz .loop             75 F6   (rel8 = -10)        (2)
    //   0x1019  mov ecx, eax          89 C1                       (2)
    //   0x101B  call [rip + 0xFE1]    FF 15 E1 0F 00 00           (6)
    //                                  next at 0x1021, IAT @ 0x2000
    //                                  disp = 0x2000 - 0x1021 = 0xFDF
    //   0x1021  ud2                   0F 0B                       (2)
    //
    // Wait — recompute: call at 0x101B, len 6, next at 0x1021.
    // disp = 0x2000 - 0x1021 = 0xFDF.
    let text_raw = 0x400usize;
    let mut p = 0usize;
    bytes[text_raw + p..text_raw + p + 5].copy_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]);
    p += 5;
    bytes[text_raw + p..text_raw + p + 5].copy_from_slice(&[0xBB, 0x01, 0x00, 0x00, 0x00]);
    p += 5;
    bytes[text_raw + p..text_raw + p + 5].copy_from_slice(&[0xB9, 0x08, 0x00, 0x00, 0x00]);
    p += 5;
    // mov edx, eax  -> 89 C2  (MOV r/m32, r32: opcode 89, ModRM C2)
    bytes[text_raw + p..text_raw + p + 2].copy_from_slice(&[0x89, 0xC2]);
    p += 2;
    // add eax, ebx  -> 01 D8
    bytes[text_raw + p..text_raw + p + 2].copy_from_slice(&[0x01, 0xD8]);
    p += 2;
    // mov ebx, edx  -> 89 D3
    bytes[text_raw + p..text_raw + p + 2].copy_from_slice(&[0x89, 0xD3]);
    p += 2;
    // dec ecx  -> FF C9
    bytes[text_raw + p..text_raw + p + 2].copy_from_slice(&[0xFF, 0xC9]);
    p += 2;
    // jnz .loop  -> 75 F6 (rel = -10)
    bytes[text_raw + p..text_raw + p + 2].copy_from_slice(&[0x75, 0xF6]);
    p += 2;
    // mov ecx, eax  -> 89 C1
    bytes[text_raw + p..text_raw + p + 2].copy_from_slice(&[0x89, 0xC1]);
    p += 2;
    // call [rip + 0xFDF]   (target IAT @ 0x2000, next inst @ 0x1021)
    bytes[text_raw + p..text_raw + p + 6].copy_from_slice(&[0xFF, 0x15, 0xDF, 0x0F, 0x00, 0x00]);
    p += 6;
    // ud2
    bytes[text_raw + p..text_raw + p + 2].copy_from_slice(&[0x0F, 0x0B]);

    // --- .idata (ExitProcess only) ---
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
fn fibonacci_loop_returns_correct_value() {
    let pe_bytes = build_pe();
    let pe = PeFile::parse(&pe_bytes).expect("parse");
    let mem = MachVmManager::new();
    let mut image = load(&pe, &mem).expect("load");
    apply_relocations(&mut image).expect("reloc");
    let imp = imports::parse(&image).expect("imports");
    imports::wire_iat(&mut image, &imp, resolve).expect("wire IAT");

    let stack = GuestStack::default_size().expect("stack");
    let mut ctx = GuestContext::default();
    ctx.gprs[4] = stack.top();

    let mut disp = Dispatcher::new(16384).expect("dispatcher");
    let entry_va = image.actual_base + image.entry_rva as u64;

    let exit_code = run_with_exit_trap(|| {
        run_via_dispatcher(&mut disp, &image, &mut ctx, entry_va);
    });

    // After 8 iterations starting from a=1, b=1:
    //   it 1: a=2, b=1
    //   it 2: a=3, b=2
    //   it 3: a=5, b=3
    //   it 4: a=8, b=5
    //   it 5: a=13, b=8
    //   it 6: a=21, b=13
    //   it 7: a=34, b=21
    //   it 8: a=55, b=34
    // So eax = 55 = fib(10) at exit.
    assert_eq!(exit_code, 55);
}

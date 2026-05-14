//! E2E: guest allocates memory via Heap{Get,Alloc} and returns 1 if
//! the allocation succeeded. Stresses multi-call sequences (3 host
//! thunks in one basic block) and the dispatcher's register
//! preservation across all of them.
//!
//! Guest program:
//!     call qword ptr [rip + GP]    ; rax = GetProcessHeap()
//!     mov  rcx, rax
//!     xor  edx, edx                ; flags = 0
//!     mov  r8d, 16                 ; size = 16
//!     call qword ptr [rip + HA]    ; rax = HeapAlloc(handle, 0, 16)
//!     test rax, rax
//!     setnz cl
//!     movzx ecx, cl                ; ecx = 0 or 1
//!     call qword ptr [rip + EP]    ; ExitProcess(ecx)
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

    // Data directory [1] IMPORT: RVA 0x2020, size = 40 (one descriptor + terminator)
    let dd1 = opt + 112 + 8;
    bytes[dd1..dd1 + 4].copy_from_slice(&0x2020u32.to_le_bytes());
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
    bytes[sh2 + 8..sh2 + 12].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[sh2 + 12..sh2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    bytes[sh2 + 16..sh2 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[sh2 + 20..sh2 + 24].copy_from_slice(&0x600u32.to_le_bytes());
    bytes[sh2 + 36..sh2 + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes());

    // --- .text raw bytes ---
    //   RVA 0x1000  call [rip + 0xFFA] -> IAT[0] (GetProcessHeap) @ 0x2000
    //   RVA 0x1006  mov  rcx, rax
    //   RVA 0x1009  xor  edx, edx
    //   RVA 0x100B  mov  r8d, 16
    //   RVA 0x1012  call [rip + 0xFF0] -> IAT[1] (HeapAlloc) @ 0x2008
    //   RVA 0x1018  test rax, rax
    //   RVA 0x101B  setnz cl
    //   RVA 0x101E  movzx ecx, cl
    //   RVA 0x1021  call [rip + 0xFE9] -> IAT[2] (ExitProcess) @ 0x2010
    //   RVA 0x1027  ud2
    let text_raw = 0x400usize;
    let mut p = 0usize;
    // call [GP]: FF 15 FA 0F 00 00
    bytes[text_raw + p..text_raw + p + 6].copy_from_slice(&[0xFF, 0x15, 0xFA, 0x0F, 0x00, 0x00]);
    p += 6;
    // mov rcx, rax: 48 89 C1
    bytes[text_raw + p..text_raw + p + 3].copy_from_slice(&[0x48, 0x89, 0xC1]);
    p += 3;
    // xor edx, edx: 31 D2
    bytes[text_raw + p..text_raw + p + 2].copy_from_slice(&[0x31, 0xD2]);
    p += 2;
    // mov r8d, 16: 41 C7 C0 10 00 00 00
    bytes[text_raw + p..text_raw + p + 7]
        .copy_from_slice(&[0x41, 0xC7, 0xC0, 0x10, 0x00, 0x00, 0x00]);
    p += 7;
    // call [HA]: FF 15 F0 0F 00 00
    bytes[text_raw + p..text_raw + p + 6].copy_from_slice(&[0xFF, 0x15, 0xF0, 0x0F, 0x00, 0x00]);
    p += 6;
    // test rax, rax: 48 85 C0
    bytes[text_raw + p..text_raw + p + 3].copy_from_slice(&[0x48, 0x85, 0xC0]);
    p += 3;
    // setnz cl: 0F 95 C1
    bytes[text_raw + p..text_raw + p + 3].copy_from_slice(&[0x0F, 0x95, 0xC1]);
    p += 3;
    // movzx ecx, cl: 0F B6 C9
    bytes[text_raw + p..text_raw + p + 3].copy_from_slice(&[0x0F, 0xB6, 0xC9]);
    p += 3;
    // call [EP]: FF 15 E9 0F 00 00
    bytes[text_raw + p..text_raw + p + 6].copy_from_slice(&[0xFF, 0x15, 0xE9, 0x0F, 0x00, 0x00]);
    p += 6;
    // ud2
    bytes[text_raw + p..text_raw + p + 2].copy_from_slice(&[0x0F, 0x0B]);

    // --- .idata at file 0x600 (RVA 0x2000) ---
    //   0x2000 IAT[0]   -> 0x2080 (GetProcessHeap hint/name)
    //   0x2008 IAT[1]   -> 0x20A0 (HeapAlloc hint/name)
    //   0x2010 IAT[2]   -> 0x20C0 (ExitProcess hint/name)
    //   0x2018 IAT terminator
    //   0x2020 IMAGE_IMPORT_DESCRIPTOR (20 bytes)
    //   0x2034 descriptor terminator (20 bytes)
    //   0x2050 ILT[0]   -> 0x2080
    //   0x2058 ILT[1]   -> 0x20A0
    //   0x2060 ILT[2]   -> 0x20C0
    //   0x2068 ILT terminator
    //   0x2080 "\0\0GetProcessHeap\0"
    //   0x20A0 "\0\0HeapAlloc\0"
    //   0x20C0 "\0\0ExitProcess\0"
    //   0x20E0 "KERNEL32.DLL\0"
    let idata_raw = 0x600usize;
    bytes[idata_raw..idata_raw + 8].copy_from_slice(&0x2080u64.to_le_bytes());
    bytes[idata_raw + 8..idata_raw + 16].copy_from_slice(&0x20A0u64.to_le_bytes());
    bytes[idata_raw + 16..idata_raw + 24].copy_from_slice(&0x20C0u64.to_le_bytes());
    // IAT terminator at 0x2018 = idata_raw+0x18 (zeros)

    let desc = idata_raw + 0x20;
    bytes[desc..desc + 4].copy_from_slice(&0x2050u32.to_le_bytes()); // OriginalFirstThunk (ILT)
    bytes[desc + 12..desc + 16].copy_from_slice(&0x20E0u32.to_le_bytes()); // Name
    bytes[desc + 16..desc + 20].copy_from_slice(&0x2000u32.to_le_bytes()); // FirstThunk (IAT)
    // Terminator descriptor at idata_raw+0x34 (zeros).

    // ILT entries
    bytes[idata_raw + 0x50..idata_raw + 0x58].copy_from_slice(&0x2080u64.to_le_bytes());
    bytes[idata_raw + 0x58..idata_raw + 0x60].copy_from_slice(&0x20A0u64.to_le_bytes());
    bytes[idata_raw + 0x60..idata_raw + 0x68].copy_from_slice(&0x20C0u64.to_le_bytes());

    // Hint/name blobs
    let gph = b"GetProcessHeap\0";
    bytes[idata_raw + 0x82..idata_raw + 0x82 + gph.len()].copy_from_slice(gph);
    let ha = b"HeapAlloc\0";
    bytes[idata_raw + 0xA2..idata_raw + 0xA2 + ha.len()].copy_from_slice(ha);
    let ep = b"ExitProcess\0";
    bytes[idata_raw + 0xC2..idata_raw + 0xC2 + ep.len()].copy_from_slice(ep);
    let dll = b"KERNEL32.DLL\0";
    bytes[idata_raw + 0xE0..idata_raw + 0xE0 + dll.len()].copy_from_slice(dll);

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
            let block = block::translate_for_dispatcher(
                &bytes,
                current_rip,
                quantum_jit::block::IsaMode::Long,
            )
            .expect("translate");
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
fn guest_calls_heap_alloc_and_exits_with_success() {
    let pe_bytes = build_pe();
    let pe = PeFile::parse(&pe_bytes).expect("parse");
    let mem = MachVmManager::new();
    let mut image = load(&pe, &mem).expect("load");
    apply_relocations(&mut image).expect("reloc");
    let imp = imports::parse(&image).expect("imports");
    assert_eq!(imp.dlls[0].entries.len(), 3);
    imports::wire_iat(&mut image, &imp, resolve).expect("wire IAT");

    let stack = GuestStack::default_size().expect("stack");
    let mut ctx = GuestContext::default();
    ctx.gprs[4] = stack.top();

    let mut disp = Dispatcher::new(16384).expect("dispatcher");
    let entry_va = image.actual_base + image.entry_rva as u64;

    let exit_code = run_with_exit_trap(|| {
        run_via_dispatcher(&mut disp, &image, &mut ctx, entry_va);
    });

    assert_eq!(
        exit_code, 1,
        "HeapAlloc returned non-null; SETNZ + MOVZX should yield 1"
    );
}

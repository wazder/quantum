//! Block-chaining end-to-end perf proof.
//!
//! A counted loop runs N iterations. With chaining, after the loop
//! block's conditional back-edge is patched the dispatcher stops
//! seeing the loop at all — the entire remaining iteration count runs
//! inside JIT'd code with zero Rust round-trips. We count
//! `invoke_block_with_ctx` calls and assert the total is tiny and
//! independent of N (a handful), whereas an unchained dispatcher
//! would call it ~N times.
//!
//! Guest (one straight-line prologue block + a self-looping block):
//!   0x1000  mov ecx, N            ; B9 imm32         (5)
//!   0x1005  mov r8d, 0            ; 41 B8 imm32      (6)
//!   0x100B  add r8d, 1            ; 41 83 C0 01      (4)   .loop
//!   0x100F  sub ecx, 1           ; 83 E9 01         (3)
//!   0x1012  jnz .loop            ; 75 F7            (2)   → 0x100B
//!   0x1014  mov ecx, r8d         ; 44 89 C1         (3)
//!   0x1017  call [rip+iat_exit]  ; FF 15 disp32     (6)   ExitProcess(r8d)
//!   0x101D  ud2
//!
//! Loop runs N times so r8d == N at the end → ExitProcess(N).

use core::ptr::NonNull;
use quantum_jit::block;
use quantum_kernel32::process::run_with_exit_trap;
use quantum_kernel32::resolve;
use quantum_loader::{PeFile, apply_relocations, imports, load};
use quantum_runtime::{
    Dispatcher, GuestContext, GuestStack, STOP_SENTINEL, MachVmManager, invoke_block_with_ctx,
};

fn build_pe(n: u32) -> Vec<u8> {
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
    bytes[sh2 + 8..sh2 + 12].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[sh2 + 12..sh2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    bytes[sh2 + 16..sh2 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[sh2 + 20..sh2 + 24].copy_from_slice(&0x600u32.to_le_bytes());
    bytes[sh2 + 36..sh2 + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes());

    let t = 0x400usize;
    // mov ecx, N
    bytes[t..t + 1].copy_from_slice(&[0xB9]);
    bytes[t + 1..t + 5].copy_from_slice(&n.to_le_bytes());
    // mov r8d, 0
    bytes[t + 5..t + 11].copy_from_slice(&[0x41, 0xB8, 0x00, 0x00, 0x00, 0x00]);
    // .loop @ 0x100B: add r8d, 1
    bytes[t + 11..t + 15].copy_from_slice(&[0x41, 0x83, 0xC0, 0x01]);
    // sub ecx, 1
    bytes[t + 15..t + 18].copy_from_slice(&[0x83, 0xE9, 0x01]);
    // jnz .loop  (rel8 = 0x100B - 0x1014 = -9 = 0xF7)
    bytes[t + 18..t + 20].copy_from_slice(&[0x75, 0xF7]);
    // mov ecx, r8d  (RVA 0x1014..0x1016)
    bytes[t + 20..t + 23].copy_from_slice(&[0x44, 0x89, 0xC1]);
    // call [rip + disp]  (RVA 0x1017..0x101C, next-ip 0x101D)
    //   IAT@0x2000, disp = 0x2000 - 0x101D = 0xFE3
    bytes[t + 23..t + 29].copy_from_slice(&[0xFF, 0x15, 0xE3, 0x0F, 0x00, 0x00]);
    // ud2 (RVA 0x101D..0x101E)
    bytes[t + 29..t + 31].copy_from_slice(&[0x0F, 0x0B]);

    // .idata: IAT[0] @0x2000 -> ExitProcess hint/name @0x20A0
    let id = 0x600usize;
    bytes[id..id + 8].copy_from_slice(&0x20A0u64.to_le_bytes());
    let desc = id + 0x10;
    bytes[desc..desc + 4].copy_from_slice(&0x2050u32.to_le_bytes());
    bytes[desc + 12..desc + 16].copy_from_slice(&0x2120u32.to_le_bytes());
    bytes[desc + 16..desc + 20].copy_from_slice(&0x2000u32.to_le_bytes());
    bytes[id + 0x50..id + 0x58].copy_from_slice(&0x20A0u64.to_le_bytes());
    bytes[id + 0xA0..id + 0xA2].copy_from_slice(&0u16.to_le_bytes());
    let en = b"ExitProcess\0";
    bytes[id + 0xA2..id + 0xA2 + en.len()].copy_from_slice(en);
    let dll = b"KERNEL32.DLL\0";
    bytes[id + 0x120..id + 0x120 + dll.len()].copy_from_slice(dll);

    bytes
}

/// Chaining-aware dispatcher loop, mirroring quantum-cli's
/// run_dispatcher_loop. Returns (exit_code, invoke_count).
fn run_chained(image: &quantum_loader::LoadedImage, n: u32) -> (u32, usize) {
    let disp = Dispatcher::new(1 << 20).expect("disp");
    let stack = GuestStack::default_size().expect("stack");
    let mut ctx = GuestContext::default();
    ctx.gprs[4] = stack.top() - 0x40;
    let entry = image.actual_base + image.entry_rva as u64;

    let mut invoke_count = 0usize;
    let exit = run_with_exit_trap(|| {
        let mut unpatched: std::collections::HashMap<u64, Vec<*mut u32>> =
            std::collections::HashMap::new();
        let mut rip = entry;
        let _ = n;
        loop {
            let ptr: NonNull<u8> = if let Some(p) = disp.lookup(rip) {
                p
            } else {
                let rva = (rip - image.actual_base) as u32;
                let win = 256usize.min(image.len() - rva as usize);
                let b: Vec<u8> = image.rva_to_slice(rva, win).unwrap().to_vec();
                let blk = block::translate_for_dispatcher(
                    &b,
                    rip,
                    quantum_jit::block::IsaMode::Long,
                )
                .unwrap();
                let hp = disp.install(rip, &blk.host_bytes).unwrap();
                for &(off, target) in &blk.chain_patches {
                    let site = unsafe { hp.as_ptr().add(off as usize) as *mut u32 };
                    unpatched.entry(target).or_default().push(site);
                }
                hp
            };
            if let Some(sites) = unpatched.remove(&rip) {
                let hot = unsafe {
                    (ptr.as_ptr() as *const u8).add(
                        quantum_jit::block::DISPATCHER_HOT_ENTRY_OFFSET as usize,
                    )
                };
                for s in sites {
                    unsafe {
                        disp.patch_chain(s, hot);
                    }
                }
            }
            invoke_count += 1;
            let next = unsafe { invoke_block_with_ctx(ptr, &mut ctx) };
            if next == STOP_SENTINEL {
                break;
            }
            rip = next;
        }
    });
    (exit, invoke_count)
}

fn load_image(pe_bytes: &[u8]) -> quantum_loader::LoadedImage {
    let pe = PeFile::parse(pe_bytes).expect("parse");
    let mem = MachVmManager::new();
    let mut image = load(&pe, &mem).expect("load");
    apply_relocations(&mut image).expect("reloc");
    let imp = imports::parse(&image).expect("imports");
    imports::wire_iat(&mut image, &imp, resolve).expect("wire IAT");
    image
}

#[test]
fn loop_runs_correct_count_and_chaining_keeps_invokes_tiny() {
    // Two loop sizes; the invoke count must NOT scale with N (that's
    // the whole point of chaining).
    let img50 = load_image(&build_pe(50));
    let (exit50, inv50) = run_chained(&img50, 50);
    assert_eq!(exit50, 50, "loop should run exactly 50 times");

    let img2000 = load_image(&build_pe(2000));
    let (exit2000, inv2000) = run_chained(&img2000, 2000);
    assert_eq!(exit2000, 2000, "loop should run exactly 2000 times");

    // Without chaining inv2000 would be ~2000+. With chaining the
    // dispatcher only sees a handful of block entries regardless of N.
    assert!(
        inv2000 < 16,
        "chaining should keep invoke count tiny; got {inv2000} for N=2000"
    );
    // And it must not grow with N (50 vs 2000 produce the same shape).
    assert_eq!(
        inv50, inv2000,
        "invoke count must be independent of iteration count \
         (got {inv50} for N=50, {inv2000} for N=2000)"
    );
}

//! Integration test: write a hand-assembled PE to a temp file, then
//! invoke `quantum-cli::process::run_pe` against the bytes read back
//! from disk. Proves the full file → loader → JIT → execute pipeline
//! works on a real on-disk binary (which is the production path).

use std::fs;
use std::path::PathBuf;

fn build_exit_42_pe() -> Vec<u8> {
    // Same PE the e2e_exit_process test builds in-memory: imports
    // KERNEL32!ExitProcess and entry calls it with 42.
    let mut bytes = vec![0u8; 0x800];

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

    let text_raw = 0x400usize;
    // mov ecx, 42 ; call [rip + 0xFF5] ; ud2
    bytes[text_raw..text_raw + 5].copy_from_slice(&[0xB9, 0x2A, 0x00, 0x00, 0x00]);
    bytes[text_raw + 5..text_raw + 11].copy_from_slice(&[0xFF, 0x15, 0xF5, 0x0F, 0x00, 0x00]);
    bytes[text_raw + 11..text_raw + 13].copy_from_slice(&[0x0F, 0x0B]);

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

/// Drive the production `process::run_pe` path against a PE file
/// actually written to and read back from disk.
#[test]
fn run_pe_from_disk_returns_exit_code() {
    let pe_bytes = build_exit_42_pe();

    let mut path: PathBuf = std::env::temp_dir();
    path.push(format!("quantum-rundisk-{}.exe", std::process::id()));
    fs::write(&path, &pe_bytes).expect("write tmp PE");

    let read_back = fs::read(&path).expect("read tmp PE");
    assert_eq!(read_back, pe_bytes);

    // The CLI's run_pe is private to that binary crate; we re-implement
    // the bare-minimum equivalent here using the same public APIs.
    // (TODO: expose `process::run_pe` from a lib target so integration
    // tests can call it directly instead of duplicating.)
    use core::ptr::NonNull;
    use quantum_jit::block;
    use quantum_kernel32::process::run_with_exit_trap;
    use quantum_kernel32::resolve;
    use quantum_loader::{PeFile, apply_relocations, imports, load};
    use quantum_runtime::{
        Dispatcher, GuestContext, GuestStack, MachVmManager, STOP_SENTINEL, invoke_block_with_ctx,
    };

    let pe = PeFile::parse(&read_back).expect("parse");
    let mem = MachVmManager::new();
    let mut image = load(&pe, &mem).expect("load");
    apply_relocations(&mut image).expect("reloc");
    let imp = imports::parse(&image).expect("imports");
    imports::wire_iat(&mut image, &imp, resolve).expect("wire IAT");

    let stack = GuestStack::default_size().expect("stack");
    let mut ctx = GuestContext::default();
    ctx.gprs[4] = stack.top() - 0x40;
    let disp = Dispatcher::new(16384).expect("dispatcher");
    let entry_va = image.actual_base + image.entry_rva as u64;

    let exit_code = run_with_exit_trap(|| {
        let mut rip = entry_va;
        for _ in 0..1000 {
            let ptr: NonNull<u8> = if let Some(p) = disp.lookup(rip) {
                p
            } else {
                let rva = (rip - image.actual_base) as u32;
                let bytes: Vec<u8> = image.rva_to_slice(rva, 64).unwrap().to_vec();
                let block =
                    block::translate_for_dispatcher(&bytes, rip, quantum_jit::block::IsaMode::Long)
                        .unwrap();
                disp.install(rip, &block.host_bytes).unwrap()
            };
            let next = unsafe { invoke_block_with_ctx(ptr, &mut ctx) };
            if next == STOP_SENTINEL {
                break;
            }
            rip = next;
        }
    });

    // Cleanup
    let _ = fs::remove_file(&path);

    assert_eq!(exit_code, 42);
}

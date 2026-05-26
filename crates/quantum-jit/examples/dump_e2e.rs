// Just disassembles what e2e_exit_process emits.
use quantum_jit::decoder::Decoder;
use quantum_jit::emitter::Emitter;
use quantum_jit::iform::Op;
use quantum_jit::lifter::Lifter;

fn main() {
    let entry_va: u64 = 0x1_4000_1000;
    let mut entry_bytes = vec![0u8; 32];
    entry_bytes[..5].copy_from_slice(&[0xB9, 0x2A, 0x00, 0x00, 0x00]);
    entry_bytes[5..11].copy_from_slice(&[0xFF, 0x15, 0xF5, 0x0F, 0x00, 0x00]);
    entry_bytes[11..13].copy_from_slice(&[0x0F, 0x0B]);

    let mut emitter = Emitter::new();
    let mut decoder = Decoder::new(&entry_bytes, entry_va);
    loop {
        let inst = decoder.next().expect("decode");
        let terminator = matches!(inst.op, Op::Ud2 | Op::Ret | Op::CallIndirect);
        Lifter::new(&mut emitter).lift(&inst).expect("lift");
        if terminator { break; }
    }
    emitter.finish().expect("finish");
    let bytes = emitter.bytes();
    println!("Total {} bytes:", bytes.len());
    for (i, w) in bytes.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        println!("  +{:04X}  {:08X}", i*4, word);
    }
}

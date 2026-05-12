//! `quantum` — entry point. For now: parse a PE file and dump its layout.
//! Execution path lands once the loader, JIT, and Win32 stubs are wired up.

use std::env;
use std::fs;
use std::process::ExitCode;

use quantum_loader::{PeFile, PeKind};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let Some(path) = args.get(1) else {
        eprintln!("usage: quantum <path-to.exe>");
        return ExitCode::from(2);
    };

    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {path}: {e}");
            return ExitCode::from(1);
        }
    };

    let pe = match PeFile::parse(&bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("parse {path}: {e}");
            return ExitCode::from(1);
        }
    };

    let kind = match pe.opt.kind {
        PeKind::Pe32 => "PE32",
        PeKind::Pe32Plus => "PE32+",
    };
    println!("{path}: {kind}, machine={:#06x}", pe.coff.machine);
    println!(
        "  image_base={:#x}  entry={:#x}  size_of_image={:#x}",
        pe.opt.image_base, pe.opt.address_of_entry_point, pe.opt.size_of_image
    );
    println!("  sections ({}):", pe.coff.number_of_sections);
    for s in pe.sections() {
        println!(
            "    {:<8}  va={:#010x}  vsize={:#x}  rawptr={:#x}  rawsize={:#x}  ch={:#010x}",
            s.name_str(),
            s.virtual_address,
            s.virtual_size,
            s.pointer_to_raw_data,
            s.size_of_raw_data,
            s.characteristics
        );
    }

    ExitCode::SUCCESS
}
